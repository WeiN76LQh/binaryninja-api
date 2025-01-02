//
// Created by kat on 5/23/23.
//

/*
	This is the cross-plat file buffering logic used for SharedCache processing.
 	This is used for reading large amounts of large files in a performant manner.

 	Here be no dragons, but this code is very complex, beware.

 	We in _all_ cases memory map the files, as we hardly ever need more than a few pages per file for most intensive operations.

 	Memory Map Implementation:
 		Of interest is that on several platforms we have to account for very low file pointer limits, and when mapping
 		40+ files, these are trivially reachable.

 		We handle this with a "SelfAllocatingWeakPtr":
 			- Calling .lock() ALWAYS delivers a shared_ptr guaranteed to stay valid. This may block waiting for a free pointer
			- As soon as that lock is released, that file pointer MAY be freed if another thread wants to open a new one, and we are at our limit.
			- Calling .lock() again on this same theoretical object will then wait for another file pointer to be freeable.

	VM Implementation:


 	Since the caches we're operating on are by nature page aligned, we are able to use nice optimizations under the hood to translate
 	"VM Addresses" to their actual in-memory counterparts.

 	We do this with a page table, which is a map of page -> file offset.

 	We also implement a "VMReader" here, which is a drop-in replacement for BinaryReader that operates on the VM.
 		see "ObjC.cpp" for where this is used.

*/


#include "VM.h"
#include <utility>
#include <memory>
#include <cstring>
#include <stdio.h>
#include <filesystem>
#include <binaryninjaapi.h>

#ifdef _MSC_VER
	#include <windows.h>
#else
	#include <sys/mman.h>
	#include <fcntl.h>
	#include <stdlib.h>
	#include <sys/resource.h>
#endif

void VMShutdown()
{
	// This will trigger the deallocation logic for these.
	// It is background threaded to avoid a deadlock on exit.

	// Do not grab both locks at the same time otherwise a deadlock will occur 
	// due to `fileAccessorReferenceHolder.clear()` triggering 
	// `SelfAllocatingWeakPtr<MMappedFileAccessor>` deallocation routines that 
	// need to acquire `fileAccessorsMutex`.
	{
		// Some additional complexity with this lock is that dropping all these references likely 
		// will cause the final reference to a DSC binary view to be dropped. In doing so 
		// `~DSCView` will call `MMappedFileAccessor::CloseAll` which requires the same lock. This 
		// occurs on the same thread, resulting in it trying to acquire a lock it already has. 
		// This solution copies all the deques from `fileAccessorReferenceHolder`, therefore 
		// keeping all the references alive temporarily. Then `fileAccessorReferenceHolder` can be 
		// cleared and the `fileAccessorDequeMutex` lock can be dropped. When exiting this scope 
		// the desctructor for `accessorDequesToDrop` will drop all the `MMappedFileAccessor` 
		// references whilst holding no locks.
		std::unique_lock<std::mutex> lock(fileAccessorDequeMutex);
		std::vector<std::deque<std::shared_ptr<MMappedFileAccessor>>> accessorDequesToDrop;
		for (auto& [_, fileAccessorDeque] : fileAccessorReferenceHolder)
		{
			accessorDequesToDrop.push_back(fileAccessorDeque);
		}
		fileAccessorReferenceHolder.clear();
		lock.unlock();
	}
	{
		std::unique_lock<std::mutex> lock(fileAccessorsMutex);
		fileAccessors.clear();
	}
}


std::string ResolveFilePath(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const std::string& path)
{
	auto dscProjectFile = dscView->GetFile()->GetProjectFile();

	// If we're not in a project, just return the path we were given
	if (!dscProjectFile)
	{
		return path;
	}

	// TODO: do we need to support looking in subfolders?
	// Replace project file path on disk with project file name for resolution
	std::string projectFilePathOnDisk = dscProjectFile->GetPathOnDisk();
	std::string cleanPath = path;
	cleanPath.replace(cleanPath.find(projectFilePathOnDisk), projectFilePathOnDisk.size(), dscProjectFile->GetName());

	size_t lastSlashPos = cleanPath.find_last_of("/\\");
	std::string fileName;

	if (lastSlashPos != std::string::npos) {
		fileName = cleanPath.substr(lastSlashPos + 1);
	} else {
		fileName = cleanPath;
	}

	auto project = dscProjectFile->GetProject();
	auto dscProjectFolder = dscProjectFile->GetFolder();
	for (const auto& file : project->GetFiles())
	{
		auto fileFolder = file->GetFolder();
		bool isSibling = false;
		if (!dscProjectFolder && !fileFolder)
		{
			// Both top-level
			isSibling = true;
		}
		else if (dscProjectFolder && fileFolder)
		{
			// Have same parent folder
			isSibling = dscProjectFolder->GetId() == fileFolder->GetId();
		}

		if (isSibling && file->GetName() == fileName)
		{
			return file->GetPathOnDisk();
		}
	}

	if (dscView->GetFile()->GetProjectFile())
	{
		BinaryNinja::LogError("Failed to resolve file path for %s", path.c_str());
	}

	// If we couldn't find a sibling filename, just return the path we were given
	return path;
}


void MMAP::Map()
{
	if (mapped)
		return;
#ifdef _MSC_VER
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize))
	{
		// Handle error
		CloseHandle(hFile);
		return;
	}
	len = static_cast<size_t>(fileSize.QuadPart);

	HANDLE hMapping = CreateFileMapping(
		hFile,                       // file handle
		NULL,                        // security attributes
		PAGE_WRITECOPY,              // protection
		0,                           // maximum size (high-order DWORD)
		0,                           // maximum size (low-order DWORD)
		NULL);                       // name of the mapping object

	if (hMapping == NULL)
	{
		// Handle error
		CloseHandle(hFile);
		return;
	}

	_mmap = static_cast<uint8_t*>(MapViewOfFile(
		hMapping,                    // handle to the file mapping object
		FILE_MAP_COPY,         		 // desired access
		0,                           // file offset (high-order DWORD)
		0,                           // file offset (low-order DWORD)
		0));                         // number of bytes to map (0 = entire file)

	if (_mmap == nullptr)
	{
		// Handle error
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}

	mapped = true;

	CloseHandle(hMapping);
	CloseHandle(hFile);

#else
	fseek(fd, 0L, SEEK_END);
	len = ftell(fd);
	fseek(fd, 0L, SEEK_SET);

	void *result = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fd), 0u);
	if (result == MAP_FAILED)
	{
		// Handle error
		return;
	}

	_mmap = static_cast<uint8_t*>(result);
	mapped = true;
#endif
}

void MMAP::Unmap()
{
#ifdef _MSC_VER
	if (_mmap)
	{
		UnmapViewOfFile(_mmap);
		mapped = false;
	}
#else
	if (mapped)
	{
		munmap(_mmap, len);
		mapped = false;
	}
#endif
}


std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>> MMappedFileAccessor::Open(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const uint64_t sessionID, const std::string &path, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine)
{
	std::unique_lock<std::mutex> lock(fileAccessorsMutex);
	if (auto it = fileAccessors.find(path); it != fileAccessors.end()) {
		return it->second;
	}

	auto fileAccessor = std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>>(new SelfAllocatingWeakPtr<MMappedFileAccessor>(
		// Allocator logic for the SelfAllocatingWeakPtr. This has been written to respect 
		// `maxFPLimit` as much as possible. However if, for whatever reason, a deadlock occurs, 
		// requiring more than `maxFPLimit` of files to be opened to continue past, there is a 
		// timeout added to do this. It should almost never occur in real world conditions (I 
		// believe) but a timeout safe guard has been added to choose to exceed `maxFPLimit` 
		// temporarily to avoid a permanent deadlock. The absolute worst case is Binary Ninja 
		// throws a bunch of errors because it tried to open a file and couldn't due to actually 
		// hitting the OS enforced open file limit.
		[path=path, sessionID=sessionID, dscView](){
			// This lock needs to be held for the entire duration of this function, in part to 
			// synchronize access to `fileAccessorReferenceHolder` and `blockedSessionIDs`, but 
			// also to ensure that, if a thread needs to drop a file accessor reference to get a 
			// `fileAccessorSemaphore` ref, then there's actually a reference to drop and its the 
			// one to acquire it after triggering for it to get dropped. This is due to 2 
			// complexities here:
			// 1. If thread 1 tries to acquire a ref on `fileAccessorSemaphore` with `try_acquire` 
			//    and fails then it needs to drop a strong reference to a file accessor by 
			//    removing an entry from one of the values in `fileAccessorReferenceHolder`. 
			//    Without synchronizing this function its possible that thread 2 could come in 
			//    after thread 1 drops an entry but before it can block in 
			//    `fileAccessorSemaphore.acquire`, potentially sniping away the reference it has 
			//    just freed up by thread 2 reaching `try_acquire` first. Its then possible that 
			//    nothing else causes a reference to be dropped because 
			//    `fileAccessorReferenceHolder` keeps file accessors alive until this function 
			//    drops one. That would then lead a thread to deadlock in 
			//    `fileAccessorSemaphore.acquire`. So a lock must be held the entire time that a 
			//    ref is trying to be acquired on `fileAccessorSemaphore` to prevent sniping.
			// 2. In a very contrived scenario where `fileAccessorSemaphore` has a count of 1 (as 
			//    in there's only 1 reference to give out) then its possible that, thread 1 could 
			//    take that only reference but before it reaches the end of the function and adds 
			//    the newly created `accessor` to `fileAccessorReferenceHolder`. Thread 2 comes 
			//    in, observes there's no reference, tries to drop one from 
			//    `fileAccessorReferenceHolder` but there aren't any currently and then deadlocks 
			//    in `fileAccessorSemaphore.acquire`.
			std::unique_lock<std::mutex> lock(fileAccessorDequeMutex);

			bool refAcquired = fileAccessorSemaphore.try_acquire();
			if (!refAcquired)
			{
				// The permitted allowance of open files has been used up. Drop a reference to one 
				// and wait for it to close its file. Assume there's always at least one reference 
				// to drop but if not then the code below can handle the situation.
				for (auto& [_, fileAccessorDeque] : fileAccessorReferenceHolder)
				{
					if (!fileAccessorDeque.empty())
					{
						fileAccessorDeque.pop_front();
						break;
					}
				}

				// There should now be a count of 1 on `fileAccessorSemaphore` but its possible 
				// that its not the case. This happens when the file limit is being heavily 
				// consumed by long living references to `MMappedFileAccessor`. 
				// `fileAccessorReferenceHolder` isn't the only holder of strong references to 
				// `MMappedFileAccessor`. Any call to this function followed by calling 
				// `SelfAllocatingWeakPtr::lock` on the return value will create a strong 
				// reference. Dropping that `MMappedFileAccessor` from the map 
				// `fileAccessorReferenceHolder` won't cause deallocation until those other strong 
				// references returned via `SelfAllocatingWeakPtr::lock` have also been destructed.
				// Therefore its possible to block here for a bit whilst another thread completes 
				// up the work it is doing with a mapped file. It is also possible to deadlock 
				// here if any of the coding in the rest of the plugin allows for a single thread 
				// to lock more than 1 `MMappedFileAccessor` at a time. At the time of writing 
				// this comment it is true that all paths of execution will only need to hold at 
				// max 1 `MMappedFileAccessor` lock at a time. Future changes should try to 
				// maintain this as much as possible to ensure a deadlock is impossible. However 
				// even if this is not the case, as long as the maximum number of 
				// `MMappedFileAccessor` locks that may need to be held by a single thread, is a 
				// small number, then the actual probability of a deadlock should be 
				// extraordinarily low and would likely require the perfect storm of conditions 
				// for it to occur.
				// `acquire` has been modified to have deadlock protection by adding a timeout. In 
				// the case that a deadlock occurs and the timeout is reached, the following code 
				// can go above `maxFPLimit` temporarily.
				// The previous implementation of the code here tried its best to make a file 
				// available but never checked that it had, instead it could go over the 
				// `maxFPLimit`.
				refAcquired = fileAccessorSemaphore.acquire(std::chrono::seconds(10));
				if (!refAcquired)
					BinaryNinja::LogWarn("Potential deadlock occurred in MMappedFileAccessor::Open");
			}

			mmapCount++;
			auto accessor = std::shared_ptr<MMappedFileAccessor>(new MMappedFileAccessor(ResolveFilePath(dscView, path)), [refAcquired](MMappedFileAccessor* accessor){
				{
					std::unique_lock<std::mutex> lock(fileAccessorsMutex);
					fileAccessors.erase(accessor->m_path);
				}
				delete accessor;
				mmapCount--;
				// Release the reference once the `MMappedFileAccessor` destructor has completed 
				// and the file is actually closed. Only drop the ref if one was actually 
				// acquired. Read the comment above the line where `fileAccessorSemaphore` is 
				// acquired, for information on how this can occur.
				if (refAcquired)
					fileAccessorSemaphore.release();
			});

			// Only hold a strong reference to a `MMappedFileAccessor` if a 
			// `fileAccessorSemaphore` ref was acquired, otherwise we're going over the FP limit 
			// and therefore should drop the reference ASAP to cause the file to close. Also this 
			// prevents a situation where the above code, when trying to acquire a 
			// `fileAccessorSemaphore` ref, drops a reference to a `MMappedFileAccessor` that 
			// won't release a `fileAccessorSemaphore` ref, which can cause a deadlock.
			if (refAcquired)
			{
				// If some background thread has managed to try and open a file when the BV was 
				// already closed, we can still give them the file they want so they dont crash, 
				// but as soon as they let go it's gone.
				if (!blockedSessionIDs.count(sessionID))
					fileAccessorReferenceHolder[sessionID].push_back(accessor);
			}
			return accessor;
		},
		[postAllocationRoutine=postAllocationRoutine](std::shared_ptr<MMappedFileAccessor> accessor){
			if (postAllocationRoutine)
				postAllocationRoutine(accessor);
		}));

	fileAccessors.insert_or_assign(path, fileAccessor);
	return fileAccessor;
}


void MMappedFileAccessor::CloseAll(const uint64_t sessionID)
{
	std::unique_lock<std::mutex> lock(fileAccessorDequeMutex);
	blockedSessionIDs.insert(sessionID);
	fileAccessorReferenceHolder.erase(sessionID);
}


void MMappedFileAccessor::InitialVMSetup()
{
	// check for BN_SHAREDCACHE_FP_MAX
	// if it exists, set maxFPLimit to that value
	maxFPLimit = 0;
	if (auto env = getenv("BN_SHAREDCACHE_FP_MAX"); env)
	{
		// FIXME behav on 0 here is unintuitive, '0123' will interpret as octal and be 83 according to manpage. meh.
		maxFPLimit = strtoull(env, nullptr, 0);
		if (maxFPLimit < 10)
		{
			BinaryNinja::LogWarn("BN_SHAREDCACHE_FP_MAX set to below 10. A value of at least 10 is recommended for performant analysis on SharedCache Binaries.");
		}
		if (maxFPLimit == 0)
		{
			BinaryNinja::LogError("BN_SHAREDCACHE_FP_MAX set to 0. Adjusting to 1");
			maxFPLimit = 1;
		}
	}
	else
	{
#ifdef _MSC_VER
		// It is not _super_ clear what the max file pointer limit is on windows,
		// 	but to my understanding, we are using the windows API to map files,
		// 	so we should have at least 2^24;
		// kind of funny to me that windows would be the most effecient OS to
		// parallelize sharedcache processing on in terms of FP usage concerns
		maxFPLimit = 0x1000000;
#else
		// unix in comparison will likely have a very small limit, especially mac, necessitating all of this consideration
		struct rlimit rlim;
		getrlimit(RLIMIT_NOFILE, &rlim);
		maxFPLimit = rlim.rlim_cur / 2;
#endif
	}
	BinaryNinja::LogInfo("Shared Cache processing initialized with a max file pointer limit of 0x%llx", maxFPLimit);
	fileAccessorSemaphore.set_count(maxFPLimit);
}


MMappedFileAccessor::MMappedFileAccessor(const std::string& path) : m_path(path)
{
#ifdef _MSC_VER
	m_mmap.hFile = CreateFile(
		path.c_str(),              // file name
		GENERIC_READ,              // desired access (read-only)
        FILE_SHARE_READ,                         // share mode
		NULL,                      // security attributes
		OPEN_EXISTING,             // creation disposition
		FILE_ATTRIBUTE_NORMAL,     // flags and attributes
		NULL);                     // template file

	if (m_mmap.hFile == INVALID_HANDLE_VALUE)
	{
		// BNLogInfo("Couldn't read file at %s", path.c_str());
		throw MissingFileException();
	}

#else
#ifdef ABORT_FAILURES
	if (path.empty())
	{
		cerr << "Path is empty." << endl;
		abort();
	}
#endif
	m_mmap.fd = fopen(path.c_str(), "r");
	if (m_mmap.fd == nullptr)
	{
		BNLogError("Serious VM Error: Couldn't read file at %s", path.c_str());

#ifndef _MSC_VER
		try {
			throw BinaryNinja::ExceptionWithStackTrace("Unable to Read file");
		}
		catch (ExceptionWithStackTrace &ex)
		{
			BNLogError("%s", ex.m_stackTrace.c_str());
			BNLogError("Error: %d (%s)", errno, strerror(errno));
		}
#endif
		throw MissingFileException();
	}
#endif

	m_mmap.Map();
}

MMappedFileAccessor::~MMappedFileAccessor()
{
	// BNLogInfo("Unmapping %s", m_path.c_str());
	m_mmap.Unmap();

#ifdef _MSC_VER
	if (m_mmap.hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_mmap.hFile);
	}
#else
	if (m_mmap.fd != nullptr)
	{
		fclose(m_mmap.fd);
	}
#endif
}

void MMappedFileAccessor::WritePointer(size_t address, size_t pointer)
{
	*(size_t*)&m_mmap._mmap[address] = pointer;
}

template <typename T>
T MMappedFileAccessor::Read(size_t address) {
	T result;
	Read(&result, address, sizeof(T));
	return result;
}

std::string MMappedFileAccessor::ReadNullTermString(size_t address)
{
	if (address > m_mmap.len)
		return "";
	auto start = &m_mmap._mmap[address];
	auto end = &m_mmap._mmap[m_mmap.len];
	auto nul = std::find(start, end, 0);
	return std::string(start, nul);
}

uint8_t MMappedFileAccessor::ReadUChar(size_t address)
{
	return Read<uint8_t>(address);
}

int8_t MMappedFileAccessor::ReadChar(size_t address)
{
	return Read<int8_t>(address);
}

uint16_t MMappedFileAccessor::ReadUShort(size_t address)
{
	return Read<uint16_t>(address);
}

int16_t MMappedFileAccessor::ReadShort(size_t address)
{
	return Read<int16_t>(address);
}

uint32_t MMappedFileAccessor::ReadUInt32(size_t address)
{
	return Read<uint32_t>(address);
}

int32_t MMappedFileAccessor::ReadInt32(size_t address)
{
	return Read<int32_t>(address);
}

uint64_t MMappedFileAccessor::ReadULong(size_t address)
{
	return Read<uint64_t>(address);
}

int64_t MMappedFileAccessor::ReadLong(size_t address)
{
	return Read<int64_t>(address);
}

BinaryNinja::DataBuffer MMappedFileAccessor::ReadBuffer(size_t address, size_t length)
{
	if (m_mmap.len <= length || address > m_mmap.len - length)
		throw MappingReadException();

	return BinaryNinja::DataBuffer(&m_mmap._mmap[address], length);
}

void MMappedFileAccessor::Read(void* dest, size_t address, size_t length)
{
	if (m_mmap.len <= length || address > m_mmap.len - length)
		throw MappingReadException();

	memcpy(dest, &m_mmap._mmap[address], length);
}


VM::VM(size_t pageSize, bool safe) : m_pageSize(pageSize), m_safe(safe)
{
}

VM::~VM()
{
}


void VM::MapPages(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, uint64_t sessionID, size_t vm_address, size_t fileoff, size_t size, std::string filePath, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine)
{
	// The mappings provided for shared caches will always be page aligned.
	// We can use this to our advantage and gain considerable performance via page tables.
	// This could probably be sped up if c++ were avoided?
	// We want to create a map of page -> file offset

	if (vm_address % m_pageSize != 0 || size % m_pageSize != 0)
	{
		throw MappingPageAlignmentException();
	}

	auto accessor = MMappedFileAccessor::Open(std::move(dscView), sessionID, filePath, postAllocationRoutine);
	auto [it, inserted] = m_map.insert_or_assign({vm_address, vm_address + size}, PageMapping(std::move(filePath), std::move(accessor), fileoff));
	if (m_safe && !inserted)
	{
		BNLogWarn("Remapping page 0x%zx (f: 0x%zx)", vm_address, fileoff);
		throw MappingCollisionException();
	}
}

std::pair<PageMapping, size_t> VM::MappingAtAddress(size_t address)
{
	if (auto it = m_map.find(address); it != m_map.end())
	{
		// The PageMapping object returned contains the page, and more importantly, the file pointer (there can be
		// multiple in newer caches) This is relevant for reading out the data in the rest of this file.
		// The second item in the returned pair is the offset of `address` within the file.
		auto& range = it->first;
		auto& mapping = it->second;
		return {mapping, mapping.fileOffset + (address - range.start)};
	}

	throw MappingReadException();
}


bool VM::AddressIsMapped(uint64_t address)
{
	auto it = m_map.find(address);
	return it != m_map.end();
}


uint64_t VMReader::ReadULEB128(size_t limit)
{
	uint64_t result = 0;
	int bit = 0;
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	auto fileCursor = mapping.second;
	auto fileLimit = fileCursor + (limit - m_cursor);
	auto fa = mapping.first.fileAccessor->lock();
	auto* fileBuff = (uint8_t*)fa->Data();
	do
	{
		if (fileCursor >= fileLimit)
			return -1;
		uint64_t slice = ((uint64_t*)&((fileBuff)[fileCursor]))[0] & 0x7f;
		if (bit > 63)
			return -1;
		else
		{
			result |= (slice << bit);
			bit += 7;
		}
	} while (((uint64_t*)&(fileBuff[fileCursor++]))[0] & 0x80);
	fa->Data(); // prevent deallocation of the fileAccessor as we're operating on the raw data buffer
	return result;
}


int64_t VMReader::ReadSLEB128(size_t limit)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;

	auto mapping = m_vm->MappingAtAddress(m_cursor);
	auto fileCursor = mapping.second;
	auto fileLimit = fileCursor + (limit - m_cursor);
	auto fa = mapping.first.fileAccessor->lock();
	auto* fileBuff = (uint8_t*)fa->Data();

	while (fileCursor < fileLimit)
	{
		cur = ((uint64_t*)&((fileBuff)[fileCursor]))[0];
		fileCursor++;
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	fa->Data(); // prevent deallocation of the fileAccessor as we're operating on the raw data buffer
	return value;
}

std::string VM::ReadNullTermString(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadNullTermString(mapping.second);
}

uint8_t VM::ReadUChar(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VM::ReadChar(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VM::ReadUShort(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VM::ReadShort(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VM::ReadUInt32(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VM::ReadInt32(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VM::ReadULong(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VM::ReadLong(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}

BinaryNinja::DataBuffer VM::ReadBuffer(size_t addr, size_t length)
{
	auto mapping = MappingAtAddress(addr);
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}


void VM::Read(void* dest, size_t addr, size_t length)
{
	auto mapping = MappingAtAddress(addr);
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}

VMReader::VMReader(std::shared_ptr<VM> vm, size_t addressSize) : m_vm(vm), m_cursor(0), m_addressSize(addressSize) {}


void VMReader::Seek(size_t address)
{
	m_cursor = address;
}

void VMReader::SeekRelative(size_t offset)
{
	m_cursor += offset;
}

std::string VMReader::ReadCString(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadNullTermString(mapping.second);
}

uint8_t VMReader::ReadUChar(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 1;
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VMReader::ReadChar(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 1;
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VMReader::ReadUShort(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 2;
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VMReader::ReadShort(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 2;
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VMReader::ReadUInt32(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 4;
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VMReader::ReadInt32(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 4;
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VMReader::ReadULong(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 8;
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VMReader::ReadLong(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 8;
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}


size_t VMReader::ReadPointer(size_t address)
{
	if (m_addressSize == 8)
		return ReadULong(address);
	else if (m_addressSize == 4)
		return ReadUInt32(address);

	// no idea what horrible arch we have, should probably die here.
	return 0;
}


size_t VMReader::ReadPointer()
{
	if (m_addressSize == 8)
		return Read64();
	else if (m_addressSize == 4)
		return Read32();

	return 0;
}

BinaryNinja::DataBuffer VMReader::ReadBuffer(size_t length)
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += length;
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}

BinaryNinja::DataBuffer VMReader::ReadBuffer(size_t addr, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(addr);
	m_cursor = addr + length;
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}

void VMReader::Read(void* dest, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += length;
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}

void VMReader::Read(void* dest, size_t addr, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(addr);
	m_cursor = addr + length;
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}


uint8_t VMReader::Read8()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 1;
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VMReader::ReadS8()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 1;
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VMReader::Read16()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 2;
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VMReader::ReadS16()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 2;
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VMReader::Read32()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 4;
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VMReader::ReadS32()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 4;
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VMReader::Read64()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 8;
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VMReader::ReadS64()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 8;
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}
