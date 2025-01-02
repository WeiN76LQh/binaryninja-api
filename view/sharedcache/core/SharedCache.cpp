//
// Created by kat on 5/19/23.
//

#include "binaryninjaapi.h"

/* ---
 * This is the primary image loader logic for Shared Caches
 *
 * It is standalone code that operates on a DSCView.
 *
 * This has to recreate _all_ of the Mach-O View logic, but slightly differently, as everything is spicy and weird and
 * 		different enough that it's not worth trying to make a shared base class.
 *
 * The SharedCache api object is a 'Controller' that serializes its own state in view metadata.
 *
 * It is multithreading capable (multiple SharedCache objects can exist and do things on different threads, it will manage)
 *
 * View state is saved to BinaryView any time it changes, however due to json deser speed we must also cache it on heap.
 *	This cache is 'load bearing' and controllers on other threads may serialize it back to view after making changes, so it
 *	must be kept up to date.
 *
 *
 *
 * */

#include "SharedCache.h"
#include "ObjC.h"
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <fcntl.h>
#include <memory>
#include <chrono>
#include <thread>

#include "immer/flex_vector.hpp"
#include "immer/vector_transient.hpp"
#include "view/sharedcache/api/sharedcachecore.h"

using namespace BinaryNinja;
using namespace SharedCacheCore;

#ifdef _MSC_VER

int count_trailing_zeros(uint64_t value) {
	unsigned long index; // 32-bit long on Windows
	if (_BitScanForward64(&index, value)) {
		return index;
	} else {
		return 64; // If the value is 0, return 64.
	}
}
#else
int count_trailing_zeros(uint64_t value) {
	return value == 0 ? 64 : __builtin_ctzll(value);
}
#endif

struct SharedCache::State
{
	immer::map<uint64_t, std::shared_ptr<immer::map<uint64_t, Ref<Symbol>>>> exportInfos;
	immer::map<uint64_t, std::shared_ptr<immer::vector<Ref<Symbol>>>> symbolInfos;

	immer::map<std::string, uint64_t> imageStarts;
	immer::map<uint64_t, SharedCacheMachOHeader> headers;

	immer::vector<CacheImage> images;

	immer::vector<MemoryRegion> regionsMappedIntoMemory;

	immer::vector<BackingCache> backingCaches;

	immer::vector<MemoryRegion> stubIslandRegions;  // TODO honestly both of these should be refactored into nonImageRegions. :p
	immer::vector<MemoryRegion> dyldDataRegions;
	immer::vector<MemoryRegion> nonImageRegions;

	std::optional<std::pair<size_t, size_t>> objcOptimizationDataRange;

	std::string baseFilePath;
	SharedCacheFormat cacheFormat;
	DSCViewState viewState = DSCViewStateUnloaded;
};

struct SharedCache::ViewSpecificState {
	std::mutex typeLibraryMutex;
	std::unordered_map<std::string, Ref<TypeLibrary>> typeLibraries;

	std::mutex viewOperationsThatInfluenceMetadataMutex;

	std::atomic<BNDSCViewLoadProgress> progress;

	std::mutex stateMutex;

	std::mutex memoryRegionLoadingMutexesMutex;
	std::unordered_map<uint64_t, std::mutex> memoryRegionLoadingMutexes;

#if __has_feature(__cpp_lib_atomic_shared_ptr)
       std::shared_ptr<struct SharedCache::State> GetCachedState() const {
               return cachedState;
       }
       void SetCachedState(std::shared_ptr<struct SharedCache::State> newState) {
               cachedState = newState;
       }
#else
       std::shared_ptr<struct SharedCache::State> GetCachedState() const {
               return std::atomic_load(&cachedState);
       }
       void SetCachedState(std::shared_ptr<struct SharedCache::State> newState) {
               std::atomic_store(&cachedState, std::move(newState));
       }
#endif
private:
#if __has_feature(__cpp_lib_atomic_shared_ptr)
       std::atomic<std::shared_ptr<struct SharedCache::State>> cachedState;
#else
       std::shared_ptr<struct SharedCache::State> cachedState;
#endif
};


std::shared_ptr<SharedCache::ViewSpecificState> ViewSpecificStateForId(uint64_t viewIdentifier, bool insertIfNeeded = true) {
	static std::mutex viewSpecificStateMutex;
	static std::unordered_map<uint64_t, std::weak_ptr<SharedCache::ViewSpecificState>> viewSpecificState;

	std::lock_guard lock(viewSpecificStateMutex);

	if (auto it = viewSpecificState.find(viewIdentifier); it != viewSpecificState.end()) {
		if (auto statePtr = it->second.lock()) {
			return statePtr;
		}
	}

	if (!insertIfNeeded) {
		return nullptr;
	}

	auto statePtr = std::make_shared<SharedCache::ViewSpecificState>();
	viewSpecificState[viewIdentifier] = statePtr;

	// Prune entries for any views that are no longer in use.
	for (auto it = viewSpecificState.begin(); it != viewSpecificState.end(); ) {
		if (it->second.expired()) {
			it = viewSpecificState.erase(it);
		} else {
			++it;
		}
	}

	return statePtr;
}

std::shared_ptr<SharedCache::ViewSpecificState> ViewSpecificStateForView(Ref<BinaryNinja::BinaryView> view) {
	return ViewSpecificStateForId(view->GetFile()->GetSessionId());
}

std::string base_name(std::string const& path)
{
	return path.substr(path.find_last_of("/\\") + 1);
}

std::string base_name(std::string_view path)
{
	return std::string(path.substr(path.find_last_of("/\\") + 1));
}

BNSegmentFlag SegmentFlagsFromMachOProtections(int initProt, int maxProt) {

	uint32_t flags = 0;
	if (initProt & MACHO_VM_PROT_READ)
		flags |= SegmentReadable;
	if (initProt & MACHO_VM_PROT_WRITE)
		flags |= SegmentWritable;
	if (initProt & MACHO_VM_PROT_EXECUTE)
		flags |= SegmentExecutable;
	if (((initProt & MACHO_VM_PROT_WRITE) == 0) &&
		((maxProt & MACHO_VM_PROT_WRITE) == 0))
		flags |= SegmentDenyWrite;
	if (((initProt & MACHO_VM_PROT_EXECUTE) == 0) &&
		((maxProt & MACHO_VM_PROT_EXECUTE) == 0))
		flags |= SegmentDenyExecute;
	return (BNSegmentFlag)flags;
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static int64_t readSLEB128(DataBuffer& buffer, size_t length, size_t& offset)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;
	while (offset < length)
	{
		cur = buffer[offset++];
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	return value;
}
#pragma clang diagnostic pop


static uint64_t readLEB128(DataBuffer& p, size_t end, size_t& offset)
{
	uint64_t result = 0;
	int bit = 0;
	do
	{
		if (offset >= end)
			return -1;

		uint64_t slice = p[offset] & 0x7f;

		if (bit > 63)
			return -1;
		else
		{
			result |= (slice << bit);
			bit += 7;
		}
	} while (p[offset++] & 0x80);
	return result;
}


uint64_t readValidULEB128(DataBuffer& buffer, size_t& cursor)
{
	uint64_t value = readLEB128(buffer, buffer.GetLength(), cursor);
	if ((int64_t)value == -1)
		throw ReadException();
	return value;
}


uint64_t SharedCache::FastGetBackingCacheCount(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView)
{
	std::shared_ptr<MMappedFileAccessor> baseFile;
	try {
		baseFile = MMappedFileAccessor::Open(dscView, dscView->GetFile()->GetSessionId(), dscView->GetFile()->GetOriginalFilename())->lock();
	}
	catch (...){
		LogError("Shared Cache preload: Failed to open file %s", dscView->GetFile()->GetOriginalFilename().c_str());
		return 0;
	}

	dyld_cache_header header {};
	size_t header_size = baseFile->ReadUInt32(16);
	baseFile->Read(&header, 0, std::min(header_size, sizeof(dyld_cache_header)));

	SharedCacheFormat cacheFormat;

	if (header.imagesCountOld != 0)
		cacheFormat = RegularCacheFormat;

	size_t subCacheOff = offsetof(struct dyld_cache_header, subCacheArrayOffset);
	size_t headerEnd = header.mappingOffset;
	if (headerEnd > subCacheOff)
	{
		if (header.cacheType != 2)
		{
			if (std::filesystem::exists(ResolveFilePath(dscView, baseFile->Path() + ".01")))
				cacheFormat = LargeCacheFormat;
			else
				cacheFormat = SplitCacheFormat;
		}
		else
			cacheFormat = iOS16CacheFormat;
	}

	switch (cacheFormat)
	{
	case RegularCacheFormat:
	{
		return 1;
	}
	case LargeCacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 1;
	}
	case SplitCacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 2;
	}
	case iOS16CacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 2;
	}
	}
}


void SharedCache::PerformInitialLoad()
{
	m_logger->LogInfo("Performing initial load of Shared Cache");
	auto path = m_dscView->GetFile()->GetOriginalFilename();
	auto baseFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), path)->lock();

	m_viewSpecificState->progress = LoadProgressLoadingCaches;

	WillMutateState();

	MutableState().baseFilePath = path;

	DataBuffer sig = baseFile->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		abort();
	const char* magic = (char*)sig.GetData();
	if (strncmp(magic, "dyld", 4) != 0)
		abort();

	MutableState().cacheFormat = RegularCacheFormat;

	dyld_cache_header primaryCacheHeader {};
	size_t header_size = baseFile->ReadUInt32(16);
	baseFile->Read(&primaryCacheHeader, 0, std::min(header_size, sizeof(dyld_cache_header)));

	if (primaryCacheHeader.imagesCountOld != 0)
		MutableState().cacheFormat = RegularCacheFormat;

	size_t subCacheOff = offsetof(struct dyld_cache_header, subCacheArrayOffset);
	size_t headerEnd = primaryCacheHeader.mappingOffset;
	if (headerEnd > subCacheOff)
	{
		if (primaryCacheHeader.cacheType != 2)
		{
			if (std::filesystem::exists(ResolveFilePath(m_dscView, baseFile->Path() + ".01")))
				MutableState().cacheFormat = LargeCacheFormat;
			else
				MutableState().cacheFormat = SplitCacheFormat;
		}
		else
			MutableState().cacheFormat = iOS16CacheFormat;
	}

	if (primaryCacheHeader.objcOptsOffset && primaryCacheHeader.objcOptsSize) {
		MutableState().objcOptimizationDataRange = {primaryCacheHeader.objcOptsOffset, primaryCacheHeader.objcOptsSize};
	}

	// Don't store directly into `State().imageStarts` so that the order is preserved. That way 
	// `imageIndex` can be assigned to a `CacheImage` in `m_images`.
	std::vector<std::pair<std::string, uint64_t>> imageStarts;

	switch (State().cacheFormat)
	{
	case RegularCacheFormat:
	{
		dyld_cache_mapping_info mapping {};
		BackingCache cache;
		cache.cacheType = BackingCacheTypePrimary;
		cache.path = path;

		immer::vector_transient<dyld_cache_mapping_info> mappings;
		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			mappings.push_back(mapping);
		}
		cache.mappings = std::move(mappings).persistent();
		MutableState().backingCaches = State().backingCaches.push_back(std::move(cache));

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCountOld; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffsetOld + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			imageStarts.push_back({iname, img.address});
		}

		m_logger->LogInfo("Found %d images in the shared cache", primaryCacheHeader.imagesCountOld);

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> addresses;
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				addresses.push_back(baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize())));
			}
			baseFile.reset(); // No longer needed, we're about to remap this file into VM space so we can load these.
			uint64_t i = 0;
			auto stubIslandRegions = State().stubIslandRegions.transient();
			for (auto address : addresses)
			{
				i++;
				auto vm = GetVMMap(true);
				auto machoHeader = SharedCache::LoadHeaderForAddress(vm, address, "dyld_shared_cache_branch_islands_" + std::to_string(i));
				if (machoHeader)
				{
					for (const auto& segment : machoHeader->segments)
					{
						MemoryRegion stubIslandRegion;
						stubIslandRegion.start = segment.vmaddr;
						stubIslandRegion.size = segment.filesize;
						char segName[17];
						memcpy(segName, segment.segname, 16);
						segName[16] = 0;
						std::string segNameStr = std::string(segName);
						stubIslandRegion.prettyName = "dyld_shared_cache_branch_islands_" + std::to_string(i) + "::" + segNameStr;
						stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
						stubIslandRegions.push_back(std::move(stubIslandRegion));
					}
				}
			}
			MutableState().stubIslandRegions = std::move(stubIslandRegions).persistent();
		}

		m_logger->LogInfo("Found %d branch pools in the shared cache", primaryCacheHeader.branchPoolsCount);

		break;
	}
	case LargeCacheFormat:
	{
		dyld_cache_mapping_info mapping {};	 // We're going to reuse this for all of the mappings. We only need it
											 // briefly.

		BackingCache cache;
		cache.cacheType = BackingCacheTypePrimary;
		cache.path = path;
		auto mappings = cache.mappings.transient();
		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			mappings.push_back(mapping);
		}
		cache.mappings = std::move(mappings).persistent();
		MutableState().backingCaches = State().backingCaches.push_back(std::move(cache));

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			imageStarts.push_back({iname, img.address});
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				imageStarts.push_back({"dyld_shared_cache_branch_islands_" + std::to_string(i), baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()))});
			}
		}

		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		dyld_subcache_entry2 _entry {};
		std::vector<dyld_subcache_entry2> subCacheEntries;
		for (size_t i = 0; i < subCacheCount; i++)
		{
			baseFile->Read(&_entry, primaryCacheHeader.subCacheArrayOffset + (i * sizeof(dyld_subcache_entry2)),
				sizeof(dyld_subcache_entry2));
			subCacheEntries.push_back(_entry);
		}

		baseFile.reset();
		for (const auto& entry : subCacheEntries)
		{
			std::string subCachePath;
			std::string subCacheFilename;
			if (std::string(entry.fileExtension).find('.') != std::string::npos)
			{
				subCachePath = path + entry.fileExtension;
				subCacheFilename = mainFileName + entry.fileExtension;
			}
			else
			{
				subCachePath = path + "." + entry.fileExtension;
				subCacheFilename = mainFileName + "." + entry.fileExtension;
			}
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			dyld_cache_mapping_info subCacheMapping {};
			BackingCache subCache;
			subCache.cacheType = BackingCacheTypeSecondary;
			subCache.path = subCachePath;

			auto mappings = subCache.mappings.transient();
			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				mappings.push_back(subCacheMapping);
			}
			subCache.mappings = std::move(mappings).persistent();

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				MutableState().stubIslandRegions = State().stubIslandRegions.push_back(std::move(stubIslandRegion));
			}

			MutableState().backingCaches = State().backingCaches.push_back(std::move(subCache));
		}
		break;
	}
	case SplitCacheFormat:
	{
		dyld_cache_mapping_info mapping {};	 // We're going to reuse this for all of the mappings. We only need it
											 // briefly.
		BackingCache cache;
		cache.cacheType = BackingCacheTypePrimary;
		cache.path = path;

		auto mappings = cache.mappings.transient();
		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			mappings.push_back(mapping);
		}
		cache.mappings = std::move(mappings).persistent();
		MutableState().backingCaches = State().backingCaches.push_back(std::move(cache));

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			imageStarts.push_back({iname, img.address});
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				imageStarts.push_back({"dyld_shared_cache_branch_islands_" + std::to_string(i), baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()))});
			}
		}

		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		baseFile.reset();

		for (size_t i = 1; i <= subCacheCount; i++)
		{
			auto subCachePath = path + "." + std::to_string(i);
			auto subCacheFilename = mainFileName + "." + std::to_string(i);
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			BackingCache subCache;
			subCache.cacheType = BackingCacheTypeSecondary;
			subCache.path = subCachePath;

			dyld_cache_mapping_info subCacheMapping {};

			auto mappings = subCache.mappings.transient();
			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				mappings.push_back(subCacheMapping);
			}
			subCache.mappings = std::move(mappings).persistent();
			MutableState().backingCaches = State().backingCaches.push_back(std::move(subCache));

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				MutableState().stubIslandRegions = State().stubIslandRegions.push_back(std::move(stubIslandRegion));
			}
		}

		// Load .symbols subcache

		auto subCachePath = path + ".symbols";
		auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

		dyld_cache_header subCacheHeader {};
		uint64_t headerSize = subCacheFile->ReadUInt32(16);
		if (headerSize > sizeof(dyld_cache_header))
		{
			m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
				sizeof(dyld_cache_header));
			headerSize = sizeof(dyld_cache_header);
		}
		subCacheFile->Read(&subCacheHeader, 0, headerSize);

		dyld_cache_mapping_info subCacheMapping {};
		BackingCache subCache;
		mappings = subCache.mappings.transient();

		for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
		{
			subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
				sizeof(subCacheMapping));
			mappings.push_back(subCacheMapping);
		}
		subCache.mappings = std::move(mappings).persistent();

		MutableState().backingCaches = State().backingCaches.push_back(std::move(subCache));
		break;
	}
	case iOS16CacheFormat:
	{
		dyld_cache_mapping_info mapping {};

		BackingCache cache;
		cache.cacheType = BackingCacheTypePrimary;
		cache.path = path;

		auto mappings = cache.mappings.transient();
		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			mappings.push_back(mapping);
		}
		cache.mappings = std::move(mappings).persistent();
		MutableState().backingCaches = State().backingCaches.push_back(std::move(cache));

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			imageStarts.push_back({iname, img.address});
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				imageStarts.push_back({"dyld_shared_cache_branch_islands_" + std::to_string(i), baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()))});
			}
		}

		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		dyld_subcache_entry2 _entry {};

		std::vector<dyld_subcache_entry2> subCacheEntries;
		for (size_t i = 0; i < subCacheCount; i++)
		{
			baseFile->Read(&_entry, primaryCacheHeader.subCacheArrayOffset + (i * sizeof(dyld_subcache_entry2)),
				sizeof(dyld_subcache_entry2));
			subCacheEntries.push_back(_entry);
		}

		baseFile.reset();

		for (const auto& entry : subCacheEntries)
		{
			std::string subCachePath;
			std::string subCacheFilename;
			if (std::string(entry.fileExtension).find('.') != std::string::npos)
			{
				subCachePath = path + entry.fileExtension;
				subCacheFilename = mainFileName + entry.fileExtension;
			}
			else
			{
				subCachePath = path + "." + entry.fileExtension;
				subCacheFilename = mainFileName + "." + entry.fileExtension;
			}

			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			dyld_cache_mapping_info subCacheMapping {};

			BackingCache subCache;
			subCache.cacheType = BackingCacheTypeSecondary;
			subCache.path = subCachePath;
			auto mappings = subCache.mappings.transient();

			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				mappings.push_back(subCacheMapping);

				if (subCachePath.find(".dylddata") != std::string::npos)
				{
					auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
					uint64_t address = subCacheMapping.address;
					uint64_t size = subCacheMapping.size;
					MemoryRegion dyldDataRegion;
					dyldDataRegion.start = address;
					dyldDataRegion.size = size;
					dyldDataRegion.prettyName = subCacheFilename + "::_data" + std::to_string(j);
					dyldDataRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable);
					MutableState().dyldDataRegions = State().dyldDataRegions.push_back(std::move(dyldDataRegion));
				}
			}
			subCache.mappings = std::move(mappings).persistent();

			MutableState().backingCaches = State().backingCaches.push_back(std::move(subCache));

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				MutableState().stubIslandRegions = State().stubIslandRegions.push_back(std::move(stubIslandRegion));
			}
		}

		// Load .symbols subcache
		try
		{
			auto subCachePath = path + ".symbols";
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();
			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (subCacheFile->ReadUInt32(16) > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected, using default size");
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			BackingCache subCache;
			subCache.cacheType = BackingCacheTypeSymbols;
			subCache.path = subCachePath;

			dyld_cache_mapping_info subCacheMapping {};
			auto mappings = subCache.mappings.transient();
			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				mappings.push_back(subCacheMapping);
			}
			subCache.mappings = std::move(mappings).persistent();
			MutableState().backingCaches = State().backingCaches.push_back(std::move(subCache));
		}
		catch (...)
		{
			m_logger->LogWarn("Failed to load the symbols cache");
		}
		break;
	}
	}
	baseFile.reset();

	m_viewSpecificState->progress = LoadProgressLoadingImages;

	// We have set up enough metadata to map VM now.

	auto vm = GetVMMap(true);
	if (!vm)
	{
		m_logger->LogError("Failed to map VM pages for Shared Cache on initial load, this is fatal.");
		return;
	}

	auto headers = State().headers.transient();
	auto images = State().images.transient();
	auto stateImageStarts = State().imageStarts.transient();
	for (uint32_t imageIndex = 0; imageIndex < imageStarts.size(); imageIndex++)
	{
		const auto& start = imageStarts[imageIndex];
		stateImageStarts.set(start.first, start.second);
		try {
			auto imageHeader = SharedCache::LoadHeaderForAddress(vm, start.second, start.first);
			if (imageHeader)
			{
				if (imageHeader->linkeditPresent && vm->AddressIsMapped(imageHeader->linkeditSegment.vmaddr))
				{
					auto mapping = vm->MappingAtAddress(imageHeader->linkeditSegment.vmaddr);
					imageHeader->exportTriePath = mapping.first.filePath;
				}
				headers.set(start.second, imageHeader.value());
				CacheImage image;
				image.index = imageIndex;
				image.installName = start.first;
				image.headerLocation = start.second;
				auto regions = image.regions.transient();
				for (const auto& segment : imageHeader->segments)
				{
					char segName[17];
					memcpy(segName, segment.segname, 16);
					segName[16] = 0;
					MemoryRegion sectionRegion;
					sectionRegion.prettyName = imageHeader.value().identifierPrefix + "::" + std::string(segName);
					sectionRegion.start = segment.vmaddr;
					sectionRegion.size = segment.vmsize;
					uint32_t flags = SegmentFlagsFromMachOProtections(segment.initprot, segment.maxprot);

					// if we're positive we have an entry point for some reason, force the segment
					// executable. this helps with kernel images.
					for (auto &entryPoint : imageHeader->m_entryPoints)
						if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
							flags |= SegmentExecutable;

					sectionRegion.flags = (BNSegmentFlag)flags;
					regions.push_back(sectionRegion);
				}
				image.regions = std::move(regions).persistent();
				images.push_back(std::move(image));
			}
			else
			{
				m_logger->LogError("Failed to load Mach-O header for %s", start.first.c_str());
			}
		}
		catch (std::exception& ex)
		{
			m_logger->LogError("Failed to load Mach-O header for %s: %s", start.first.c_str(), ex.what());
		}
	}
	MutableState().headers = std::move(headers).persistent();
	MutableState().images = std::move(images).persistent();

	m_logger->LogInfo("Loaded %d Mach-O headers", State().headers.size());

	auto nonImageRegions = State().nonImageRegions.transient();
	for (const auto& cache : State().backingCaches)
	{
		size_t i = 0;
		for (const auto& mapping : cache.mappings)
		{
			MemoryRegion region;
			region.start = mapping.address;
			region.size = mapping.size;
			region.prettyName = base_name(cache.path) + "::" + std::to_string(i);
			region.flags = SegmentFlagsFromMachOProtections(mapping.initProt, mapping.maxProt);
			nonImageRegions.push_back(std::move(region));
			i++;
		}
	}
	MutableState().nonImageRegions = std::move(nonImageRegions).persistent();

	// Iterate through each Mach-O header
	if (!State().dyldDataRegions.empty())
	{
		// Removal / insertion is not ergonomic with `immer::vector` so use std::vector for this instead.
		std::vector<MemoryRegion> dyldDataRegions(State().dyldDataRegions.begin(), State().dyldDataRegions.end());
		for (const auto& [headerKey, header] : State().headers)
		{
			// Iterate through each segment of the header
			for (const auto& segment : header.segments)
			{
				uint64_t segmentStart = segment.vmaddr;
				uint64_t segmentEnd = segmentStart + segment.vmsize;

				// Iterate through each region in m_dyldDataRegions
				for (auto it = dyldDataRegions.begin(); it != dyldDataRegions.end();)
				{
					uint64_t regionStart = it->start;
					uint64_t regionSize = it->size;
					uint64_t regionEnd = regionStart + regionSize;

					// Check if the region overlaps with the segment
					if (segmentStart < regionEnd && segmentEnd > regionStart)
					{
						// Split the region into two, removing the overlapped portion
						std::vector<MemoryRegion> newRegions;

						// Part before the overlap
						if (regionStart < segmentStart)
						{
							MemoryRegion newRegion(*it);
							newRegion.start = regionStart;
							newRegion.size = segmentStart - regionStart;
							newRegions.push_back(std::move(newRegion));
						}

						// Part after the overlap
						if (regionEnd > segmentEnd)
						{
							MemoryRegion newRegion(*it);
							newRegion.start = segmentEnd;
							newRegion.size = regionEnd - segmentEnd;
							newRegions.push_back(std::move(newRegion));
						}

						// Erase the original region
						it = dyldDataRegions.erase(it);

						// Insert the new regions (if any)
						for (const auto& newRegion : newRegions)
						{
							it = dyldDataRegions.insert(it, newRegion);
							++it;  // Move iterator to the next position
						}
					}
					else
					{
						++it;  // No overlap, move to the next region
					}
				}
			}
		}
		// TODO(bdash): Ideally this would move out of dyldDataRegions.
		MutableState().dyldDataRegions = immer::vector<MemoryRegion>(dyldDataRegions.begin(), dyldDataRegions.end());
	}

	// Iterate through each Mach-O header
	if (!State().nonImageRegions.empty())
	{
		// Removal / insertion is not ergonomic with `immer::vector` so use std::vector for this instead.
		std::vector<MemoryRegion> nonImageRegions(State().nonImageRegions.begin(), State().nonImageRegions.end());
		for (const auto& [headerKey, header] : State().headers)
		{
			// Iterate through each segment of the header
			for (const auto& segment : header.segments)
			{
				uint64_t segmentStart = segment.vmaddr;
				uint64_t segmentEnd = segmentStart + segment.vmsize;

				// Iterate through each region in m_dyldDataRegions
				for (auto it = nonImageRegions.begin(); it != nonImageRegions.end();)
				{
					uint64_t regionStart = it->start;
					uint64_t regionSize = it->size;
					uint64_t regionEnd = regionStart + regionSize;

					// Check if the region overlaps with the segment
					if (segmentStart < regionEnd && segmentEnd > regionStart)
					{
						// Split the region into two, removing the overlapped portion
						std::vector<MemoryRegion> newRegions;

						// Part before the overlap
						if (regionStart < segmentStart)
						{
							MemoryRegion newRegion(*it);
							newRegion.start = regionStart;
							newRegion.size = segmentStart - regionStart;
							newRegions.push_back(std::move(newRegion));
						}

						// Part after the overlap
						if (regionEnd > segmentEnd)
						{
							MemoryRegion newRegion(*it);
							newRegion.start = segmentEnd;
							newRegion.size = regionEnd - segmentEnd;
							newRegions.push_back(std::move(newRegion));
						}

						// Erase the original region
						it = nonImageRegions.erase(it);

						// Insert the new regions (if any)
						for (const auto& newRegion : newRegions)
						{
							it = nonImageRegions.insert(it, newRegion);
							++it;  // Move iterator to the next position
						}
					}
					else
					{
						++it;  // No overlap, move to the next region
					}
				}
			}
		}
		// TODO(bdash): Ideally this would move out of nonImageRegions.
		MutableState().nonImageRegions = immer::vector<MemoryRegion>(nonImageRegions.begin(), nonImageRegions.end());
	}
	SaveToDSCView();

	m_logger->LogDebug("Finished initial load of Shared Cache");

	m_viewSpecificState->progress = LoadProgressFinished;
}

std::shared_ptr<VM> SharedCache::GetVMMap(bool mapPages)
{
	std::shared_ptr<VM> vm = std::make_shared<VM>(0x1000);

	if (mapPages)
	{
		for (const auto& cache : State().backingCaches)
		{
			for (const auto& mapping : cache.mappings)
			{
				vm->MapPages(m_dscView, m_dscView->GetFile()->GetSessionId(), mapping.address, mapping.fileOffset, mapping.size, cache.path,
					[this, vm=vm](std::shared_ptr<MMappedFileAccessor> mmap){
						ParseAndApplySlideInfoForFile(mmap);
					});
			}
		}
	}

	return vm;
}


void SharedCache::DeserializeFromRawView()
{
	if (m_dscView->QueryMetadata(SharedCacheMetadataTag))
	{
		if (auto cachedState = m_viewSpecificState->GetCachedState())
		{
			m_state = std::move(cachedState);
			m_stateIsShared = true;
			m_metadataValid = true;
		}
		else
		{
			LoadFromString(m_dscView->GetStringMetadata(SharedCacheMetadataTag));
		}
		if (!m_metadataValid)
		{
			m_logger->LogError("Failed to deserialize Shared Cache metadata");
			WillMutateState();
			MutableState().viewState = DSCViewStateUnloaded;
		}
	}
	else
	{
		m_metadataValid = true;
		WillMutateState();
		MutableState().viewState = DSCViewStateUnloaded;
		MutableState().images = immer::vector<CacheImage>();
	}
}


std::string to_hex_string(uint64_t value)
{
	std::stringstream ss;
	ss << std::hex << value;
	return ss.str();
}


void SharedCache::ParseAndApplySlideInfoForFile(std::shared_ptr<MMappedFileAccessor> file)
{
	if (file->SlideInfoWasApplied())
		return;

	WillMutateState();
	std::vector<std::pair<uint64_t, uint64_t>> rewrites;

	dyld_cache_header baseHeader;
	file->Read(&baseHeader, 0, sizeof(dyld_cache_header));
	uint64_t base = UINT64_MAX;
	for (const auto& backingCache : State().backingCaches)
	{
		for (const auto& mapping : backingCache.mappings)
		{
			if (mapping.address < base)
			{
				base = mapping.address;
				break;
			}
		}
	}

	std::vector<std::pair<uint64_t, MappingInfo>> mappings;

	if (baseHeader.slideInfoOffsetUnused)
	{
		// Legacy

		auto slideInfoOff = baseHeader.slideInfoOffsetUnused;
		auto slideInfoVersion = file->ReadUInt32(slideInfoOff);
		if (slideInfoVersion != 2 && slideInfoVersion != 3)
		{
			abort();
		}

		MappingInfo map;

		file->Read(&map.mappingInfo, baseHeader.mappingOffset + sizeof(dyld_cache_mapping_info), sizeof(dyld_cache_mapping_info));
		map.file = file;
		map.slideInfoVersion = slideInfoVersion;
		if (map.slideInfoVersion == 2)
			file->Read(&map.slideInfoV2, slideInfoOff, sizeof(dyld_cache_slide_info_v2));
		else if (map.slideInfoVersion == 3)
			file->Read(&map.slideInfoV3, slideInfoOff, sizeof(dyld_cache_slide_info_v3));

		mappings.emplace_back(slideInfoOff, map);
	}
	else
	{
		dyld_cache_header targetHeader;
		file->Read(&targetHeader, 0, sizeof(dyld_cache_header));

		if (targetHeader.mappingWithSlideCount == 0)
		{
			m_logger->LogDebug("No mappings with slide info found");
		}

		for (auto i = 0; i < targetHeader.mappingWithSlideCount; i++)
		{
			dyld_cache_mapping_and_slide_info mappingAndSlideInfo;
			file->Read(&mappingAndSlideInfo, targetHeader.mappingWithSlideOffset + (i * sizeof(dyld_cache_mapping_and_slide_info)), sizeof(dyld_cache_mapping_and_slide_info));
			if (mappingAndSlideInfo.slideInfoFileOffset)
			{
				MappingInfo map;
				map.file = file;
				if (mappingAndSlideInfo.size == 0)
					continue;
				map.slideInfoVersion = file->ReadUInt32(mappingAndSlideInfo.slideInfoFileOffset);
				m_logger->LogDebug("Slide Info Version: %d", map.slideInfoVersion);
				map.mappingInfo.address = mappingAndSlideInfo.address;
				map.mappingInfo.size = mappingAndSlideInfo.size;
				map.mappingInfo.fileOffset = mappingAndSlideInfo.fileOffset;
				if (map.slideInfoVersion == 2)
				{
					file->Read(
						&map.slideInfoV2, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info_v2));
				}
				else if (map.slideInfoVersion == 3)
				{
					file->Read(
						&map.slideInfoV3, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info_v3));
					map.slideInfoV3.auth_value_add = base;
				}
				else if (map.slideInfoVersion == 5)
				{
					file->Read(
						&map.slideInfoV5, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info5));
					map.slideInfoV5.value_add = base;
				}
				else
				{
					m_logger->LogError("Unknown slide info version: %d", map.slideInfoVersion);
					continue;
				}

				uint64_t slideInfoOffset = mappingAndSlideInfo.slideInfoFileOffset;
				mappings.emplace_back(slideInfoOffset, map);
				m_logger->LogDebug("Filename: %s", file->Path().c_str());
				m_logger->LogDebug("Slide Info Offset: 0x%llx", slideInfoOffset);
				m_logger->LogDebug("Mapping Address: 0x%llx", map.mappingInfo.address);
				m_logger->LogDebug("Slide Info v", map.slideInfoVersion);
			}
		}
	}

	if (mappings.empty())
	{
		m_logger->LogDebug("No slide info found");
		file->SetSlideInfoWasApplied(true);
		return;
	}

	for (const auto& [off, mapping] : mappings)
	{
		m_logger->LogDebug("Slide Info Version: %d", mapping.slideInfoVersion);
		uint64_t extrasOffset = off;
		uint64_t pageStartsOffset = off;
		uint64_t pageStartCount;
		uint64_t pageSize;

		if (mapping.slideInfoVersion == 2)
		{
			pageStartsOffset += mapping.slideInfoV2.page_starts_offset;
			pageStartCount = mapping.slideInfoV2.page_starts_count;
			pageSize = mapping.slideInfoV2.page_size;
			extrasOffset += mapping.slideInfoV2.page_extras_offset;
			auto cursor = pageStartsOffset;

			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint16_t start = mapping.file->ReadUShort(cursor);
					cursor += sizeof(uint16_t);
					if (start == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE)
						continue;

					auto rebaseChain = [&](const dyld_cache_slide_info_v2& slideInfo, uint64_t pageContent, uint16_t startOffset)
					{
						uintptr_t slideAmount = 0;

						auto deltaMask = slideInfo.delta_mask;
						auto valueMask = ~deltaMask;
						auto valueAdd = slideInfo.value_add;

						auto deltaShift = count_trailing_zeros(deltaMask) - 2;

						uint32_t pageOffset = startOffset;
						uint32_t delta = 1;
						while ( delta != 0 )
						{
							uint64_t loc = pageContent + pageOffset;
							try
							{
								uintptr_t rawValue = file->ReadULong(loc);
								delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
								uintptr_t value = (rawValue & valueMask);
								if (value != 0)
								{
									value += valueAdd;
									value += slideAmount;
								}
								pageOffset += delta;
								rewrites.emplace_back(loc, value);
							}
							catch (MappingReadException& ex)
							{
								m_logger->LogError("Failed to read v2 slide pointer at 0x%llx\n", loc);
								break;
							}
						}
					};

					if (start & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)
					{
						int j=(start & 0x3FFF);
						bool done = false;
						do
						{
							uint64_t extraCursor = extrasOffset + (j * sizeof(uint16_t));
							try
							{
								auto extra = mapping.file->ReadUShort(extraCursor);
								uint16_t aStart = extra;
								uint64_t page = mapping.mappingInfo.fileOffset + (pageSize * i);
								uint16_t pageStartOffset = (aStart & 0x3FFF)*4;
								rebaseChain(mapping.slideInfoV2, page, pageStartOffset);
								done = (extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END);
								++j;
							}
							catch (MappingReadException& ex)
							{
								m_logger->LogError("Failed to read v2 slide extra at 0x%llx\n", cursor);
								break;
							}
						} while (!done);
					}
					else
					{
						uint64_t page = mapping.mappingInfo.fileOffset + (pageSize * i);
						uint16_t pageStartOffset = start*4;
						rebaseChain(mapping.slideInfoV2, page, pageStartOffset);
					}
				}
				catch (MappingReadException& ex)
				{
					m_logger->LogError("Failed to read v2 slide info at 0x%llx\n", cursor);
				}
			}
		}
		else if (mapping.slideInfoVersion == 3) {
			// Slide Info Version 3 Logic
			pageStartsOffset += sizeof(dyld_cache_slide_info_v3);
			pageStartCount = mapping.slideInfoV3.page_starts_count;
			pageSize = mapping.slideInfoV3.page_size;
			auto cursor = pageStartsOffset;

			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint16_t delta = mapping.file->ReadUShort(cursor);
					cursor += sizeof(uint16_t);
					if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE)
						continue;
					
					delta = delta/sizeof(uint64_t); // initial offset is byte based
					uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
					do
					{
						loc += delta * sizeof(dyld_cache_slide_pointer3);
						try
						{
							dyld_cache_slide_pointer3 slideInfo;
							file->Read(&slideInfo, loc, sizeof(slideInfo));
							delta = slideInfo.plain.offsetToNextPointer;

							if (slideInfo.auth.authenticated)
							{
								uint64_t value = slideInfo.auth.offsetFromSharedCacheBase;
								value += mapping.slideInfoV3.auth_value_add;
								rewrites.emplace_back(loc, value);
							}
							else
							{
								uint64_t value51 = slideInfo.plain.pointerValue;
								uint64_t top8Bits = value51 & 0x0007F80000000000;
								uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFF;
								uint64_t value = (uint64_t)top8Bits << 13 | bottom43Bits;
								rewrites.emplace_back(loc, value);
							}
						}
						catch (MappingReadException& ex)
						{
							m_logger->LogError("Failed to read v3 slide pointer at 0x%llx\n", loc);
							break;
						}
					} while (delta != 0);
				}
				catch (MappingReadException& ex)
				{
					m_logger->LogError("Failed to read v3 slide info at 0x%llx\n", cursor);
				}
			}
		}
		else if (mapping.slideInfoVersion == 5)
		{
			pageStartsOffset += sizeof(dyld_cache_slide_info5);
			pageStartCount = mapping.slideInfoV5.page_starts_count;
			pageSize = mapping.slideInfoV5.page_size;
			auto cursor = pageStartsOffset;

			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint16_t delta = mapping.file->ReadUShort(cursor);
					cursor += sizeof(uint16_t);
					if (delta == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE)
						continue;
					
					delta = delta/sizeof(uint64_t); // initial offset is byte based
					uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
					do
					{
						loc += delta * sizeof(dyld_cache_slide_pointer5);
						try
						{
							dyld_cache_slide_pointer5 slideInfo;
							file->Read(&slideInfo, loc, sizeof(slideInfo));
							delta = slideInfo.regular.next;
							if (slideInfo.auth.auth)
							{
								uint64_t value = mapping.slideInfoV5.value_add + slideInfo.auth.runtimeOffset;
								rewrites.emplace_back(loc, value);
							}
							else
							{
								uint64_t value = mapping.slideInfoV5.value_add + slideInfo.regular.runtimeOffset;
								rewrites.emplace_back(loc, value);
							}
						}
						catch (MappingReadException& ex)
						{
							m_logger->LogError("Failed to read v5 slide pointer at 0x%llx\n", loc);
							break;
						}
					} while (delta != 0);
				}
				catch (MappingReadException& ex)
				{
					m_logger->LogError("Failed to read v5 slide info at 0x%llx\n", cursor);
				}
			}
		}
	}
	for (const auto& [loc, value] : rewrites)
	{
		file->WritePointer(loc, value);
#ifdef SLIDEINFO_DEBUG_TAGS
		uint64_t vmAddr = 0;
		{
			for (uint64_t off = baseHeader.mappingOffset; off < baseHeader.mappingOffset + baseHeader.mappingCount * sizeof(dyld_cache_mapping_info); off += sizeof(dyld_cache_mapping_info))
			{
				dyld_cache_mapping_info mapping;
				file->Read(&mapping, off, sizeof(dyld_cache_mapping_info));
				if (mapping.fileOffset <= loc && loc < mapping.fileOffset + mapping.size)
				{
					vmAddr = mapping.address + (loc - mapping.fileOffset);
					break;
				}
			}
		}
		Ref<TagType> type = m_dscView->GetTagType("slideinfo");
		if (!type)
		{
			m_dscView->AddTagType(new TagType(m_dscView, "slideinfo", "\xF0\x9F\x9A\x9E"));
			type = m_dscView->GetTagType("slideinfo");
		}
		m_dscView->AddAutoDataTag(vmAddr, new Tag(type, "0x" + to_hex_string(file->ReadULong(loc)) + " => 0x" + to_hex_string(value)));
#endif
	}
	m_logger->LogDebug("Applied slide info for %s (0x%llx rewrites)", file->Path().c_str(), rewrites.size());
	file->SetSlideInfoWasApplied(true);
}


SharedCache::SharedCache(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView) : m_dscView(dscView), m_viewSpecificState(ViewSpecificStateForView(dscView))
{
	if (dscView->GetTypeName() != VIEW_NAME)
	{
		// Unreachable?
		m_logger->LogError("Attempted to create SharedCache object from non-Shared Cache view");
		return;
	}
	sharedCacheReferences++;
	INIT_SHAREDCACHE_API_OBJECT()
	m_logger = LogRegistry::GetLogger("SharedCache", dscView->GetFile()->GetSessionId());
	DeserializeFromRawView();
	if (!m_metadataValid)
		return;

	if (State().viewState != DSCViewStateUnloaded) {
		m_viewSpecificState->progress = LoadProgressFinished;
		return;
	}

	std::unique_lock lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
	try {
		PerformInitialLoad();
	}
	catch (...)
	{
		m_logger->LogError("Failed to perform initial load of Shared Cache");
	}

	auto settings = m_dscView->GetLoadSettings(VIEW_NAME);
	bool autoLoadLibsystem = true;
	if (settings && settings->Contains("loader.dsc.autoLoadLibSystem"))
	{
		autoLoadLibsystem = settings->Get<bool>("loader.dsc.autoLoadLibSystem", m_dscView);
	}
	if (autoLoadLibsystem)
	{
		for (const auto& [_, header] : State().headers)
		{
			if (header.installName.find("libsystem_c.dylib") != std::string::npos)
			{
				lock.unlock();
				m_logger->LogInfo("Loading core libsystem_c.dylib library");
				LoadImageWithInstallName(header.installName, false);
				break;
			}
		}
	}

	MutableState().viewState = DSCViewStateLoaded;
	SaveToDSCView();
}

SharedCache::~SharedCache() {
	sharedCacheReferences--;
}

SharedCache* SharedCache::GetFromDSCView(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView)
{
	if (dscView->GetTypeName() != VIEW_NAME)
		return nullptr;
	try {
		return new SharedCache(dscView);
	}
	catch (...)
	{
		return nullptr;
	}
}

std::optional<uint64_t> SharedCache::GetImageStart(std::string installName)
{
	for (const auto& [name, start] : State().imageStarts)
	{
		if (name == installName)
		{
			return start;
		}
	}
	return {};
}

const SharedCacheMachOHeader* SharedCache::HeaderForAddress(uint64_t address)
{
	// It is very common for `HeaderForAddress` to be called with an address corresponding to a header.
	if (auto it = State().headers.find(address)) {
		return it;
	}

	// We _could_ mark each page with the image start? :grimacing emoji:
	// But that'd require mapping pages :grimacing emoji: :grimacing emoji:
	// There's not really any other hacks that could make this faster, that I can think of...
	for (const auto& [start, header] : State().headers)
	{
		for (const auto& segment : header.segments)
		{
			if (segment.vmaddr <= address && segment.vmaddr + segment.vmsize > address)
			{
				return &header;
			}
		}
	}

	return nullptr;
}

std::string SharedCache::NameForAddress(uint64_t address)
{
	for (const auto& stubIsland : State().stubIslandRegions)
	{
		if (stubIsland.start <= address && stubIsland.start + stubIsland.size > address)
		{
			return stubIsland.prettyName;
		}
	}
	for (const auto& dyldData : State().dyldDataRegions)
	{
		if (dyldData.start <= address && dyldData.start + dyldData.size > address)
		{
			return dyldData.prettyName;
		}
	}
	for (const auto& nonImageRegion : State().nonImageRegions)
	{
		if (nonImageRegion.start <= address && nonImageRegion.start + nonImageRegion.size > address)
		{
			return nonImageRegion.prettyName;
		}
	}
	if (auto header = HeaderForAddress(address))
	{
		for (const auto& section : header->sections)
		{
			if (section.addr <= address && section.addr + section.size > address)
			{
				char sectionName[17];
				strncpy(sectionName, section.sectname, 16);
				sectionName[16] = '\0';
				return header->identifierPrefix + "::" + sectionName;
			}
		}
	}
	return "";
}

std::string SharedCache::ImageNameForAddress(uint64_t address)
{
	if (auto header = HeaderForAddress(address))
	{
		return header->identifierPrefix;
	}
	return "";
}

bool SharedCache::LoadImageContainingAddress(uint64_t address, bool skipObjC)
{
	for (const auto& [start, header] : State().headers)
	{
		for (const auto& segment : header.segments)
		{
			if (segment.vmaddr <= address && segment.vmaddr + segment.vmsize > address)
			{
				return LoadImageWithInstallName(header.installName, skipObjC);
			}
		}
	}

	return false;
}

bool SharedCache::LoadSectionAtAddress(uint64_t address)
{
	const MemoryRegion* targetSegment = nullptr;

	for (auto imageIt = State().images.begin(); imageIt != State().images.end(); ++imageIt)
	{
		auto& image = *imageIt;
		for (auto regionIt = image.regions.begin(); regionIt != image.regions.end(); ++regionIt)
		{
			auto& region = *regionIt;
			if (region.start <= address && region.start + region.size > address)
			{
				targetSegment = &region;
				break;
			}
		}
		if (targetSegment)
			break;
	}
	if (!targetSegment)
	{
		for (auto it = State().stubIslandRegions.begin(); it != State().stubIslandRegions.end(); ++it)
		{
			auto stubIsland = &*it;
			if (stubIsland->start <= address && stubIsland->start + stubIsland->size > address)
			{
				if (stubIsland->loaded)
				{
					return true;
				}

				// The region appears not to be loaded. Acquire the loading lock, re-check 
				// that it hasn't been loaded and if it still hasn't then actually load it.
				std::unique_lock<std::mutex> memoryRegionLoadingLockslock(m_viewSpecificState->memoryRegionLoadingMutexesMutex);
				auto& memoryRegionLoadingMutex = m_viewSpecificState->memoryRegionLoadingMutexes[stubIsland->start];
				// Now the specific memory region's loading mutex has been retrieved, this one can be dropped
				memoryRegionLoadingLockslock.unlock();
				// Hold this lock until loading of the region is done
				std::unique_lock<std::mutex> memoryRegionLoadingLock(memoryRegionLoadingMutex);

				// Check the latest state to see if the memory region has been loaded while acquiring the lock
				{
					std::unique_lock<std::mutex> viewStateCacheLock(m_viewSpecificState->stateMutex);
					
					for (auto& cacheStubIsland : m_viewSpecificState->GetCachedState()->stubIslandRegions)
					{
						if (cacheStubIsland.start <= address && cacheStubIsland.start + cacheStubIsland.size > address)
						{
							if (cacheStubIsland.loaded)
							{
								return true;
							}
							stubIsland = &cacheStubIsland;
							break;
						}
					}
				}

				// Still not loaded, so load it below
				std::unique_lock<std::mutex> lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
				DeserializeFromRawView();
				WillMutateState();

				auto vm = GetVMMap();
				if (!vm)
				{
					m_logger->LogError("Failed to map VM pages for Shared Cache.");
					return false;
				}

				m_logger->LogInfo("Loading stub island %s @ 0x%llx", stubIsland->prettyName.c_str(), stubIsland->start);
				auto targetFile = vm->MappingAtAddress(stubIsland->start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(stubIsland->start, stubIsland->size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = stubIsland->prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, stubIsland->size, rawViewEnd, stubIsland->size,
					SegmentReadable | SegmentExecutable);
				m_dscView->AddUserSegment(stubIsland->start, stubIsland->size, rawViewEnd, stubIsland->size,
					SegmentReadable | SegmentExecutable);
				m_dscView->AddUserSection(name, stubIsland->start, stubIsland->size, ReadOnlyCodeSectionSemantics);
				m_dscView->WriteBuffer(stubIsland->start, buff);

				MemoryRegion newStubIsland(*stubIsland);
				newStubIsland.loaded = true;
				newStubIsland.rawViewOffsetIfLoaded = rawViewEnd;
				MutableState().regionsMappedIntoMemory = State().regionsMappedIntoMemory.push_back(newStubIsland);
				MutableState().stubIslandRegions = State().stubIslandRegions.set(it.index(), std::move(newStubIsland));

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		for (auto it = State().dyldDataRegions.begin(); it != State().dyldDataRegions.end(); ++it)
		{
			auto dyldData = &*it;
			if (dyldData->start <= address && dyldData->start + dyldData->size > address)
			{
				if (dyldData->loaded)
				{
					return true;
				}

				// The region appears not to be loaded. Acquire the loading lock, re-check 
				// that it hasn't been loaded and if it still hasn't then actually load it.
				std::unique_lock<std::mutex> memoryRegionLoadingLockslock(m_viewSpecificState->memoryRegionLoadingMutexesMutex);
				auto& memoryRegionLoadingMutex = m_viewSpecificState->memoryRegionLoadingMutexes[dyldData->start];
				// Now the specific memory region's loading mutex has been retrieved, this one can be dropped
				memoryRegionLoadingLockslock.unlock();
				// Hold this lock until loading of the region is done
				std::unique_lock<std::mutex> memoryRegionLoadingLock(memoryRegionLoadingMutex);

				// Check the latest state to see if the memory region has been loaded while acquiring the lock
				{
					std::unique_lock<std::mutex> viewStateCacheLock(m_viewSpecificState->stateMutex);
					
					for (auto& cacheDyldData : m_viewSpecificState->GetCachedState()->dyldDataRegions)
					{
						if (cacheDyldData.start <= address && cacheDyldData.start + cacheDyldData.size > address)
						{
							if (cacheDyldData.loaded)
							{
								return true;
							}
							dyldData = &cacheDyldData;
							break;
						}
					}
				}

				// Still not loaded, so load it below
				std::unique_lock<std::mutex> lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
				DeserializeFromRawView();
				WillMutateState();

				auto vm = GetVMMap();
				if (!vm)
				{
					m_logger->LogError("Failed to map VM pages for Shared Cache.");
					return false;
				}

				m_logger->LogInfo("Loading dyld data %s", dyldData->prettyName.c_str());
				auto targetFile = vm->MappingAtAddress(dyldData->start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(dyldData->start, dyldData->size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = dyldData->prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, dyldData->size, rawViewEnd, dyldData->size,
					SegmentReadable);
				m_dscView->AddUserSegment(dyldData->start, dyldData->size, rawViewEnd, dyldData->size, SegmentReadable);
				m_dscView->AddUserSection(name, dyldData->start, dyldData->size, ReadOnlyDataSectionSemantics);
				m_dscView->WriteBuffer(dyldData->start, buff);

				MemoryRegion newDyldData(*dyldData);
				newDyldData.loaded = true;
				newDyldData.rawViewOffsetIfLoaded = rawViewEnd;
				MutableState().regionsMappedIntoMemory = State().regionsMappedIntoMemory.push_back(newDyldData);
				MutableState().dyldDataRegions = State().dyldDataRegions.set(it.index(), std::move(newDyldData));

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		for (auto it = State().nonImageRegions.begin(); it != State().nonImageRegions.end(); ++it)
		{
			auto region = &*it;
			if (region->start <= address && region->start + region->size > address)
			{
				if (region->loaded)
				{
					return true;
				}

				// The region appears not to be loaded. Acquire the loading lock, re-check 
				// that it hasn't been loaded and if it still hasn't then actually load it.
				std::unique_lock<std::mutex> memoryRegionLoadingLockslock(m_viewSpecificState->memoryRegionLoadingMutexesMutex);
				auto& memoryRegionLoadingMutex = m_viewSpecificState->memoryRegionLoadingMutexes[region->start];
				// Now the specific memory region's loading mutex has been retrieved, this one can be dropped
				memoryRegionLoadingLockslock.unlock();
				// Hold this lock until loading of the region is done
				std::unique_lock<std::mutex> memoryRegionLoadingLock(memoryRegionLoadingMutex);

				// Check the latest state to see if the memory region has been loaded while acquiring the lock
				{
					auto viewSpecificState = m_viewSpecificState;
					std::unique_lock<std::mutex> viewStateCacheLock(viewSpecificState->stateMutex);
					
					for (auto& cacheRegion : viewSpecificState->GetCachedState()->nonImageRegions)
					{
						if (cacheRegion.start <= address && cacheRegion.start + cacheRegion.size > address)
						{
							if (cacheRegion.loaded)
							{
								return true;
							}
							region = &cacheRegion;
							break;
						}
					}
				}

				// Still not loaded, so load it below
				std::unique_lock<std::mutex> lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
				DeserializeFromRawView();
				WillMutateState();

				auto vm = GetVMMap();
				if (!vm)
				{
					m_logger->LogError("Failed to map VM pages for Shared Cache.");
					return false;
				}

				m_logger->LogInfo("Loading non-image region %s", region->prettyName.c_str());
				auto targetFile = vm->MappingAtAddress(region->start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(region->start, region->size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = region->prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, region->size, rawViewEnd, region->size, region->flags);
				m_dscView->AddUserSegment(region->start, region->size, rawViewEnd, region->size, region->flags);
				m_dscView->AddUserSection(name, region->start, region->size, region->flags & SegmentDenyExecute ? ReadOnlyDataSectionSemantics : ReadOnlyCodeSectionSemantics);
				m_dscView->WriteBuffer(region->start, buff);

				MemoryRegion newRegion(*region);
				newRegion.loaded = true;
				newRegion.rawViewOffsetIfLoaded = rawViewEnd;
				MutableState().regionsMappedIntoMemory = State().regionsMappedIntoMemory.push_back(newRegion);
				MutableState().nonImageRegions = State().nonImageRegions.set(it.index(), std::move(newRegion));

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		m_logger->LogError("Failed to find a segment containing address 0x%llx", address);
		return false;
	}

	std::unique_lock lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
	DeserializeFromRawView();
	WillMutateState();

	auto vm = GetVMMap();
	if (!vm)
	{
		m_logger->LogError("Failed to map VM pages for Shared Cache.");
		return false;
	}

	SharedCacheMachOHeader targetHeader;
	decltype(State().images.begin()) targetImageIt;
	decltype(CacheImage().regions.begin()) targetSegmentIt;
	targetSegment = nullptr;

	for (auto imageIt = State().images.begin(); imageIt != State().images.end(); ++imageIt)
	{
		for (auto regionIt = imageIt->regions.begin(); regionIt != imageIt->regions.end(); ++regionIt)
		{
			if (regionIt->start <= address && regionIt->start + regionIt->size > address)
			{
				targetHeader = State().headers[imageIt->headerLocation];
				targetImageIt = imageIt;
				targetSegmentIt = regionIt;
				targetSegment = &*regionIt;
				break;
			}
		}
		if (targetSegment)
			break;
	}

	auto id = m_dscView->BeginUndoActions();
	auto rawViewEnd = m_dscView->GetParentView()->GetEnd();
	auto reader = VMReader(vm);

	m_logger->LogDebug("Partial loading image %s", targetHeader.installName.c_str());

	auto targetFile = vm->MappingAtAddress(targetSegment->start).first.fileAccessor->lock();
	ParseAndApplySlideInfoForFile(targetFile);
	auto buff = reader.ReadBuffer(targetSegment->start, targetSegment->size);
	m_dscView->GetParentView()->GetParentView()->WriteBuffer(
		m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
	m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
	m_dscView->GetParentView()->AddAutoSegment(
		rawViewEnd, targetSegment->size, rawViewEnd, targetSegment->size, SegmentReadable);
	m_dscView->AddUserSegment(
		targetSegment->start, targetSegment->size, rawViewEnd, targetSegment->size, targetSegment->flags);
	m_dscView->WriteBuffer(targetSegment->start, buff);

	MemoryRegion newTargetSegment(*targetSegment);
	newTargetSegment.loaded = true;
	newTargetSegment.rawViewOffsetIfLoaded = rawViewEnd;
	MutableState().regionsMappedIntoMemory = State().regionsMappedIntoMemory.push_back(newTargetSegment);

	auto images = State().images;
	auto regions = images[targetImageIt.index()].regions;
	CacheImage newTargetImage(*targetImageIt);
	newTargetImage.regions = regions.set(targetSegmentIt.index(), std::move(newTargetSegment));
	MutableState().images = images.set(targetImageIt.index(), std::move(newTargetImage));

	SaveToDSCView();

	if (!targetSegment->headerInitialized)
	{
		targetSegment = &State().images[targetImageIt.index()].regions[targetSegmentIt.index()];
		SharedCache::InitializeHeader(m_dscView, vm.get(), targetHeader, {targetSegment});

		MemoryRegion newTargetSegment(*targetSegment);
		newTargetSegment.headerInitialized = true;
		auto images = State().images;
		auto regions = images[targetImageIt.index()].regions;
		CacheImage newTargetImage(*targetImageIt);
		newTargetImage.regions = regions.set(targetSegmentIt.index(), std::move(newTargetSegment));
		MutableState().images = images.set(targetImageIt.index(), std::move(newTargetImage));
	}

	m_dscView->AddAnalysisOption("linearsweep");
	m_dscView->UpdateAnalysis();

	m_dscView->CommitUndoActions(id);

	return true;
}

static void GetObjCSettings(Ref<BinaryView> view, bool* processObjCMetadata, bool* processCFStrings)
{
	auto settings = view->GetLoadSettings(VIEW_NAME);
	*processCFStrings = true;
	*processObjCMetadata = true;
	if (settings && settings->Contains("loader.dsc.processCFStrings"))
		*processCFStrings = settings->Get<bool>("loader.dsc.processCFStrings", view);
	if (settings && settings->Contains("loader.dsc.processObjC"))
		*processObjCMetadata = settings->Get<bool>("loader.dsc.processObjC", view);
}

static void ProcessObjCSectionsForImageWithName(std::string baseName, std::shared_ptr<VM> vm, std::shared_ptr<DSCObjC::DSCObjCProcessor> objc, bool processCFStrings, bool processObjCMetadata, Ref<Logger> logger)
{
	try
	{
		if (processObjCMetadata)
			objc->ProcessObjCData(vm, baseName);
		if (processCFStrings)
			objc->ProcessCFStrings(vm, baseName);
	}
	catch (const std::exception& ex)
	{
		logger->LogWarn("Error processing ObjC data for image %s: %s", baseName.c_str(), ex.what());
	}
	catch (...)
	{
		logger->LogWarn("Error processing ObjC data for image %s", baseName.c_str());
	}
}

void SharedCache::ProcessObjCSectionsForImageWithInstallName(std::string_view installName)
{
	bool processCFStrings;
	bool processObjCMetadata;
	GetObjCSettings(m_dscView, &processCFStrings, &processObjCMetadata);

	if (!processObjCMetadata && !processCFStrings)
		return;

	auto objc = std::make_shared<DSCObjC::DSCObjCProcessor>(m_dscView, this, false);
	auto vm = GetVMMap();

	ProcessObjCSectionsForImageWithName(base_name(installName), vm, objc, processCFStrings, processObjCMetadata, m_logger);
}

void SharedCache::ProcessAllObjCSections()
{
	bool processCFStrings;
	bool processObjCMetadata;
	GetObjCSettings(m_dscView, &processCFStrings, &processObjCMetadata);

	if (!processObjCMetadata && !processCFStrings)
		return;

	auto objc = std::make_shared<DSCObjC::DSCObjCProcessor>(m_dscView, this, false);
	auto vm = GetVMMap();

	std::set<uint64_t> processedImageHeaders;
	for (auto region : GetMappedRegions())
	{
		if (!region.loaded)
			continue;
		
		// Don't repeat the same images multiple times
		auto header = HeaderForAddress(region.start);
		if (!header)
			continue;
		if (processedImageHeaders.find(header->textBase) != processedImageHeaders.end())
			continue;
		processedImageHeaders.insert(header->textBase);

		ProcessObjCSectionsForImageWithName(header->identifierPrefix, vm, objc, processCFStrings, processObjCMetadata, m_logger);
	}
}

bool SharedCache::LoadImageWithInstallName(std::string_view installName, bool skipObjC)
{
	auto settings = m_dscView->GetLoadSettings(VIEW_NAME);

	std::unique_lock lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);

	DeserializeFromRawView();
	WillMutateState();

	m_logger->LogInfo("Loading image %s", installName.data());

	auto vm = GetVMMap();
	const CacheImage* targetImage = nullptr;
	decltype(State().images.begin()) targetImageIt;

	for (auto it = State().images.begin(); it != State().images.end(); ++it)
	{
		if (it->installName == installName)
		{
			targetImage = &*it;
			targetImageIt = it;
			break;
		}
	}

	auto it = State().headers.find(targetImage->headerLocation);
	if (!it)
	{
		return false;
	}
	const auto& header = *it;

	auto id = m_dscView->BeginUndoActions();
	MutableState().viewState = DSCViewStateLoadedWithImages;

	auto reader = VMReader(vm);
	reader.Seek(targetImage->headerLocation);

	std::vector<size_t> regionsToLoad;

	auto newTargetImageRegions = targetImage->regions.transient();
	auto newRegionsMappedIntoMemory = State().regionsMappedIntoMemory.transient();
	for (auto it = targetImage->regions.begin(); it != targetImage->regions.end(); ++it)
	{
		auto& region = *it;
		bool allowLoadingLinkedit = false;
		if (settings && settings->Contains("loader.dsc.allowLoadingLinkeditSegments"))
			allowLoadingLinkedit = settings->Get<bool>("loader.dsc.allowLoadingLinkeditSegments", m_dscView);
		if ((region.prettyName.find("__LINKEDIT") != std::string::npos) && !allowLoadingLinkedit)
			continue;

		if (region.loaded)
		{
			m_logger->LogDebug("Skipping region %s as it is already loaded.", region.prettyName.c_str());
			continue;
		}

		auto targetFile = vm->MappingAtAddress(region.start).first.fileAccessor->lock();
		ParseAndApplySlideInfoForFile(targetFile);

		auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

		auto buff = reader.ReadBuffer(region.start, region.size);
		m_dscView->GetParentView()->GetParentView()->WriteBuffer(rawViewEnd, buff);
		m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);

		MemoryRegion newRegion(region);
		newRegion.loaded = true;
		newRegion.rawViewOffsetIfLoaded = rawViewEnd;
		newRegionsMappedIntoMemory.push_back(newRegion);
		newTargetImageRegions.set(it.index(), std::move(newRegion));
		regionsToLoad.push_back(it.index());

		m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, region.size, rawViewEnd, region.size, region.flags);
		m_dscView->AddUserSegment(region.start, region.size, rawViewEnd, region.size, region.flags);
		m_dscView->WriteBuffer(region.start, buff);
	}

	if (regionsToLoad.empty())
	{
		m_logger->LogWarn("No regions to load for image %s", installName.data());
		return false;
	}

	MutableState().regionsMappedIntoMemory = std::move(newRegionsMappedIntoMemory).persistent();
	auto images = State().images;
	CacheImage newTargetImage(*targetImage);
	// newTargetImageRegions is intentionally not moved here as it is used again below. 
	newTargetImage.regions = newTargetImageRegions.persistent();
	MutableState().images = images.set(targetImageIt.index(), std::move(newTargetImage));

	auto typeLib = TypeLibraryForImage(header.installName);

	SaveToDSCView();

	auto h = SharedCache::LoadHeaderForAddress(vm, targetImage->headerLocation, installName);
	if (!h.has_value())
	{
		return false;
	}

	std::vector<const MemoryRegion*> regions;
	for (size_t idx : regionsToLoad) {
		regions.push_back(&newTargetImageRegions[idx]);
	}

	SharedCache::InitializeHeader(m_dscView, vm.get(), *h, regions);

	{
		for (size_t idx : regionsToLoad) {
			MemoryRegion newTargetSegment(newTargetImageRegions[idx]);
			newTargetSegment.headerInitialized = true;
			newTargetImageRegions.set(idx, std::move(newTargetSegment));
		}
		auto images = State().images;
		CacheImage newTargetImage(*targetImage);
		newTargetImage.regions = std::move(newTargetImageRegions).persistent();
		MutableState().images = images.set(targetImageIt.index(), std::move(newTargetImage));
	}

	if (!skipObjC)
	{
		bool processCFStrings;
		bool processObjCMetadata;
		GetObjCSettings(m_dscView, &processCFStrings, &processObjCMetadata);

		ProcessObjCSectionsForImageWithName(h->identifierPrefix, vm, std::make_shared<DSCObjC::DSCObjCProcessor>(m_dscView, this, false), processCFStrings, processObjCMetadata, m_logger);
	}

	m_dscView->AddAnalysisOption("linearsweep");
	m_dscView->UpdateAnalysis();

	m_dscView->CommitUndoActions(id);

	return true;
}

struct TransientSharedCacheMachOHeader
{
	uint64_t textBase = 0;
	uint64_t loadCommandOffset = 0;
	mach_header_64 ident {};
	std::string identifierPrefix;
	std::string installName;

	immer::vector_transient<std::pair<uint64_t, bool>> entryPoints;
	immer::vector_transient<uint64_t> m_entryPoints;  // list of entrypoints

	symtab_command symtab {};
	dysymtab_command dysymtab {};
	dyld_info_command dyldInfo {};
	routines_command_64 routines64 {};
	function_starts_command functionStarts {};
	immer::vector_transient<section_64> moduleInitSections;
	linkedit_data_command exportTrie {};
	linkedit_data_command chainedFixups {};

	uint64_t relocationBase = 0;
	// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
	immer::vector_transient<segment_command_64> segments;  // only three types of sections __TEXT, __DATA, __IMPORT
	segment_command_64 linkeditSegment = {};
	immer::vector_transient<section_64> sections;
	immer::vector_transient<std::string> sectionNames;

	immer::vector_transient<section_64> symbolStubSections;
	immer::vector_transient<section_64> symbolPointerSections;

	immer::vector_transient<std::string> dylibs;

	build_version_command buildVersion = {};
	immer::vector_transient<build_tool_version> buildToolVersions;

	std::string exportTriePath;

	bool linkeditPresent = false;
	bool dysymPresent = false;
	bool dyldInfoPresent = false;
	bool exportTriePresent = false;
	bool chainedFixupsPresent = false;
	bool routinesPresent = false;
	bool functionStartsPresent = false;
	bool relocatable = false;

	SharedCacheMachOHeader persistent() && {
		return SharedCacheMachOHeader {
			.textBase = textBase,
			.loadCommandOffset = loadCommandOffset,
			.ident = ident,
			.identifierPrefix = std::move(identifierPrefix),
			.installName = std::move(installName),
			.entryPoints = std::move(entryPoints).persistent(),
			.m_entryPoints = std::move(m_entryPoints).persistent(),
			.symtab = std::move(symtab),
			.dysymtab = std::move(dysymtab),
			.dyldInfo = std::move(dyldInfo),
			.routines64 = std::move(routines64),
			.functionStarts = std::move(functionStarts),
			.moduleInitSections = std::move(moduleInitSections).persistent(),
			.exportTrie = std::move(exportTrie),
			.chainedFixups = std::move(chainedFixups),
			.relocationBase = relocationBase,
			.segments = std::move(segments).persistent(),
			.linkeditSegment = std::move(linkeditSegment),
			.sections = std::move(sections).persistent(),
			.sectionNames = std::move(sectionNames).persistent(),
			.symbolStubSections = std::move(symbolStubSections).persistent(),
			.symbolPointerSections = std::move(symbolPointerSections).persistent(),
			.dylibs = std::move(dylibs).persistent(),
			.buildVersion = std::move(buildVersion),
			.buildToolVersions = std::move(buildToolVersions).persistent(),
			.exportTriePath = std::move(exportTriePath),
			.linkeditPresent = linkeditPresent,
			.dysymPresent = dysymPresent,
			.dyldInfoPresent = dyldInfoPresent,
			.exportTriePresent = exportTriePresent,
			.chainedFixupsPresent = chainedFixupsPresent,
			.routinesPresent = routinesPresent,
			.functionStartsPresent = functionStartsPresent,
			.relocatable = relocatable,
		};
	}
};


std::optional<SharedCacheMachOHeader> SharedCache::LoadHeaderForAddress(std::shared_ptr<VM> vm, uint64_t address, std::string_view installName)
{
	TransientSharedCacheMachOHeader header;

	header.textBase = address;
	header.installName = installName;
	header.identifierPrefix = base_name(installName);

	std::string errorMsg;
	// address is a Raw file offset
	VMReader reader(vm);
	reader.Seek(address);

	header.ident.magic = reader.Read32();

	BNEndianness endianness;
	if (header.ident.magic == MH_MAGIC || header.ident.magic == MH_MAGIC_64)
		endianness = LittleEndian;
	else if (header.ident.magic == MH_CIGAM || header.ident.magic == MH_CIGAM_64)
		endianness = BigEndian;
	else
	{
		return {};
	}

	reader.SetEndianness(endianness);
	header.ident.cputype = reader.Read32();
	header.ident.cpusubtype = reader.Read32();
	header.ident.filetype = reader.Read32();
	header.ident.ncmds = reader.Read32();
	header.ident.sizeofcmds = reader.Read32();
	header.ident.flags = reader.Read32();
	if ((header.ident.cputype & MachOABIMask) == MachOABI64)  // address size == 8
	{
		header.ident.reserved = reader.Read32();
	}
	header.loadCommandOffset = reader.GetOffset();

	bool first = true;
	// Parse segment commands
	try
	{
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			// BNLogInfo("of 0x%llx", reader.GetOffset());
			load_command load;
			segment_command_64 segment64;
			section_64 sect;
			memset(&sect, 0, sizeof(sect));
			size_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();
			size_t nextOffset = curOffset + load.cmdsize;
			if (load.cmdsize < sizeof(load_command))
				return {};

			switch (load.cmd)
			{
			case LC_MAIN:
			{
				uint64_t entryPoint = reader.Read64();
				header.entryPoints.push_back({entryPoint, true});
				(void)reader.Read64();	// Stack start
				break;
			}
			case LC_SEGMENT:  // map the 32bit version to 64 bits
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read32();
				segment64.vmsize = reader.Read32();
				segment64.fileoff = reader.Read32();
				segment64.filesize = reader.Read32();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read32();
					sect.size = reader.Read32();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}
					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_SEGMENT_64:
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read64();
				segment64.vmsize = reader.Read64();
				segment64.fileoff = reader.Read64();
				segment64.filesize = reader.Read64();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (strncmp(segment64.segname, "__LINKEDIT", 10) == 0)
				{
					header.linkeditSegment = segment64;
					header.linkeditPresent = true;
				}
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read64();
					sect.size = reader.Read64();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					sect.reserved3 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}

					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_ROUTINES:  // map the 32bit version to 64bits
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read32();
				header.routines64.init_module = reader.Read32();
				header.routines64.reserved1 = reader.Read32();
				header.routines64.reserved2 = reader.Read32();
				header.routines64.reserved3 = reader.Read32();
				header.routines64.reserved4 = reader.Read32();
				header.routines64.reserved5 = reader.Read32();
				header.routines64.reserved6 = reader.Read32();
				header.routinesPresent = true;
				break;
			case LC_ROUTINES_64:
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read64();
				header.routines64.init_module = reader.Read64();
				header.routines64.reserved1 = reader.Read64();
				header.routines64.reserved2 = reader.Read64();
				header.routines64.reserved3 = reader.Read64();
				header.routines64.reserved4 = reader.Read64();
				header.routines64.reserved5 = reader.Read64();
				header.routines64.reserved6 = reader.Read64();
				header.routinesPresent = true;
				break;
			case LC_FUNCTION_STARTS:
				header.functionStarts.funcoff = reader.Read32();
				header.functionStarts.funcsize = reader.Read32();
				header.functionStartsPresent = true;
				break;
			case LC_SYMTAB:
				header.symtab.symoff = reader.Read32();
				header.symtab.nsyms = reader.Read32();
				header.symtab.stroff = reader.Read32();
				header.symtab.strsize = reader.Read32();
				break;
			case LC_DYSYMTAB:
				header.dysymtab.ilocalsym = reader.Read32();
				header.dysymtab.nlocalsym = reader.Read32();
				header.dysymtab.iextdefsym = reader.Read32();
				header.dysymtab.nextdefsym = reader.Read32();
				header.dysymtab.iundefsym = reader.Read32();
				header.dysymtab.nundefsym = reader.Read32();
				header.dysymtab.tocoff = reader.Read32();
				header.dysymtab.ntoc = reader.Read32();
				header.dysymtab.modtaboff = reader.Read32();
				header.dysymtab.nmodtab = reader.Read32();
				header.dysymtab.extrefsymoff = reader.Read32();
				header.dysymtab.nextrefsyms = reader.Read32();
				header.dysymtab.indirectsymoff = reader.Read32();
				header.dysymtab.nindirectsyms = reader.Read32();
				header.dysymtab.extreloff = reader.Read32();
				header.dysymtab.nextrel = reader.Read32();
				header.dysymtab.locreloff = reader.Read32();
				header.dysymtab.nlocrel = reader.Read32();
				header.dysymPresent = true;
				break;
			case LC_DYLD_CHAINED_FIXUPS:
				header.chainedFixups.dataoff = reader.Read32();
				header.chainedFixups.datasize = reader.Read32();
				header.chainedFixupsPresent = true;
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				header.dyldInfo.rebase_off = reader.Read32();
				header.dyldInfo.rebase_size = reader.Read32();
				header.dyldInfo.bind_off = reader.Read32();
				header.dyldInfo.bind_size = reader.Read32();
				header.dyldInfo.weak_bind_off = reader.Read32();
				header.dyldInfo.weak_bind_size = reader.Read32();
				header.dyldInfo.lazy_bind_off = reader.Read32();
				header.dyldInfo.lazy_bind_size = reader.Read32();
				header.dyldInfo.export_off = reader.Read32();
				header.dyldInfo.export_size = reader.Read32();
				header.exportTrie.dataoff = header.dyldInfo.export_off;
				header.exportTrie.datasize = header.dyldInfo.export_size;
				header.exportTriePresent = true;
				header.dyldInfoPresent = true;
				break;
			case LC_DYLD_EXPORTS_TRIE:
				header.exportTrie.dataoff = reader.Read32();
				header.exportTrie.datasize = reader.Read32();
				header.exportTriePresent = true;
				break;
			case LC_THREAD:
			case LC_UNIXTHREAD:
				/*while (reader.GetOffset() < nextOffset)
				{

					thread_command thread;
					thread.flavor = reader.Read32();
					thread.count = reader.Read32();
					switch (m_archId)
					{
						case MachOx64:
							m_logger->LogDebug("x86_64 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex64, sizeof(thread.statex64));
							header.entryPoints.push_back({thread.statex64.rip, false});
							break;
						case MachOx86:
							m_logger->LogDebug("x86 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE32)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex86, sizeof(thread.statex86));
							header.entryPoints.push_back({thread.statex86.eip, false});
							break;
						case MachOArm:
							m_logger->LogDebug("Arm Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statearmv7, sizeof(thread.statearmv7));
							header.entryPoints.push_back({thread.statearmv7.r15, false});
							break;
						case MachOAarch64:
						case MachOAarch6432:
							m_logger->LogDebug("Aarch64 Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							reader.Read(&thread.stateaarch64, sizeof(thread.stateaarch64));
							header.entryPoints.push_back({thread.stateaarch64.pc, false});
							break;
						case MachOPPC:
							m_logger->LogDebug("PPC Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//Read individual entries for endian reasons
							header.entryPoints.push_back({reader.Read32(), false});
							(void)reader.Read32();
							(void)reader.Read32();
							//Read the rest of the structure
							(void)reader.Read(&thread.stateppc.r1, sizeof(thread.stateppc) - (3 * 4));
							break;
						case MachOPPC64:
							m_logger->LogDebug("PPC64 Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							header.entryPoints.push_back({reader.Read64(), false});
							(void)reader.Read64();
							(void)reader.Read64(); // Stack start
							(void)reader.Read(&thread.stateppc64.r1, sizeof(thread.stateppc64) - (3 * 8));
							break;
						default:
							m_logger->LogError("Unknown archid: %x", m_archId);
					}

				}*/
				break;
			case LC_LOAD_DYLIB:
			{
				uint32_t offset = reader.Read32();
				if (offset < nextOffset)
				{
					reader.Seek(curOffset + offset);
					std::string libname = reader.ReadCString(reader.GetOffset());
					header.dylibs.push_back(libname);
				}
			}
			break;
			case LC_BUILD_VERSION:
			{
				// m_logger->LogDebug("LC_BUILD_VERSION:");
				header.buildVersion.platform = reader.Read32();
				header.buildVersion.minos = reader.Read32();
				header.buildVersion.sdk = reader.Read32();
				header.buildVersion.ntools = reader.Read32();
				// m_logger->LogDebug("Platform: %s", BuildPlatformToString(header.buildVersion.platform).c_str());
				// m_logger->LogDebug("MinOS: %s", BuildToolVersionToString(header.buildVersion.minos).c_str());
				// m_logger->LogDebug("SDK: %s", BuildToolVersionToString(header.buildVersion.sdk).c_str());
				for (uint32_t j = 0; (i < header.buildVersion.ntools) && (j < 10); j++)
				{
					uint32_t tool = reader.Read32();
					uint32_t version = reader.Read32();
					header.buildToolVersions.push_back({tool, version});
					// m_logger->LogDebug("Build Tool: %s: %s", BuildToolToString(tool).c_str(),
					// BuildToolVersionToString(version).c_str());
				}
				break;
			}
			case LC_FILESET_ENTRY:
			{
				throw ReadException();
			}
			default:
				// m_logger->LogDebug("Unhandled command: %s : %" PRIu32 "\n", CommandToString(load.cmd).c_str(),
				// load.cmdsize);
				break;
			}
			if (reader.GetOffset() != nextOffset)
			{
				// m_logger->LogDebug("Didn't parse load command: %s fully %" PRIx64 ":%" PRIxPTR,
				// CommandToString(load.cmd).c_str(), reader.GetOffset(), nextOffset);
			}
			reader.Seek(nextOffset);
		}

		for (auto& section : header.sections)
		{
			char sectionName[17];
			memcpy(sectionName, section.sectname, sizeof(section.sectname));
			sectionName[16] = 0;
			if (header.identifierPrefix.empty())
				header.sectionNames.push_back(sectionName);
			else
				header.sectionNames.push_back(header.identifierPrefix + "::" + sectionName);
		}
	}
	catch (ReadException&)
	{
		return {};
	}

	return std::move(header).persistent();
}

void SharedCache::ProcessSymbols(std::shared_ptr<MMappedFileAccessor> file, const SharedCacheMachOHeader& header, uint64_t stringsOffset, size_t stringsSize, uint64_t nlistEntriesOffset, uint32_t nlistCount, uint32_t nlistStartIndex)
{
	WillMutateState();

	auto addressSize = m_dscView->GetAddressSize();
	auto strings = file->ReadBuffer(stringsOffset, stringsSize);

	immer::vector_transient<Ref<Symbol>> symbolInfos;
	for (uint64_t i = 0; i < nlistCount; i++)
	{
		uint64_t entryIndex = (nlistStartIndex + i);

		nlist_64 nlist;
		if (addressSize == 4)
		{
			// 32-bit DSC
			struct nlist nlist32;
			file->Read(&nlist, nlistEntriesOffset + (entryIndex * sizeof(nlist32)), sizeof(nlist32));
			nlist.n_strx = nlist32.n_strx;
			nlist.n_type = nlist32.n_type;
			nlist.n_sect = nlist32.n_sect;
			nlist.n_desc = nlist32.n_desc;
			nlist.n_value = nlist32.n_value;
		}
		else
		{
			// 64-bit DSC
			file->Read(&nlist, nlistEntriesOffset + (entryIndex * sizeof(nlist)), sizeof(nlist));
		}

		auto symbolAddress = nlist.n_value;
		if (((nlist.n_type & N_TYPE) == N_INDR) || symbolAddress == 0)
			continue;

		if (nlist.n_strx >= stringsSize)
		{
			m_logger->LogError("Symbol entry at index %llu has a string offset of %u which is outside the strings buffer of size %llu for file %s", entryIndex, nlist.n_strx, stringsSize, file->Path().c_str());
			continue;
		}
		
		std::string symbolName((char*)strings.GetDataAt(nlist.n_strx));
		if (symbolName == "<redacted>")
			continue;

		BNSymbolType symbolType = DataSymbol;
		uint32_t flags;
		if ((nlist.n_type & N_TYPE) == N_SECT && nlist.n_sect > 0 && (size_t)(nlist.n_sect - 1) < header.sections.size())
		{}
		else if ((nlist.n_type & N_TYPE) == N_ABS)
		{}
		else if ((nlist.n_type & N_EXT))
		{
			symbolType = ExternalSymbol;
		}
		else
			continue;

		for (auto s : header.sections)
		{
			if (s.addr <= symbolAddress && symbolAddress < s.addr + s.size)
			{
				flags = s.flags;
			}
		}

		if (symbolType != ExternalSymbol)
		{
			if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
				|| (flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
				symbolType = FunctionSymbol;
			else
				symbolType = DataSymbol;
		}
		if ((nlist.n_desc & N_ARM_THUMB_DEF) == N_ARM_THUMB_DEF)
			symbolAddress++;

		symbolInfos.push_back(new Symbol(symbolType, symbolName, symbolAddress, GlobalBinding));
	}
	MutableState().symbolInfos = State().symbolInfos.set(header.textBase, std::make_shared<immer::vector<Ref<Symbol>>>(std::move(std::move(symbolInfos).persistent())));
}

void SharedCache::ApplySymbol(Ref<BinaryView> view, Ref<TypeLibrary> typeLib, Ref<Symbol> symbol)
{
	Ref<Function> func = nullptr;
	auto symbolAddress = symbol->GetAddress();

	if (symbol->GetType() == FunctionSymbol)
	{
		Ref<Platform> targetPlatform = view->GetDefaultPlatform();
		func = view->AddFunctionForAnalysis(targetPlatform, symbolAddress);
	}
	if (typeLib)
	{
		auto type = m_dscView->ImportTypeLibraryObject(typeLib, {symbol->GetFullName()});
		if (type)
			view->DefineAutoSymbolAndVariableOrFunction(view->GetDefaultPlatform(), symbol, type);
		else
			view->DefineAutoSymbol(symbol);

		if (!func)
			func = view->GetAnalysisFunction(view->GetDefaultPlatform(), symbolAddress);
		if (func)
		{
			if (symbol->GetFullName() == "_objc_msgSend")
			{
				func->SetHasVariableArguments(false);
			}
			else if (symbol->GetFullName().find("_objc_retain_x") != std::string::npos || symbol->GetFullName().find("_objc_release_x") != std::string::npos)
			{
				auto x = symbol->GetFullName().rfind("x");
				auto num = symbol->GetFullName().substr(x + 1);

				std::vector<BinaryNinja::FunctionParameter> callTypeParams;
				auto cc = m_dscView->GetDefaultArchitecture()->GetCallingConventionByName("apple-arm64-objc-fast-arc-" + num);

				callTypeParams.push_back({"obj", m_dscView->GetTypeByName({ "id" }), true, BinaryNinja::Variable()});

				auto funcType = BinaryNinja::Type::FunctionType(m_dscView->GetTypeByName({ "id" }), cc, callTypeParams);
				func->SetUserType(funcType);
			}
		}
	}
	else
		view->DefineAutoSymbol(symbol);
}

void SharedCache::InitializeHeader(
	Ref<BinaryView> view, VM* vm, SharedCacheMachOHeader header, const std::vector<const MemoryRegion*> regionsToLoad)
{
	WillMutateState();

	Ref<Settings> settings = view->GetLoadSettings(VIEW_NAME);
	bool applyFunctionStarts = true;
	if (settings && settings->Contains("loader.dsc.processFunctionStarts"))
		applyFunctionStarts = settings->Get<bool>("loader.dsc.processFunctionStarts", view);

	for (size_t i = 0; i < header.sections.size(); i++)
	{
		bool skip = false;
		for (const auto& region : regionsToLoad)
		{
			if (header.sections[i].addr >= region->start && header.sections[i].addr < region->start + region->size)
			{
				if (region->headerInitialized)
				{
					skip = true;
				}
				break;
			}
		}
		if (!header.sections[i].size || skip)
			continue;

		std::string type;
		BNSectionSemantics semantics = DefaultSectionSemantics;
		switch (header.sections[i].flags & 0xff)
		{
		case S_REGULAR:
			if (header.sections[i].flags & S_ATTR_PURE_INSTRUCTIONS)
			{
				type = "PURE_CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else if (header.sections[i].flags & S_ATTR_SOME_INSTRUCTIONS)
			{
				type = "CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else
			{
				type = "REGULAR";
			}
			break;
		case S_ZEROFILL:
			type = "ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_CSTRING_LITERALS:
			type = "CSTRING_LITERALS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_4BYTE_LITERALS:
			type = "4BYTE_LITERALS";
			break;
		case S_8BYTE_LITERALS:
			type = "8BYTE_LITERALS";
			break;
		case S_LITERAL_POINTERS:
			type = "LITERAL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_NON_LAZY_SYMBOL_POINTERS:
			type = "NON_LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_LAZY_SYMBOL_POINTERS:
			type = "LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_SYMBOL_STUBS:
			type = "SYMBOL_STUBS";
			semantics = ReadOnlyCodeSectionSemantics;
			break;
		case S_MOD_INIT_FUNC_POINTERS:
			type = "MOD_INIT_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_MOD_TERM_FUNC_POINTERS:
			type = "MOD_TERM_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_COALESCED:
			type = "COALESCED";
			break;
		case S_GB_ZEROFILL:
			type = "GB_ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_INTERPOSING:
			type = "INTERPOSING";
			break;
		case S_16BYTE_LITERALS:
			type = "16BYTE_LITERALS";
			break;
		case S_DTRACE_DOF:
			type = "DTRACE_DOF";
			break;
		case S_LAZY_DYLIB_SYMBOL_POINTERS:
			type = "LAZY_DYLIB_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_THREAD_LOCAL_REGULAR:
			type = "THREAD_LOCAL_REGULAR";
			break;
		case S_THREAD_LOCAL_ZEROFILL:
			type = "THREAD_LOCAL_ZEROFILL";
			break;
		case S_THREAD_LOCAL_VARIABLES:
			type = "THREAD_LOCAL_VARIABLES";
			break;
		case S_THREAD_LOCAL_VARIABLE_POINTERS:
			type = "THREAD_LOCAL_VARIABLE_POINTERS";
			break;
		case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
			type = "THREAD_LOCAL_INIT_FUNCTION_POINTERS";
			break;
		default:
			type = "UNKNOWN";
			break;
		}
		if (i >= header.sectionNames.size())
			break;
		if (strncmp(header.sections[i].sectname, "__text", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyCodeSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__const", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__data", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadWriteDataSectionSemantics;
		if (strncmp(header.sections[i].segname, "__DATA_CONST", sizeof(header.sections[i].segname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;

		view->AddUserSection(header.sectionNames[i], header.sections[i].addr, header.sections[i].size, semantics,
			type, header.sections[i].align);
	}

	auto typeLib = view->GetTypeLibrary(header.installName);

	BinaryReader virtualReader(view);

	bool applyHeaderTypes = false;
	for (const auto& region : regionsToLoad)
	{
		if (header.textBase >= region->start && header.textBase < region->start + region->size)
		{
			if (!region->headerInitialized)
				applyHeaderTypes = true;
			break;
		}
	}
	if (applyHeaderTypes)
	{
		view->DefineDataVariable(header.textBase, Type::NamedType(view, QualifiedName("mach_header_64")));
		view->DefineAutoSymbol(
			new Symbol(DataSymbol, "__macho_header::" + header.identifierPrefix, header.textBase, LocalBinding));

		try
		{
			virtualReader.Seek(header.textBase + sizeof(mach_header_64));
			size_t sectionNum = 0;
			for (size_t i = 0; i < header.ident.ncmds; i++)
			{
				load_command load;
				uint64_t curOffset = virtualReader.GetOffset();
				load.cmd = virtualReader.Read32();
				load.cmdsize = virtualReader.Read32();
				uint64_t nextOffset = curOffset + load.cmdsize;
				switch (load.cmd)
				{
				case LC_SEGMENT:
				{
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("segment_command")));
					virtualReader.SeekRelative(5 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
						view->DefineDataVariable(
							virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section")));
						view->DefineUserSymbol(new Symbol(DataSymbol,
							"__macho_section::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
							virtualReader.GetOffset(), LocalBinding));
						virtualReader.SeekRelative((8 * 8) + 4);
					}
					break;
				}
				case LC_SEGMENT_64:
				{
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("segment_command_64")));
					virtualReader.SeekRelative(7 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
						view->DefineDataVariable(
							virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section_64")));
						view->DefineUserSymbol(new Symbol(DataSymbol,
							"__macho_section_64::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
							virtualReader.GetOffset(), LocalBinding));
						virtualReader.SeekRelative(10 * 8);
					}
					break;
				}
				case LC_SYMTAB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("symtab")));
					break;
				case LC_DYSYMTAB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dysymtab")));
					break;
				case LC_UUID:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("uuid")));
					break;
				case LC_ID_DYLIB:
				case LC_LOAD_DYLIB:
				case LC_REEXPORT_DYLIB:
				case LC_LOAD_WEAK_DYLIB:
				case LC_LOAD_UPWARD_DYLIB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dylib_command")));
					if (load.cmdsize - 24 <= 150)
						view->DefineDataVariable(
							curOffset + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
					break;
				case LC_CODE_SIGNATURE:
				case LC_SEGMENT_SPLIT_INFO:
				case LC_FUNCTION_STARTS:
				case LC_DATA_IN_CODE:
				case LC_DYLIB_CODE_SIGN_DRS:
				case LC_DYLD_EXPORTS_TRIE:
				case LC_DYLD_CHAINED_FIXUPS:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("linkedit_data")));
					break;
				case LC_ENCRYPTION_INFO:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("encryption_info")));
					break;
				case LC_VERSION_MIN_MACOSX:
				case LC_VERSION_MIN_IPHONEOS:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("version_min")));
					break;
				case LC_DYLD_INFO:
				case LC_DYLD_INFO_ONLY:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dyld_info")));
					break;
				default:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("load_command")));
					break;
				}

				view->DefineAutoSymbol(new Symbol(DataSymbol,
					"__macho_load_command::" + header.identifierPrefix + "_[" + std::to_string(i) + "]", curOffset,
					LocalBinding));
				virtualReader.Seek(nextOffset);
			}
		}
		catch (ReadException&)
		{
			LogError("Error when applying Mach-O header types at %" PRIx64, header.textBase);
		}
	}

	if (applyFunctionStarts && header.functionStartsPresent && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		auto funcStarts =
			vm->MappingAtAddress(header.linkeditSegment.vmaddr)
				.first.fileAccessor->lock()
				->ReadBuffer(header.functionStarts.funcoff, header.functionStarts.funcsize);
		size_t i = 0;
		uint64_t curfunc = header.textBase;
		uint64_t curOffset;

		while (i < header.functionStarts.funcsize)
		{
			curOffset = readLEB128(funcStarts, header.functionStarts.funcsize, i);
			bool addFunction = false;
			for (const auto& region : regionsToLoad)
			{
				if (curfunc >= region->start && curfunc < region->start + region->size)
				{
					if (!region->headerInitialized)
						addFunction = true;
				}
			}
			// LogError("0x%llx, 0x%llx", header.textBase, curOffset);
			if (curOffset == 0 || !addFunction)
				continue;
			curfunc += curOffset;
			uint64_t target = curfunc;
			Ref<Platform> targetPlatform = view->GetDefaultPlatform();
			view->AddFunctionForAnalysis(targetPlatform, target);
		}
	}

	if (header.symtab.symoff != 0 && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		// Mach-O View symtab processing with
		// a ton of stuff cut out so it can work

		auto reader = vm->MappingAtAddress(header.linkeditSegment.vmaddr).first.fileAccessor->lock();
		ProcessSymbols(reader, header, header.symtab.stroff, header.symtab.strsize, header.symtab.symoff, header.symtab.nsyms);
	}

	int64_t imageIndex = -1;
	for (auto& cacheImage : State().images)
	{
		if (cacheImage.headerLocation == header.textBase)
		{
			imageIndex = cacheImage.index;
			break;
		}
	}
	if (imageIndex > -1)
	{
		auto addressSize = m_dscView->GetAddressSize();
		for (auto backingCache : State().backingCaches)
		{
			if (backingCache.cacheType != BackingCacheTypeSymbols)
				continue;

			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), backingCache.path)->lock();
			
			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(__offsetof(dyld_cache_header, mappingOffset));
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected, using default size");
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			if (subCacheHeader.localSymbolsOffset != 0)
			{
				dyld_cache_local_symbols_info localSymbolsInfo;
				subCacheFile->Read(&localSymbolsInfo, subCacheHeader.localSymbolsOffset, sizeof(localSymbolsInfo));
				
				if (imageIndex < localSymbolsInfo.entriesCount)
				{
					dyld_cache_local_symbols_entry_64 localSymbolsEntry;
					if (addressSize == 4)
					{
						// 32-bit DSC
						dyld_cache_local_symbols_entry localSymbolsEntry32;
						subCacheFile->Read(&localSymbolsEntry32, subCacheHeader.localSymbolsOffset + localSymbolsInfo.entriesOffset + (imageIndex * sizeof(localSymbolsEntry32)), sizeof(localSymbolsEntry32));
						localSymbolsEntry.dylibOffset = localSymbolsEntry32.dylibOffset;
						localSymbolsEntry.nlistStartIndex = localSymbolsEntry32.nlistStartIndex;
						localSymbolsEntry.nlistCount = localSymbolsEntry32.nlistCount;
					}
					else
					{
						// 64-bit DSC
						subCacheFile->Read(&localSymbolsEntry, subCacheHeader.localSymbolsOffset + localSymbolsInfo.entriesOffset + (imageIndex * sizeof(localSymbolsEntry)), sizeof(localSymbolsEntry));
					}
					ProcessSymbols(subCacheFile, header, subCacheHeader.localSymbolsOffset + localSymbolsInfo.stringsOffset, localSymbolsInfo.stringsSize, subCacheHeader.localSymbolsOffset + localSymbolsInfo.nlistOffset, localSymbolsEntry.nlistCount, localSymbolsEntry.nlistStartIndex);
				}
				else
				{
					m_logger->LogDebug("No entry for image index %lld in symbols file %s with %u entries", imageIndex, subCacheFile->Path().c_str(), localSymbolsInfo.entriesCount);
				}
			}
		}
		m_logger->LogDebug("Loaded local symbols");
	}
	else
	{
		m_logger->LogError("Failed to identify the DSC image that contains the header at 0x%llx", header.textBase);
	}

	view->BeginBulkModifySymbols();
	for (auto symbol : *MutableState().symbolInfos[header.textBase])
	{
		ApplySymbol(view, typeLib, symbol);
	}

	if (header.exportTriePresent && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		auto symbols = GetExportListForHeader(header, [&]() {
			return vm->MappingAtAddress(header.linkeditSegment.vmaddr).first.fileAccessor->lock();
		});
		if (symbols)
		{
			for (const auto& [_, symbol] : *symbols)
			{
				ApplySymbol(view, typeLib, symbol);
			}
		}
	}
	view->EndBulkModifySymbols();

	// TODO: The caller is responsible for this for now.
	// for (auto region : regionsToLoad)
	// {
	// 	region->headerInitialized = true;
	// }
}

struct ExportNode
{
	std::string text;
	uint64_t offset;
	uint64_t flags;
};


void SharedCache::ReadExportNode(std::vector<Ref<Symbol>>& symbolList, SharedCacheMachOHeader& header, DataBuffer& buffer, uint64_t textBase,
	const std::string& currentText, size_t cursor, uint32_t endGuard)
{
	WillMutateState();

	if (cursor > endGuard)
		throw ReadException();

	uint64_t terminalSize = readValidULEB128(buffer, cursor);
	uint64_t childOffset = cursor + terminalSize;
	if (terminalSize != 0) {
		uint64_t imageOffset = 0;
		uint64_t flags = readValidULEB128(buffer, cursor);
		if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT))
		{
			imageOffset = readValidULEB128(buffer, cursor);
			auto symbolType = m_dscView->GetAnalysisFunctionsForAddress(textBase + imageOffset).size() ? FunctionSymbol : DataSymbol;
			{
				if (!currentText.empty() && textBase + imageOffset)
				{
					uint32_t flags;
					BNSymbolType type;
					for (auto s : header.sections)
					{
						if (s.addr < textBase + imageOffset)
						{
							if (s.addr + s.size > textBase + imageOffset)
							{
								flags = s.flags;
							}
						}
					}
					if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
						|| (flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
						type = FunctionSymbol;
					else
						type = DataSymbol;

#if EXPORT_TRIE_DEBUG
						// BNLogInfo("export: %s -> 0x%llx", n.text.c_str(), image.baseAddress + n.offset);
#endif
					auto sym = new Symbol(type, currentText, textBase + imageOffset);
					symbolList.push_back(sym);
				}
			}
		}
	}
	cursor = childOffset;
	uint8_t childCount = buffer[cursor];
	cursor++;
	if (cursor > endGuard)
		throw ReadException();
	for (uint8_t i = 0; i < childCount; ++i)
	{
		std::string childText;
		while (buffer[cursor] != 0 & cursor <= endGuard)
			childText.push_back(buffer[cursor++]);
		cursor++;
		if (cursor > endGuard)
			throw ReadException();
		auto next = readValidULEB128(buffer, cursor);
		if (next == 0)
			throw ReadException();
		ReadExportNode(symbolList, header, buffer, textBase, currentText + childText, next, endGuard);
	}
}


std::vector<Ref<Symbol>> SharedCache::ParseExportTrie(std::shared_ptr<MMappedFileAccessor> linkeditFile, SharedCacheMachOHeader header)
{
	std::vector<Ref<Symbol>> symbols;
	try
	{
		auto reader = linkeditFile;

		std::vector<ExportNode> nodes;

		DataBuffer buffer = reader->ReadBuffer(header.exportTrie.dataoff, header.exportTrie.datasize);
		ReadExportNode(symbols, header, buffer, header.textBase, "", 0, header.exportTrie.datasize);
	}
	catch (std::exception& e)
	{
		BNLogError("Failed to load Export Trie");
	}
	return symbols;
}


std::shared_ptr<immer::map<uint64_t, Ref<Symbol>>> SharedCache::GetExportListForHeader(SharedCacheMachOHeader header, std::function<std::shared_ptr<MMappedFileAccessor>()> provideLinkeditFile, bool* didModifyExportList)
{
	if (auto it = State().exportInfos.find(header.textBase))
	{
		if (didModifyExportList)
			*didModifyExportList = false;
		return *it;
	}
	else
	{
		std::shared_ptr<MMappedFileAccessor> linkeditFile = provideLinkeditFile();
		if (!linkeditFile)
		{
			if (didModifyExportList)
				*didModifyExportList = false;
			return nullptr;
		}

		auto exportList = SharedCache::ParseExportTrie(linkeditFile, header);
		auto exportMapping = immer::map_transient<uint64_t, Ref<Symbol>>();
		for (const auto& sym : exportList)
		{
			exportMapping.set(sym->GetAddress(), sym);
		}
		MutableState().exportInfos = State().exportInfos.set(header.textBase, std::make_shared<immer::map<uint64_t, Ref<Symbol>>>(std::move(std::move(exportMapping).persistent())));
		if (didModifyExportList)
			*didModifyExportList = true;
		return MutableState().exportInfos[header.textBase];
	}
}


std::vector<std::string> SharedCache::GetAvailableImages()
{
	std::vector<std::string> installNames;
	for (const auto& header : State().headers)
	{
		installNames.push_back(header.second.installName);
	}
	return installNames;
}


std::vector<std::pair<std::string, Ref<Symbol>>> SharedCache::LoadAllSymbolsAndWait()
{
	WillMutateState();

	std::unique_lock<std::mutex> initialLoadBlock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);

	bool doSave = false;
	std::vector<std::pair<std::string, Ref<Symbol>>> symbols;
	for (const auto& img : State().images)
	{
		auto header = HeaderForAddress(img.headerLocation);
		auto exportList = GetExportListForHeader(*header, [&]() {
			try {
				auto mapping = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), header->exportTriePath)->lock();
				return mapping;
			}
			catch (...)
			{
				m_logger->LogWarn("Serious Error: Failed to open export trie %s for %s", header->exportTriePath.c_str(), header->installName.c_str());
				return std::shared_ptr<MMappedFileAccessor>(nullptr);
			}
		}, &doSave);
		if (!exportList)
			continue;
		for (const auto& [_, symbol] : *exportList)
		{
			symbols.push_back({img.installName, symbol});
		}
	}

	// Only save to DSC view if a header was actually loaded
	if (doSave)
		SaveToDSCView();

	return symbols;
}


std::string SharedCache::SerializedImageHeaderForAddress(uint64_t address)
{
	auto header = HeaderForAddress(address);
	if (header)
	{
		return header->AsString();
	}
	return "";
}


std::string SharedCache::SerializedImageHeaderForName(std::string name)
{
	if (auto it = State().imageStarts.find(name))
	{
		if (auto header = HeaderForAddress(*it))
		{
			return header->AsString();
		}
	}
	return "";
}

Ref<TypeLibrary> SharedCache::TypeLibraryForImage(const std::string& installName) {
	std::lock_guard lock(m_viewSpecificState->typeLibraryMutex);
	if (auto it = m_viewSpecificState->typeLibraries.find(installName); it != m_viewSpecificState->typeLibraries.end()) {
		return it->second;
	}

	auto typeLib = m_dscView->GetTypeLibrary(installName);
	if (!typeLib) {
		auto typeLibs = m_dscView->GetDefaultPlatform()->GetTypeLibrariesByName(installName);
		if (!typeLibs.empty()) {
			typeLib = typeLibs[0];
			m_dscView->AddTypeLibrary(typeLib);
		}
	}

	m_viewSpecificState->typeLibraries[installName] = typeLib;
	return typeLib;
}

void SharedCache::FindSymbolAtAddrAndApplyToAddr(
	uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis)
{
	WillMutateState();

	std::string prefix = "";
	if (symbolLocation != targetLocation)
		prefix = "j_";
	if (auto preexistingSymbol = m_dscView->GetSymbolByAddress(targetLocation))
	{
		if (preexistingSymbol->GetFullName().find("j_") != std::string::npos)
			return;
	}
	if (auto loadedSymbol = m_dscView->GetSymbolByAddress(symbolLocation))
	{
		auto id = m_dscView->BeginUndoActions();
		if (m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation))
			m_dscView->DefineUserSymbol(new Symbol(FunctionSymbol, prefix + loadedSymbol->GetFullName(), targetLocation));
		else
			m_dscView->DefineUserSymbol(new Symbol(loadedSymbol->GetType(), prefix + loadedSymbol->GetFullName(), targetLocation));
		m_dscView->ForgetUndoActions(id);
	}
	auto header = HeaderForAddress(symbolLocation);
	if (header)
	{
		auto typeLib = TypeLibraryForImage(header->installName);
		auto exportList = GetExportListForHeader(*header, [&]() {
			try {
				return MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), header->exportTriePath)->lock();
			}
			catch (...)
			{
				m_logger->LogWarn("Serious Error: Failed to open export trie %s for %s", header->exportTriePath.c_str(), header->installName.c_str());
				return std::shared_ptr<MMappedFileAccessor>(nullptr);
			}
		});

		if (exportList)
		{
			if (auto it = exportList->find(symbolLocation))
			{
				auto symbol = *it;

				auto func = m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation);
				
				auto id = m_dscView->BeginUndoActions();
				m_dscView->DefineUserSymbol(
					new Symbol(func ? FunctionSymbol : symbol->GetType(), prefix + symbol->GetFullName(), targetLocation));

				if (typeLib)
				{
					if (auto type = m_dscView->ImportTypeLibraryObject(typeLib, {symbol->GetFullName()}))
					{
						if (func)
							func->SetUserType(type);
						else
							m_dscView->DefineUserDataVariable(targetLocation, type);
					}
				}
				m_dscView->ForgetUndoActions(id);

				if (triggerReanalysis)
				{
					if (func)
						func->Reanalyze();
				}
			}
		}
	}
}


bool SharedCache::SaveToDSCView()
{
	if (m_dscView)
	{
		auto data = AsMetadata();
		m_dscView->StoreMetadata(SharedCacheMetadataTag, data);
		m_dscView->GetParentView()->GetParentView()->StoreMetadata(SharedCacheMetadataTag, data);

		// By moving our state the to cache we can avoid creating a copy in the case
		// that no further mutations are made to `this`. If we're not done being mutated,
		// the data will be copied on the first mutation.
		auto cachedState = std::make_shared<struct State>(std::move(*m_state));
		m_state = cachedState;
		m_stateIsShared = true;

		m_viewSpecificState->SetCachedState(std::move(cachedState));
		m_metadataValid = true;

		return true;
	}
	return false;
}

immer::vector<MemoryRegion> SharedCache::GetMappedRegions() const
{
	std::unique_lock<std::mutex> lock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);
	return State().regionsMappedIntoMemory;
}

bool SharedCache::IsMemoryMapped(uint64_t address)
{
	return m_dscView->IsValidOffset(address);
}

extern "C"
{
	BNSharedCache* BNGetSharedCache(BNBinaryView* data)
	{
		if (!data)
			return nullptr;

		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		if (auto cache = SharedCache::GetFromDSCView(view))
		{
			cache->AddAPIRef();
			return cache->GetAPIObject();
		}

		return nullptr;
	}

	BNSharedCache* BNNewSharedCacheReference(BNSharedCache* cache)
	{
		if (!cache->object)
			return nullptr;

		cache->object->AddAPIRef();
		return cache;
	}

	void BNFreeSharedCacheReference(BNSharedCache* cache)
	{
		if (!cache->object)
			return;

		cache->object->ReleaseAPIRef();
	}

	bool BNDSCViewLoadImageWithInstallName(BNSharedCache* cache, char* name, bool skipObjC)
	{
		std::string imageName = std::string(name);
		// FIXME !!!!!!!! BNFreeString(name);

		if (cache->object)
			return cache->object->LoadImageWithInstallName(imageName, skipObjC);

		return false;
	}

	bool BNDSCViewLoadSectionAtAddress(BNSharedCache* cache, uint64_t addr)
	{
		if (cache->object)
		{
			return cache->object->LoadSectionAtAddress(addr);
		}

		return false;
	}

	bool BNDSCViewLoadImageContainingAddress(BNSharedCache* cache, uint64_t address, bool skipObjC)
	{
		if (cache->object)
		{
			return cache->object->LoadImageContainingAddress(address, skipObjC);
		}

		return false;
	}

	void BNDSCViewProcessObjCSectionsForImageWithInstallName(BNSharedCache* cache, char* name, bool deallocName)
	{
		std::string imageName = std::string(name);
		if (deallocName)
			BNFreeString(name);

		if (cache->object)
			cache->object->ProcessObjCSectionsForImageWithInstallName(imageName);
	}

	void BNDSCViewProcessAllObjCSections(BNSharedCache* cache)
	{
		if (cache->object)
			cache->object->ProcessAllObjCSections();
	}

	char** BNDSCViewGetInstallNames(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->GetAvailableImages();
			*count = value.size();

			std::vector<const char*> cstrings;
			for (size_t i = 0; i < value.size(); i++)
			{
				cstrings.push_back(value[i].c_str());
			}
			return BNAllocStringList(cstrings.data(), cstrings.size());
		}
		*count = 0;
		return nullptr;
	}

	BNDSCSymbolRep* BNDSCViewLoadAllSymbolsAndWait(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->LoadAllSymbolsAndWait();
			*count = value.size();

			BNDSCSymbolRep* symbols = (BNDSCSymbolRep*)malloc(sizeof(BNDSCSymbolRep) * value.size());
			for (size_t i = 0; i < value.size(); i++)
			{
				symbols[i].address = value[i].second->GetAddress();
				symbols[i].name = BNAllocString(value[i].second->GetRawName().c_str());
				symbols[i].image = BNAllocString(value[i].first.c_str());
			}
			return symbols;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeSymbols(BNDSCSymbolRep* symbols, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(symbols[i].name);
			BNFreeString(symbols[i].image);
		}
		delete symbols;
	}

	char* BNDSCViewGetNameForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->NameForAddress(address).c_str());
		}

		return nullptr;
	}

	char* BNDSCViewGetImageNameForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->ImageNameForAddress(address).c_str());
		}

		return nullptr;
	}

	uint64_t BNDSCViewLoadedImageCount(BNSharedCache* cache)
	{
		// FIXME?
		return 0;
	}

	BNDSCViewState BNDSCViewGetState(BNSharedCache* cache)
	{
		if (cache->object)
		{
			return (BNDSCViewState)cache->object->ViewState();
		}

		return BNDSCViewState::Unloaded;
	}


	BNDSCMappedMemoryRegion* BNDSCViewGetLoadedRegions(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto regions = cache->object->GetMappedRegions();
			*count = regions.size();
			BNDSCMappedMemoryRegion* mappedRegions = (BNDSCMappedMemoryRegion*)malloc(sizeof(BNDSCMappedMemoryRegion) * regions.size());
			for (size_t i = 0; i < regions.size(); i++)
			{
				mappedRegions[i].vmAddress = regions[i].start;
				mappedRegions[i].size = regions[i].size;
				mappedRegions[i].name = BNAllocString(regions[i].prettyName.c_str());
			}
			return mappedRegions;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeLoadedRegions(BNDSCMappedMemoryRegion* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(images[i].name);
		}
		delete images;
	}


	BNDSCBackingCache* BNDSCViewGetBackingCaches(BNSharedCache* cache, size_t* count)
	{
		BNDSCBackingCache* caches = nullptr;

		if (cache->object)
		{
			auto viewCaches = cache->object->BackingCaches();
			*count = viewCaches.size();
			caches = (BNDSCBackingCache*)malloc(sizeof(BNDSCBackingCache) * viewCaches.size());
			for (size_t i = 0; i < viewCaches.size(); i++)
			{
				caches[i].path = BNAllocString(viewCaches[i].path.c_str());
				caches[i].cacheType = viewCaches[i].cacheType;

				BNDSCBackingCacheMapping* mappings;
				mappings = (BNDSCBackingCacheMapping*)malloc(sizeof(BNDSCBackingCacheMapping) * viewCaches[i].mappings.size());

				size_t j = 0;
				for (const auto& mapping : viewCaches[i].mappings)
				{
					mappings[j].vmAddress = mapping.address;
					mappings[j].size = mapping.size;
					mappings[j].fileOffset = mapping.fileOffset;
					j++;
				}
				caches[i].mappings = mappings;
				caches[i].mappingCount = viewCaches[i].mappings.size();
			}
		}

		return caches;
	}

	void BNDSCViewFreeBackingCaches(BNDSCBackingCache* caches, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			delete[] caches[i].mappings;
			BNFreeString(caches[i].path);
		}
		delete[] caches;
	}

	void BNDSCFindSymbolAtAddressAndApplyToAddress(BNSharedCache* cache, uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis)
	{
		if (cache->object)
		{
			cache->object->FindSymbolAtAddrAndApplyToAddr(symbolLocation, targetLocation, triggerReanalysis);
		}
	}

	BNDSCImage* BNDSCViewGetAllImages(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto vm = cache->object->GetVMMap(true);
			auto viewImageHeaders = cache->object->AllImageHeaders();
			*count = viewImageHeaders.size();
			BNDSCImage* images = (BNDSCImage*)malloc(sizeof(BNDSCImage) * viewImageHeaders.size());
			size_t i = 0;
			for (const auto& [baseAddress, header] : viewImageHeaders)
			{
				images[i].name = BNAllocString(header.installName.c_str());
				images[i].headerAddress = baseAddress;

				std::vector<const char*> dependencies;
				for (size_t j = 0; j < header.dylibs.size(); j++)
				{
					dependencies.push_back(header.dylibs[j].c_str());
				}
				images[i].dependenciesCount = dependencies.size();
				images[i].dependencies = BNAllocStringList(dependencies.data(), dependencies.size());

				const auto mappingCount = header.sections.size();
				images[i].mappingCount = mappingCount;
				images[i].mappings = (BNDSCImageMemoryMapping*)malloc(sizeof(BNDSCImageMemoryMapping) * mappingCount);
				for (size_t j = 0; j < mappingCount; j++)
				{
					const auto sectionStart = header.sections[j].addr;
					images[i].mappings[j].rawViewOffset = header.sections[j].offset;
					images[i].mappings[j].vmAddress = sectionStart;
					images[i].mappings[j].size = header.sections[j].size;
					images[i].mappings[j].name = BNAllocString(header.sectionNames[j].c_str());
					images[i].mappings[j].filePath = BNAllocString(vm->MappingAtAddress(sectionStart).first.filePath.c_str());
					images[i].mappings[j].loaded = cache->object->IsMemoryMapped(sectionStart);
				}
				i++;
			}
			return images;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeAllImages(BNDSCImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeStringList(images[i].dependencies, images[i].dependenciesCount);
			for (size_t j = 0; j < images[i].mappingCount; j++)
			{
				BNFreeString(images[i].mappings[j].name);
				BNFreeString(images[i].mappings[j].filePath);
			}
			delete[] images[i].mappings;
			BNFreeString(images[i].name);
		}
		delete[] images;
	}

	char* BNDSCViewGetImageHeaderForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForAddress(address);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	char* BNDSCViewGetImageHeaderForName(BNSharedCache* cache, char* name)
	{
		std::string imageName = std::string(name);
		BNFreeString(name);
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForName(imageName);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	BNDSCMemoryUsageInfo BNDSCViewGetMemoryUsageInfo()
	{
		BNDSCMemoryUsageInfo info;
		info.mmapRefs = mmapCount.load();
		info.sharedCacheRefs = sharedCacheReferences.load();
		return info;
	}

	BNDSCViewLoadProgress BNDSCViewGetLoadProgress(uint64_t sessionID)
	{
		if (auto viewSpecificState = ViewSpecificStateForId(sessionID, false)) {
			return viewSpecificState->progress;
		}

		return LoadProgressNotStarted;
	}

	uint64_t BNDSCViewFastGetBackingCacheCount(BNBinaryView* data)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		return SharedCache::FastGetBackingCacheCount(view);
	}
}

[[maybe_unused]] DSCViewType* g_dscViewType;
[[maybe_unused]] DSCRawViewType* g_dscRawViewType;

void InitDSCViewType()
{
	MMappedFileAccessor::InitialVMSetup();
	std::atexit(VMShutdown);

	static DSCRawViewType rawType;
	BinaryViewType::Register(&rawType);
	static DSCViewType type;
	BinaryViewType::Register(&type);
	g_dscViewType = &type;
	g_dscRawViewType = &rawType;
}

namespace SharedCacheCore {

void Serialize(SerializationContext& context, const dyld_cache_mapping_info& value)
{
	context.writer.StartArray();
	Serialize(context, value.address);
	Serialize(context, value.size);
	Serialize(context, value.fileOffset);
	Serialize(context, value.maxProt);
	Serialize(context, value.initProt);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, immer::vector<dyld_cache_mapping_info>& b)
{

	auto bArr = context.doc[name.data()].GetArray();
	auto transient = b.transient();
	for (auto& s : bArr)
	{
		dyld_cache_mapping_info mapping;
		auto s2 = s.GetArray();
		mapping.address = s2[0].GetUint64();
		mapping.size = s2[1].GetUint64();
		mapping.fileOffset = s2[2].GetUint64();
		mapping.maxProt = s2[3].GetUint();
		mapping.initProt = s2[4].GetUint();
		transient.push_back(mapping);
	}
	b = std::move(transient).persistent();
}

void SharedCache::Store(SerializationContext& context) const
{
	Serialize(context, "metadataVersion", METADATA_VERSION);

    Serialize(context, "m_viewState", State().viewState);
    Serialize(context, "m_cacheFormat", State().cacheFormat);
    Serialize(context, "m_imageStarts", State().imageStarts);
    Serialize(context, "m_baseFilePath", State().baseFilePath);

	Serialize(context, "headers");
	context.writer.StartArray();
	for (auto& [k, v] : State().headers)
	{
		context.writer.StartObject();
		v.Store(context);
		context.writer.EndObject();
	}
	context.writer.EndArray();

	Serialize(context, "exportInfos");
	context.writer.StartArray();
	for (const auto& [headerLocation, symbolMap] : State().exportInfos)
	{
		context.writer.StartObject();
		Serialize(context, "key", headerLocation);
		Serialize(context, "value");
		context.writer.StartArray();
		for (const auto& [symbolAddress, symbol] : *symbolMap)
		{
			context.writer.StartObject();
			Serialize(context, "key", symbolAddress);
			Serialize(context, "val1", symbol->GetType());
			Serialize(context, "val2", symbol->GetRawName());
			context.writer.EndObject();
		}
		context.writer.EndArray();
		context.writer.EndObject();
	}
	context.writer.EndArray();

	Serialize(context, "symbolInfos");
	context.writer.StartArray();
	for (const auto& [headerLocation, symbols] : State().symbolInfos)
	{
	        context.writer.StartObject();
	        Serialize(context, "key", headerLocation);
	        Serialize(context, "value");
	        context.writer.StartArray();
	        for (const auto& symbol : *symbols)
	        {
	                context.writer.StartObject();
	                Serialize(context, "key", symbol->GetAddress());
	                Serialize(context, "val1", symbol->GetType());
	                Serialize(context, "val2", symbol->GetRawName());
	                context.writer.EndObject();
	        }
	        context.writer.EndArray();
	        context.writer.EndObject();
	}
	context.writer.EndArray();

	Serialize(context, "backingCaches", State().backingCaches);
	Serialize(context, "stubIslands", State().stubIslandRegions);
	Serialize(context, "images", State().images);
	Serialize(context, "regionsMappedIntoMemory", State().regionsMappedIntoMemory);
	Serialize(context, "dyldDataSections", State().dyldDataRegions);
	Serialize(context, "nonImageRegions", State().nonImageRegions);
}

void SharedCache::Load(DeserializationContext& context)
{
	if (context.doc.HasMember("metadataVersion"))
	{
		if (context.doc["metadataVersion"].GetUint() != METADATA_VERSION)
		{
			m_logger->LogError("Shared Cache metadata version mismatch");
			return;
		}
	}
	else
	{
		m_logger->LogError("Shared Cache metadata version missing");
		return;
	}

	m_stateIsShared = false;
	m_state = std::make_shared<struct SharedCache::State>();

	MutableState().viewState = static_cast<DSCViewState>(context.load<uint8_t>("m_viewState"));
	MutableState().cacheFormat = static_cast<SharedCacheFormat>(context.load<uint8_t>("m_cacheFormat"));

	auto headers = State().headers.transient();
	for (auto& startAndHeader : context.doc["headers"].GetArray())
	{
		SharedCacheMachOHeader header;
		header.LoadFromValue(startAndHeader);
		headers.set(header.textBase, std::move(header));
	}
	MutableState().headers = std::move(headers).persistent();

	Deserialize(context, "m_imageStarts", MutableState().imageStarts);
	Deserialize(context, "m_baseFilePath", MutableState().baseFilePath);

	auto exportInfos = State().exportInfos.transient();
	for (const auto& obj1 : context.doc["exportInfos"].GetArray())
	{
		immer::map_transient<uint64_t, Ref<Symbol>> innerMap;
		for (const auto& obj2 : obj1["value"].GetArray())
		{
			innerMap.set(obj2["key"].GetUint64(), new Symbol((BNSymbolType)obj2["val1"].GetUint64(), obj2["val2"].GetString(), obj2["key"].GetUint64()));
		}
		exportInfos.set(obj1["key"].GetUint64(), std::make_shared<immer::map<uint64_t, Ref<Symbol>>>(std::move(std::move(innerMap).persistent())));
	}
	MutableState().exportInfos = std::move(exportInfos).persistent();

	auto symbolInfos = State().symbolInfos.transient();
	for (auto& symbolInfo : context.doc["symbolInfos"].GetArray())
	{
		immer::vector_transient<Ref<Symbol>> symbolsVec;
		for (auto& symbol : symbolInfo["value"].GetArray())
		{
			symbolsVec.push_back(new Symbol(
				(BNSymbolType)symbol["val1"].GetUint(), 
				symbol["val2"].GetString(), 
				symbol["key"].GetUint64()));
		}
		symbolInfos.set(symbolInfo["key"].GetUint64(), std::make_shared<immer::vector<Ref<Symbol>>>(std::move(std::move(symbolsVec).persistent())));
	}
	MutableState().symbolInfos = std::move(symbolInfos).persistent();

	auto backingCaches = State().backingCaches.transient();
	for (auto& bcV : context.doc["backingCaches"].GetArray())
	{
		BackingCache bc;
		bc.LoadFromValue(bcV);
		backingCaches.push_back(std::move(bc));
	}
	MutableState().backingCaches = std::move(backingCaches).persistent();

	auto images = State().images.transient();
	for (auto& imgV : context.doc["images"].GetArray())
	{
		CacheImage img;
		img.LoadFromValue(imgV);
		images.push_back(std::move(img));
	}
	MutableState().images = std::move(images).persistent();

	auto regionsMappedIntoMemory = State().regionsMappedIntoMemory.transient();
	for (auto& rV : context.doc["regionsMappedIntoMemory"].GetArray())
	{
		MemoryRegion r;
		r.LoadFromValue(rV);
		regionsMappedIntoMemory.push_back(std::move(r));
	}
	MutableState().regionsMappedIntoMemory = std::move(regionsMappedIntoMemory).persistent();

	auto stubIslandRegions = State().stubIslandRegions.transient();
	for (auto& siV : context.doc["stubIslands"].GetArray())
	{
		MemoryRegion si;
		si.LoadFromValue(siV);
		stubIslandRegions.push_back(std::move(si));
	}
	MutableState().stubIslandRegions = std::move(stubIslandRegions).persistent();

	auto dyldDataRegions = State().dyldDataRegions.transient();
	for (auto& siV : context.doc["dyldDataSections"].GetArray())
	{
		MemoryRegion si;
		si.LoadFromValue(siV);
		dyldDataRegions.push_back(std::move(si));
	}
	MutableState().dyldDataRegions = std::move(dyldDataRegions).persistent();

	auto nonImageRegions = State().nonImageRegions.transient();
	for (auto& siV : context.doc["nonImageRegions"].GetArray())
	{
		MemoryRegion si;
		si.LoadFromValue(siV);
		nonImageRegions.push_back(std::move(si));
	}
	MutableState().nonImageRegions = std::move(nonImageRegions).persistent();

	m_metadataValid = true;
}

__attribute__((always_inline)) void SharedCache::AssertMutable() const
{
	if (m_stateIsShared)
	{
		abort();
	}
}

void SharedCache::WillMutateState()
{
	if (!m_state)
	{
		m_state = std::make_shared<struct State>();
	}
	else if (m_stateIsShared)
	{
		m_state = std::make_shared<struct State>(*m_state);
	}
	m_stateIsShared = false;
}


const immer::vector<BackingCache>& SharedCache::BackingCaches() const
{
	return State().backingCaches;
}

DSCViewState SharedCache::ViewState() const
{
	return State().viewState;
}

const immer::map<std::string, uint64_t>& SharedCache::AllImageStarts() const
{
	return State().imageStarts;
}

const immer::map<uint64_t, SharedCacheMachOHeader>& SharedCache::AllImageHeaders() const
{
	return State().headers;
}

void BackingCache::Store(SerializationContext& context) const
{
	MSS(path);
	MSS_CAST(cacheType, uint32_t);
	MSS(mappings);
}
void BackingCache::Load(DeserializationContext& context)
{
	MSL(path);
	MSL_CAST(cacheType, uint32_t, BNBackingCacheType);
	MSL(mappings);
}

size_t SharedCache::GetBaseAddress() const {
	if (State().backingCaches.empty()) {
		return 0;
	}

	const BackingCache& primaryCache = State().backingCaches[0];
	if (primaryCache.cacheType != BackingCacheTypePrimary) {
		abort();
		return 0;
	}

	if (primaryCache.mappings.empty()) {
		return 0;
	}

	return primaryCache.mappings[0].address;
}

// Intentionally takes a copy to avoid modifying the cursor position in the original reader.
std::optional<ObjCOptimizationHeader> SharedCache::GetObjCOptimizationHeader(VMReader reader) const {
	if (!State().objcOptimizationDataRange) {
		return {};
	}

	ObjCOptimizationHeader header{};
	// Ignoring `objcOptsSize` in favor of `sizeof(ObjCOptimizationHeader)` matches dyld's behavior.
	reader.Read(&header, GetBaseAddress() + State().objcOptimizationDataRange->first, sizeof(ObjCOptimizationHeader));

	return header;
}

size_t SharedCache::GetObjCRelativeMethodBaseAddress(const VMReader& reader) const {
	if (auto header = GetObjCOptimizationHeader(reader); header.has_value()) {
		return GetBaseAddress() + header->relativeMethodSelectorBaseAddressOffset;
	}
	return 0;
}

}  // namespace SharedCacheCore