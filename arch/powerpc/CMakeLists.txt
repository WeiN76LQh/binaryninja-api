cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(arch_ppc)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	arch_ppc.cpp
	assembler.cpp
	disassembler.cpp
	il.cpp
	util.cpp
	*.h
)

if(DEMO)
	add_library(arch_ppc STATIC ${SOURCES})
else()
	add_library(arch_ppc SHARED ${SOURCES})
endif()

option(CAPSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" OFF)
option(CAPSTONE_BUILD_SHARED "Build shared library" OFF)
option(CAPSTONE_BUILD_TESTS "Build tests" OFF)
add_subdirectory(capstone)

target_link_libraries(arch_ppc binaryninjaapi capstone)

if(UNIX AND NOT APPLE)
	target_link_options(arch_ppc PRIVATE "LINKER:--exclude-libs,ALL")
endif()

set_target_properties(arch_ppc PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

target_include_directories(arch_ppc PRIVATE ${PROJECT_SOURCE_DIR}/capstone/include)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_ppc)
	set_target_properties(arch_ppc PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()

if (DEFINED FORCE_TEST)
	set(TEST_INLCUDE_LIST )
	set(TEST_LINK_DIRECTORIES )
	set(TEST_LINK_LIBRARIES capstone)
	
	if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		add_executable(test_disasm test_disasm.cpp disassembler.cpp)
		add_executable(test_asm test_asm.cpp assembler.cpp)

		target_compile_definitions(test_disasm PRIVATE FORCE_TEST=1)

		set_target_properties(test_disasm test_asm PROPERTIES
			CXX_STANDARD 17
			CXX_VISIBILITY_PRESET hidden
			CXX_STANDARD_REQUIRED ON
			VISIBILITY_INLINES_HIDDEN ON
			POSITION_INDEPENDENT_CODE ON)
		
		target_include_directories(test_disasm PRIVATE ${TEST_INCLUDE_LIST})
		target_link_directories(test_disasm PRIVATE ${TEST_LINK_DIRECTORIES})
		target_link_libraries(test_disasm PRIVATE ${TEST_LINK_LIBRARIES})

		target_include_directories(test_asm PRIVATE ${TEST_INCLUDE_LIST})
		target_link_directories(test_asm PRIVATE ${TEST_LINK_DIRECTORIES})
		target_link_libraries(test_asm PRIVATE ${TEST_LINK_LIBRARIES})
	endif()
endif()
