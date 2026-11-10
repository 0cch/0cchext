cmake_minimum_required(VERSION 3.25)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" _0CCHEXT_VERSION_FILE)
string(STRIP "${_0CCHEXT_VERSION_FILE}" _0CCHEXT_DEFAULT_VERSION)
if(NOT _0CCHEXT_DEFAULT_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "VERSION must contain four numeric components: ${_0CCHEXT_DEFAULT_VERSION}")
endif()

set(0CCHEXT_VERSION "${_0CCHEXT_DEFAULT_VERSION}" CACHE STRING "0cchext version in dotted form")

project(0cchext VERSION ${0CCHEXT_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(0CCHEXT_BUILD_LUADBG "Build the luadbg extension" ON)
option(0CCHEXT_WARNINGS_AS_ERRORS "Treat warnings in project code as errors" OFF)

include(cmake/WinDbg.cmake)
include(cmake/Xed.cmake)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

foreach(_config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_config} "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_config} "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_config} "${CMAKE_BINARY_DIR}/lib")
    set(CMAKE_PDB_OUTPUT_DIRECTORY_${_config} "${CMAKE_BINARY_DIR}/bin")
endforeach()

function(cchext_configure_project_target target_name)
    target_compile_features(${target_name} PRIVATE cxx_std_17)
    target_compile_definitions(${target_name} PRIVATE UNICODE _UNICODE NOMINMAX)
    target_compile_options(${target_name} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /guard:cf /wd4702 /wd5040)
    if(0CCHEXT_WARNINGS_AS_ERRORS)
        target_compile_options(${target_name} PRIVATE /WX)
    endif()
    target_link_options(${target_name} PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
    if(WINDBG_ARCH STREQUAL "x64")
        target_link_options(${target_name} PRIVATE /HIGHENTROPYVA)
    endif()
    set_target_properties(${target_name} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endfunction()

add_subdirectory(0cchext/xed/src)
add_subdirectory(0cchext)

if(0CCHEXT_BUILD_LUADBG)
    add_subdirectory(extensions/luadbg)
endif()

include(CTest)
add_subdirectory(tests)

install(TARGETS 0cchext RUNTIME DESTINATION "bin/${WINDBG_ARCH}")
if(TARGET luadbg)
    install(TARGETS luadbg RUNTIME DESTINATION "bin/${WINDBG_ARCH}")
endif()
install(FILES LICENSE README.md DESTINATION ".")
