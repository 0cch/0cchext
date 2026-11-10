include(FetchContent)

option(0CCHEXT_USE_XED_2026 "Build and use Intel XED 2026 from source" ON)

if(0CCHEXT_USE_XED_2026)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    FetchContent_Declare(xed2026
        URL "https://github.com/intelxed/xed/archive/refs/tags/v2026.08.23.tar.gz"
        URL_HASH "SHA256=4638942B38DABB7825E6340C1804C97E732837739DAE375A0AD74314ECAC1FFA"
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_Declare(mbuild
        URL "https://github.com/intelxed/mbuild/archive/1b437e409221a2b5703b4d8896baa20d43e4ba1a.tar.gz"
        URL_HASH "SHA256=0D52A3FFD872E69F03C58260E4CED0690E164D944AC670FEAA41AA690A80300C"
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(xed2026 mbuild)

    if(WINDBG_ARCH STREQUAL "x86")
        set(XED2026_HOST_CPU "ia32")
    else()
        set(XED2026_HOST_CPU "x86-64")
    endif()

    string(REPLACE "\\" "/" XED2026_SOURCE_DIR_FORWARD "${xed2026_SOURCE_DIR}")
    set(XED2026_BUILD_DIR "${CMAKE_BINARY_DIR}/xed2026")
    set(XED2026_WKIT_DIR "${XED2026_BUILD_DIR}/wkit")
    set(XED2026_INCLUDE_DIR "${XED2026_WKIT_DIR}/include/xed")
    set(XED2026_LIBRARY "${XED2026_WKIT_DIR}/lib/xed.lib")
    set(XED2026_ILD_LIBRARY "${XED2026_WKIT_DIR}/lib/xed-ild.lib")
    string(REPLACE "\\" "/" XED2026_BUILD_DIR_FORWARD "${XED2026_BUILD_DIR}")

    add_custom_command(
        OUTPUT "${XED2026_LIBRARY}" "${XED2026_ILD_LIBRARY}"
        COMMAND ${CMAKE_COMMAND} -E env
            "PYTHONPATH=${mbuild_SOURCE_DIR}"
            "PYTHONUTF8=1"
            "PYTHONIOENCODING=utf-8"
            "VSLANG=1033"
            "${Python3_EXECUTABLE}" "${XED2026_SOURCE_DIR_FORWARD}/mfile.py"
            --opt=2
            --msvs-version=17
            --setup-msvc
            --host-cpu=${XED2026_HOST_CPU}
            -j 4
            --build-dir=${XED2026_BUILD_DIR_FORWARD}
            --extra-ccflags=/utf-8
            --extra-cxxflags=/utf-8
        WORKING_DIRECTORY "${xed2026_SOURCE_DIR}"
        COMMENT "Building Intel XED 2026 (${XED2026_HOST_CPU})"
        VERBATIM
    )
    add_custom_target(xed2026_build DEPENDS "${XED2026_LIBRARY}" "${XED2026_ILD_LIBRARY}")

    add_library(xed2026 STATIC IMPORTED GLOBAL)
    set_target_properties(xed2026 PROPERTIES IMPORTED_LOCATION "${XED2026_LIBRARY}")
    add_library(xed2026_ild STATIC IMPORTED GLOBAL)
    set_target_properties(xed2026_ild PROPERTIES IMPORTED_LOCATION "${XED2026_ILD_LIBRARY}")
    add_library(xed_runtime INTERFACE)
    target_include_directories(xed_runtime INTERFACE "${XED2026_INCLUDE_DIR}")
    target_link_libraries(xed_runtime INTERFACE xed2026 xed2026_ild)

    message(STATUS "XED backend: Intel XED 2026 source build (${XED2026_HOST_CPU})")
else()
    if(WINDBG_ARCH STREQUAL "x86")
        set(XED_LEGACY_LIBRARY "${CMAKE_SOURCE_DIR}/0cchext/xed/xed2/lib/libxed_x86.lib")
    else()
        set(XED_LEGACY_LIBRARY "${CMAKE_SOURCE_DIR}/0cchext/xed/xed2/lib/libxed_x64.lib")
    endif()
    if(NOT EXISTS "${XED_LEGACY_LIBRARY}")
        message(FATAL_ERROR "Legacy XED library not found: ${XED_LEGACY_LIBRARY}")
    endif()
    add_library(xed_legacy STATIC IMPORTED GLOBAL)
    set_target_properties(xed_legacy PROPERTIES IMPORTED_LOCATION "${XED_LEGACY_LIBRARY}")
    add_library(xed_runtime INTERFACE)
    target_include_directories(xed_runtime INTERFACE "${CMAKE_SOURCE_DIR}/0cchext/xed/xed2/include")
    target_link_libraries(xed_runtime INTERFACE xed_legacy)
    message(STATUS "XED backend: legacy prebuilt XED")
endif()
