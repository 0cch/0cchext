set(WINDBG_ARCH "x64")
if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32" OR CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(WINDBG_ARCH "x86")
endif()

option(0CCHEXT_USE_INSTALLED_ENGEXTCPP "Use engextcpp from installed Windows Debugging Tools" ON)

if(NOT DEFINED WINDBG_ROOT)
    set(WINDBG_ROOT "C:/Program Files (x86)/Windows Kits/10/Debuggers" CACHE PATH "Windows Debugging Tools installation root")
endif()

if(NOT DEFINED WINDOWS_SDK_INCLUDE_DIR)
    if(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION)
        set(WINDOWS_SDK_INCLUDE_DIR "C:/Program Files (x86)/Windows Kits/10/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/um")
        set(WINDOWS_SDK_LIB_DIR "C:/Program Files (x86)/Windows Kits/10/Lib/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/um/${WINDBG_ARCH}")
    else()
        set(WINDOWS_SDK_INCLUDE_DIR "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um")
        set(WINDOWS_SDK_LIB_DIR "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/${WINDBG_ARCH}")
    endif()
endif()

set(WINDBG_INCLUDE_DIR "${WINDBG_ROOT}/inc")
set(WINDBG_LIB_DIR "${WINDBG_ROOT}/lib/${WINDBG_ARCH}")
set(INSTALLED_ENGEXTCPP_SOURCE "${WINDBG_INCLUDE_DIR}/engextcpp.cpp")
set(BUNDLED_ENGEXTCPP_SOURCE "${CMAKE_SOURCE_DIR}/compat/windbg/engextcpp.cpp")

if(0CCHEXT_USE_INSTALLED_ENGEXTCPP AND EXISTS "${INSTALLED_ENGEXTCPP_SOURCE}" AND EXISTS "${WINDBG_INCLUDE_DIR}/engextcpp.hpp")
    set(WINDBG_ENGEXTCPP_INCLUDE_DIR "${WINDBG_INCLUDE_DIR}")
    set(WINDBG_ENGEXTCPP_SOURCE "${INSTALLED_ENGEXTCPP_SOURCE}")
    message(STATUS "Using installed EngExtCpp: ${WINDBG_INCLUDE_DIR}")
else()
    set(WINDBG_ENGEXTCPP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/compat/windbg")
    set(WINDBG_ENGEXTCPP_SOURCE "${BUNDLED_ENGEXTCPP_SOURCE}")
    message(STATUS "Using bundled EngExtCpp: ${WINDBG_ENGEXTCPP_INCLUDE_DIR}")
endif()

if(NOT EXISTS "${WINDBG_ENGEXTCPP_SOURCE}" OR NOT EXISTS "${WINDBG_ENGEXTCPP_INCLUDE_DIR}/engextcpp.hpp")
    message(FATAL_ERROR "EngExtCpp sources were not found. Check WINDBG_ROOT or compat/windbg.")
endif()
if(NOT EXISTS "${WINDOWS_SDK_INCLUDE_DIR}/dbgeng.h" OR NOT EXISTS "${WINDOWS_SDK_INCLUDE_DIR}/dbghelp.h")
    message(FATAL_ERROR "DbgEng/DbgHelp headers were not found under ${WINDOWS_SDK_INCLUDE_DIR}.")
endif()

find_library(DBGENG_LIBRARY NAMES dbgeng PATHS "${WINDOWS_SDK_LIB_DIR}" "${WINDBG_LIB_DIR}" NO_DEFAULT_PATH)
find_library(DBGHELP_LIBRARY NAMES dbghelp PATHS "${WINDOWS_SDK_LIB_DIR}" "${WINDBG_LIB_DIR}" NO_DEFAULT_PATH)

if(NOT DBGENG_LIBRARY)
    message(FATAL_ERROR "dbgeng.lib was not found under ${WINDOWS_SDK_LIB_DIR} or ${WINDBG_LIB_DIR}.")
endif()
if(NOT DBGHELP_LIBRARY)
    message(FATAL_ERROR "dbghelp.lib was not found under ${WINDOWS_SDK_LIB_DIR} or ${WINDBG_LIB_DIR}.")
endif()

add_library(windbg_engextcpp STATIC "${WINDBG_ENGEXTCPP_SOURCE}")
target_include_directories(windbg_engextcpp PUBLIC
    "${WINDOWS_SDK_INCLUDE_DIR}"
    "${WINDBG_ENGEXTCPP_INCLUDE_DIR}"
)
target_compile_options(windbg_engextcpp PRIVATE /permissive /W3 /wd5040 /wd4267 /wd4245 /wd4244)
set_target_properties(windbg_engextcpp PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

function(cchext_link_dbgeng target_name)
    target_include_directories(${target_name} BEFORE PRIVATE
        "${WINDOWS_SDK_INCLUDE_DIR}"
        "${WINDBG_ENGEXTCPP_INCLUDE_DIR}"
    )
    target_link_libraries(${target_name} PRIVATE
        windbg_engextcpp
        "${DBGENG_LIBRARY}"
        "${DBGHELP_LIBRARY}"
    )
endfunction()

message(STATUS "Windows Debugging Tools: ${WINDBG_ROOT} (${WINDBG_ARCH})")
message(STATUS "Windows SDK include: ${WINDOWS_SDK_INCLUDE_DIR}")
