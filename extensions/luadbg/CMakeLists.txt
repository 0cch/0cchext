include(FetchContent)

FetchContent_Declare(lua54
    URL "https://github.com/lua/lua/archive/refs/tags/v5.4.9.tar.gz"
    URL_HASH "SHA256=76DEF9B3B100E029BFBE37C985D869D0ED993A0CF1A157DF282D6DCD9D6A4E15"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(lua54)

set(LUA54_SOURCES
    "${lua54_SOURCE_DIR}/lapi.c"
    "${lua54_SOURCE_DIR}/lcode.c"
    "${lua54_SOURCE_DIR}/lctype.c"
    "${lua54_SOURCE_DIR}/ldebug.c"
    "${lua54_SOURCE_DIR}/ldo.c"
    "${lua54_SOURCE_DIR}/ldump.c"
    "${lua54_SOURCE_DIR}/lfunc.c"
    "${lua54_SOURCE_DIR}/lgc.c"
    "${lua54_SOURCE_DIR}/llex.c"
    "${lua54_SOURCE_DIR}/lmem.c"
    "${lua54_SOURCE_DIR}/lobject.c"
    "${lua54_SOURCE_DIR}/lopcodes.c"
    "${lua54_SOURCE_DIR}/lparser.c"
    "${lua54_SOURCE_DIR}/lstate.c"
    "${lua54_SOURCE_DIR}/lstring.c"
    "${lua54_SOURCE_DIR}/ltable.c"
    "${lua54_SOURCE_DIR}/ltm.c"
    "${lua54_SOURCE_DIR}/lundump.c"
    "${lua54_SOURCE_DIR}/lvm.c"
    "${lua54_SOURCE_DIR}/lzio.c"
    "${lua54_SOURCE_DIR}/lauxlib.c"
    "${lua54_SOURCE_DIR}/lbaselib.c"
    "${lua54_SOURCE_DIR}/lcorolib.c"
    "${lua54_SOURCE_DIR}/ldblib.c"
    "${lua54_SOURCE_DIR}/liolib.c"
    "${lua54_SOURCE_DIR}/lmathlib.c"
    "${lua54_SOURCE_DIR}/loadlib.c"
    "${lua54_SOURCE_DIR}/loslib.c"
    "${lua54_SOURCE_DIR}/lstrlib.c"
    "${lua54_SOURCE_DIR}/ltablib.c"
    "${lua54_SOURCE_DIR}/lutf8lib.c"
    "${lua54_SOURCE_DIR}/linit.c"
)

add_library(lua54_static STATIC ${LUA54_SOURCES})
target_include_directories(lua54_static PUBLIC "${lua54_SOURCE_DIR}")
target_compile_definitions(lua54_static PRIVATE _CRT_SECURE_NO_WARNINGS)
target_compile_options(lua54_static PRIVATE /W3 /utf-8)
set_target_properties(lua54_static PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

add_library(luadbg SHARED
    dllmain.cpp
    luadbg.cpp
    stdafx.cpp
    stdafx.h
    targetver.h
    luadbg.def
    luadbg.rc
    resource.h
)

cchext_configure_project_target(luadbg)
cchext_link_dbgeng(luadbg)

target_include_directories(luadbg PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(luadbg PRIVATE lua54_static shell32 ole32 oleaut32 user32 advapi32)
target_compile_definitions(luadbg PRIVATE _CRT_SECURE_NO_WARNINGS)
