string(REPLACE "." "," EXT_VER_NUM "${0CCHEXT_VERSION}")
set(EXT_VER_STR "${0CCHEXT_VERSION}")

configure_file(resource.h.in "${CMAKE_CURRENT_BINARY_DIR}/resource.h")

add_library(0cchext SHARED
    dllmain.cpp
    assembler_backend.cpp
    assembler_backend.h
    0cchext.cpp
    0cchext.h
    stdafx.cpp
    stdafx.h
    struct_script.cpp
    struct_script.h
    text_utils.cpp
    text_utils.h
    util.cpp
    util.h
    targetver.h
    0cchext.def
    0cchext.rc
    "${CMAKE_CURRENT_BINARY_DIR}/resource.h"
)

cchext_configure_project_target(0cchext)
cchext_link_dbgeng(0cchext)

target_include_directories(0cchext PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/xed/src"
)
target_link_libraries(0cchext PRIVATE
    libxed
    shell32
    shlwapi
    version
    winhttp
    ws2_32
    wbemuuid
    psapi
    ole32
    oleaut32
    uuid
    user32
    advapi32
    gdi32
    comdlg32
    winspool
)
target_compile_definitions(0cchext PRIVATE XEDPARSE_STATIC)


