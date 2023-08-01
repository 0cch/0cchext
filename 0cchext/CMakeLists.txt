project(0cchext)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT "${CMAKE_GENERATOR}" MATCHES "Win32")
set(BUILD_PLATFORM "x86")
else()
set(BUILD_PLATFORM "amd64")
endif()

if(NOT "${CMAKE_GENERATOR}" MATCHES "Win32")
set(PLATFORM_LIB_NAME "libxed_x64.lib")
else()
set(PLATFORM_LIB_NAME "libxed_x86.lib")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd\"5040\"")
ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)
ADD_DEFINITIONS(-DXEDPARSE_STATIC)

if(NOT DEFINED "${0CCHEXT_VERSION}")
set(0CCHEXT_VERSION "1.0.0.1")
endif()

string(REPLACE "." "," EXT_VER_NUM ${0CCHEXT_VERSION})
set(EXT_VER_STR ${0CCHEXT_VERSION})

configure_file(resource.h.in resource.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc)
link_directories(${CMAKE_SOURCE_DIR}/${BUILD_PLATFORM}/lib)
link_libraries(
	dbgeng.lib
	dbghelp.lib
	)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/xed/xed2/lib)
link_libraries(
	${PLATFORM_LIB_NAME}
	)

ADD_LIBRARY(0cchext SHARED 
	${CMAKE_CURRENT_SOURCE_DIR}/inc/engextcpp.cpp
	dllmain.cpp
	0cchext.cpp
	0cchext.h
	resource.h
	stdafx.cpp
	stdafx.h
	struct_script.cpp
	struct_script.h
	targetver.h
	util.cpp
	util.h
	0cchext.def
	0cchext.rc
)

target_link_libraries(0cchext libxed)


