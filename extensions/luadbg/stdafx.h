// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

#include <atlbase.h>
#include <atlstr.h>
#include <atlpath.h>
#include <atlenc.h>
#include <engextcpp.hpp>
#include <Dbghelp.h>
#include <map>
#include <set>
#include <vector>
#include "wdbgexts.h"
#include "dbgeng.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "dbgeng.lib")


// TODO: reference additional headers your program requires here
