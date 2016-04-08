#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Psapi.h>
#include <atlbase.h>
#include <atlstr.h>
#include <engextcpp.hpp>
#include <regex>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <Shlwapi.h>
#include <Shellapi.h>
#include <WinInet.h>
#include <comdef.h>
#include <wbemidl.h>
#include <comutil.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
