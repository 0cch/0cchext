#ifndef __0CCHEXT_H__
#define __0CCHEXT_H__

#ifdef _WIN64
#define KDEXT_64BIT
#else
#define KDEXT_32BIT
#endif

#include <atlbase.h>
#include <atlstr.h>
#include <atlpath.h>
#include "wdbgexts.h"
#include "dbgeng.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "dbgeng.lib")


#endif




