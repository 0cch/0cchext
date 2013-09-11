#ifndef __0CCHEXT_UTIL_H__
#define __0CCHEXT_UTIL_H__

#include <Windows.h>
#include <string>

BOOL IsPrintAble(CHAR *str, ULONG len);
PCHAR* WdbgCommandLineToArgv(PCHAR cmd_line, int* arg_num);
std::string ReadLine(PCSTR str);
#endif
