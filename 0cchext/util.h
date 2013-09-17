#ifndef __0CCHEXT_UTIL_H__
#define __0CCHEXT_UTIL_H__

#include <Windows.h>
#include <string>
#include <vector>

BOOL IsPrintAble(CHAR *str, ULONG len);
PCHAR* WdbgCommandLineToArgv(PCHAR cmd_line, int* arg_num);
std::string ReadLines(PCSTR start_pos, PCSTR str, int lines);
void ReadLines(PCSTR str, std::vector<std::string> &str_vec);
BOOL GetTxtFileDataA(LPCSTR file, std::string &data);
#endif
