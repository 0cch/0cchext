#include "StdAfx.h"
#include "util.h"
#include <fstream>

BOOL IsPrintAble(CHAR *str, ULONG len)
{
	for (ULONG i = 0; i < len; i++) {
		if (!isprint((UCHAR)str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

PCHAR* WdbgCommandLineToArgv(PCHAR cmd_line, int* arg_num)
{
	PCHAR* argv;
	PCHAR argv_buf;
	ULONG len;
	ULONG argc;
	CHAR a;
	ULONG i, j;

	BOOLEAN in_QM;
	BOOLEAN in_TEXT;
	BOOLEAN in_SPACE;

	len = (ULONG)strlen(cmd_line);
	i = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

	argv = (PCHAR*)LocalAlloc(LMEM_FIXED,
		i + (len + 2)*sizeof(CHAR));

	argv_buf = (PCHAR)(((PUCHAR)argv) + i);

	argc = 0;
	argv[argc] = argv_buf;
	in_QM = FALSE;
	in_TEXT = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;

	while( a = cmd_line[i] ) {
		if(in_QM) {
			if(a == '\'') {
				in_QM = FALSE;
			} else {
				argv_buf[j] = a;
				j++;
			}
		} else {
			switch(a) {
			case '\'':
				in_QM = TRUE;
				in_TEXT = TRUE;
				if(in_SPACE) {
					argv[argc] = argv_buf+j;
					argc++;
				}
				in_SPACE = FALSE;
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				if(in_TEXT) {
					argv_buf[j] = '\0';
					j++;
				}
				in_TEXT = FALSE;
				in_SPACE = TRUE;
				break;
			default:
				in_TEXT = TRUE;
				if(in_SPACE) {
					argv[argc] = argv_buf+j;
					argc++;
				}
				argv_buf[j] = a;
				j++;
				in_SPACE = FALSE;
				break;
			}
		}
		i++;
	}
	argv_buf[j] = '\0';
	argv[argc] = NULL;

	(*arg_num) = argc;
	return argv;
}

std::string ReadLines(PCSTR str, int lines)
{
	std::string buf;
	int cur_lines = 0;
	while (*str != 0) {
		if (*str == '\n') {
			cur_lines++;
		}

		if (cur_lines >= lines) {
			break;
		}

		buf += *str;
		str++;
	}

	return buf;
}

void ReadLines(PCSTR str, std::vector<std::string> &str_vec)
{
	std::string buf;
	while (*str != 0) {
		if (*str == '\n') {
			str_vec.push_back(buf);
			buf.clear();
		}
		else if (*str == '\r') {
			
		}
		else {
			buf += *str;
		}
		str++;
	}

	if (!buf.empty()) {
		str_vec.push_back(buf);
		buf.clear();
	}
}

BOOL GetTxtFileDataA(LPCSTR file, std::string &data)
{
	std::ifstream ifs(file);
	if (!ifs.is_open()) {
		return FALSE;
	}

	std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	data = str;
	return TRUE;
}