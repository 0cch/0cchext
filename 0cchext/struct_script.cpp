#include "stdafx.h"
#include "struct_script.h"

char * GetToken(char *str, std::string &token, LEX_TOKEN_TYPE &type, int &err)
{
	LEX_STATES state = LEX_START;
	CHAR c;
	err = 0;

	while (state != LEX_DONE) {
		c = *str;
		if (c == 0) {
			err = 1;
			return str;
		}

		switch (state) { 

		case LEX_START:
			if (isdigit(c)) {
				token = c;
				state = LEX_INNUM;
			}
			else if (isalpha(c) || c == '_') {
				token = c;
				state = LEX_INID;
			}
			else if (c == '{') {
				token = c;
				state = LEX_DONE;
				type = TK_ST_BEGIN;
			}
			else if (c == ';') {
				token = c;
				state = LEX_DONE;
				type = TK_SEM;
			}
			else if (c == '}') {
				token = c;
				state = LEX_DONE;
				type = TK_ST_END;
			}
			else if (c == '[') {
				token = "";
				state = LEX_INARRAY;
			}
			else if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r')) {
				str++;
				continue;
			}
			else {
				str--;
				state = LEX_ERROR;
			}

			str++;
			break;

		case LEX_INID:
			if (isalpha(c) || isdigit(c) || c == '_') {
				token += c;
				str++;
			}
			else {
				state = LEX_DONE;
				type = TK_ID;
			}
			break;

		case LEX_INNUM:
			if (isdigit(c)) {
				token += c;
				str++;
			}
			else {
				state = LEX_DONE;
				type = TK_NUMBER;
			}
			break;
		case LEX_INARRAY:
			if (isdigit(c)) {
				token += c;
				str++;
			}
			else if (c == ']') {
				str++;
				state = LEX_DONE;
				type = TK_NUMBER;
			}
			else {
				state = LEX_ERROR;
			}
			break;
		case LEX_ERROR:
			err = -1;
			return str;

		default:
			if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r')) {
				str++;
			}
			else {
				err = -1;
				return str;
			}
		}

	}

	if (type == TK_ID) {
		if (_stricmp(token.c_str(), "BYTE") == 0) {
			type = TK_TYPE_BYTE;
		}
		else if (_stricmp(token.c_str(), "WORD") == 0) {
			type = TK_TYPE_WORD;
		}
		else if (_stricmp(token.c_str(), "DWORD") == 0) {
			type = TK_TYPE_DWORD;
		}
		else if (_stricmp(token.c_str(), "QWORD") == 0) {
			type = TK_TYPE_QWORD;
		}
	}

	return str;
} 


static char s_err_info[64];
BOOL ParseStructScript(const char *str, std::vector<StructInfo> &struct_array)
{
	char *pos = (char *)str;
	int err = 0;
	std::string token;
	LEX_TOKEN_TYPE type;

	for (;;) {
		StructInfo info;
		pos = GetToken(pos, token, type, err);
		if (err != 0) {
			break;
		}
		if (type != TK_ID) {
			err = -2;
			break;
		}

		info.SetName(token.c_str());

		pos = GetToken(pos, token, type, err);
		if (err != 0) {
			break;
		}
		if (type != TK_ST_BEGIN) {
			err = -2;
			break;
		}

		for (;;) {

			pos = GetToken(pos, token, type, err);
			if (err != 0) {
				break;
			}

			if (type == TK_ST_END) {
				break;
			}
			else if (type != TK_TYPE_BYTE && 
				type != TK_TYPE_WORD && 
				type != TK_TYPE_DWORD &&
				type != TK_TYPE_QWORD) {
					err = -2;
					break;
			}

			LEX_TOKEN_TYPE member_type = type;

			pos = GetToken(pos, token, type, err);
			if (err != 0) {
				break;
			}
			if (type != TK_ID) {
				err = -2;
				break;
			}

			std::string member_name(token);

			int count = 1;

			pos = GetToken(pos, token, type, err);
			if (err != 0) {
				break;
			}
			if (type == TK_NUMBER) {
				count = strtol(token.c_str(), NULL, 10);
				if (count == 0) {
					err = -3;
					break;
				}

				pos = GetToken(pos, token, type, err);
				if (err != 0) {
					break;
				}
				if (type != TK_SEM) {
					err = -2;
					break;
				}
			}
			else if (type != TK_SEM) {
				err = -2;
				break;
			}

			info.Add(member_name.c_str(), member_type, count);
		}

		if (err != 0) {
			break;
		}

		pos = GetToken(pos, token, type, err);
		if (err != 0) {
			break;
		}
		if (type != TK_SEM) {
			err = -2;
			break;
		}

		struct_array.push_back(info);
	}

	if (err < 0) {

		strncpy_s(s_err_info, 64, pos, 32);
		s_err_info[32] = 0;
		return FALSE;
	}

	return TRUE;
}

const char * GetErrorPosString()
{
	return s_err_info;
}

const char * GetTypeString(LEX_TOKEN_TYPE type)
{
	switch (type) {
	case TK_TYPE_BYTE:
		return "BYTE";
	case TK_TYPE_WORD:
		return "WORD";
	case TK_TYPE_DWORD:
		return "DWORD";
	case TK_TYPE_QWORD:
		return "QWORD";
	default:
		__debugbreak();
	}
}