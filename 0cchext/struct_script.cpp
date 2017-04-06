#include "stdafx.h"
#include "struct_script.h"

BOOL IsUDT(const char * name, std::vector<StructInfo> &struct_array)
{
	BOOL retval = FALSE;
	for (size_t i = 0; i < struct_array.size(); i++) {
		if (strcmp(name, struct_array[i].GetName().c_str()) == 0) {
			retval = TRUE;
			break;
		}
	}
	return retval;
}

char * GetToken(char *str, std::string &token, LEX_TOKEN_TYPE &type, int &err, std::vector<StructInfo> &struct_array)
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
			else if (c == '*') {
				token = c;
				state = LEX_DONE;
				type = TK_AST;
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
		if (strcmp(token.c_str(), "BYTE") == 0) {
			type = TK_TYPE_BYTE;
		}
		else if (strcmp(token.c_str(), "WORD") == 0) {
			type = TK_TYPE_WORD;
		}
		else if (strcmp(token.c_str(), "DWORD") == 0) {
			type = TK_TYPE_DWORD;
		}
		else if (strcmp(token.c_str(), "QWORD") == 0) {
			type = TK_TYPE_QWORD;
		}
		else if (strcmp(token.c_str(), "CHAR") == 0) {
			type = TK_TYPE_CHAR;
		}
		else if (strcmp(token.c_str(), "WCHAR") == 0) {
			type = TK_TYPE_WCHAR;
		}
		else if (IsUDT(token.c_str(), struct_array)) {
			type = TK_TYPE_UDT;
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
		pos = GetToken(pos, token, type, err, struct_array);
		if (err != 0) {
			break;
		}
		if (type != TK_ID) {
			err = -2;
			break;
		}

		info.SetName(token.c_str());

		pos = GetToken(pos, token, type, err, struct_array);
		if (err != 0) {
			break;
		}
		if (type != TK_ST_BEGIN) {
			err = -2;
			break;
		}

		for (;;) {

			pos = GetToken(pos, token, type, err, struct_array);
			if (err != 0) {
				break;
			}

			if (type == TK_ST_END) {
				break;
			}
			else if (type != TK_TYPE_BYTE && 
				type != TK_TYPE_WORD && 
				type != TK_TYPE_DWORD &&
				type != TK_TYPE_QWORD && 
				type != TK_TYPE_CHAR &&
				type != TK_TYPE_WCHAR &&
				type != TK_TYPE_UDT) {
					err = -2;
					break;
			}

			LEX_TOKEN_TYPE member_type = type;
			std::string member_udt_name(token);
			
			pos = GetToken(pos, token, type, err, struct_array);
			if (err != 0) {
				break;
			}

			BOOL isptr = FALSE;
			if (type == TK_AST) {

				isptr = TRUE;
				pos = GetToken(pos, token, type, err, struct_array);
				if (err != 0) {
					break;
				}
			}

			if (type != TK_ID) {
				err = -2;
				break;
			}

			std::string member_name(token);

			int count = 1;

			pos = GetToken(pos, token, type, err, struct_array);
			if (err != 0) {
				break;
			}
			if (type == TK_NUMBER) {
				count = strtol(token.c_str(), NULL, 10);
				if (count == 0) {
					err = -3;
					break;
				}

				pos = GetToken(pos, token, type, err, struct_array);
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

			info.Add(member_name.c_str(), member_type, isptr, member_udt_name.c_str(), count);
		}

		if (err != 0) {
			break;
		}

		pos = GetToken(pos, token, type, err, struct_array);
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


void Skip(const CHAR **pos)
{
	const CHAR * cur = *pos;
	while (*cur == ' ' || *cur == '\t' || *cur == ',' || *cur == ':') {
		cur++;
	}
	*pos = cur;
}

void DbgStructToken(LPCSTR struct_str, std::vector<std::pair<ULONG, std::vector<CStringA>>> &struct_out)
{
	const CHAR *cur = struct_str;
	CStringA offset_str;
	std::vector<CStringA> items;
	for (;;) {
		Skip(&cur);
		switch (*cur)
		{
		case '+':
			cur++;
			while (*cur != ' ' && *cur != '\r' && *cur != '\n' && *cur != '\0') {
				offset_str += *cur;
				cur++;
			}
			break;
		case '\r':
		case '\n':
		case '\0':
			{
				if (*cur == '\r' && *(cur + 1) == '\n') {
					cur += 2;
				}
				else if (*cur == '\n') {
					cur++;
				}

				if (!items.empty()) {
					struct_out.push_back(std::make_pair(strtoul(offset_str.GetString(), NULL, 16), items));
					items.clear();
					offset_str.Empty();
				}

				if (*cur == 0) {
					return;
				}
			}
			break;
		default:
			{
				CStringA item;
				while (*cur != ' ' && *cur != '\r' && *cur != '\n' && *cur != '\0') {
					item += *cur;
					cur++;
				}


				items.push_back(item);
			}

			break;
		}

	}
}

void DbgStructParse(std::vector<std::pair<ULONG, std::vector<CStringA>>> &struct_out, std::map<ULONG, std::vector<dtLexItem>> &items)
{

	std::vector<std::pair<ULONG, std::vector<CStringA>>>::iterator it = struct_out.begin();
	for (;it != struct_out.end(); ++it) {
		dtLexItem item;
		item.name_ = (*it).second[0];
		item.offset_ = (*it).first;

		if ((*it).second[1] == "Pos") {
			item.is_bitfield_ = TRUE;
			item.bit_offset_ = strtoul((*it).second[2].GetString(), NULL, 10);
			item.bit_length_ = strtoul((*it).second[3].GetString(), NULL, 10);
			item.name_ = (*it).second[0];
		}
		else {
			ULONG i = 1;
			if ((*it).second[i][0] == '[') {
				item.array_count_ = strtoul((*it).second[i].GetString() + 1, NULL, 10);
				item.is_array_ = TRUE;
				i++;
			}

			for (; i < (*it).second.size(); i++) {
				if ((*it).second[i] == "Ptr64" || (*it).second[i] == "Ptr32") {
					item.ptr_count_++;
				}
				else {
					break;
				}
			}

			if ((*it).second[i] == "Void") {
				item.type_name_ = "VOID";
			}
			else if ((*it).second[i] == "UChar") {
				item.type_name_ = "BYTE";
			}
			else if ((*it).second[i] == "Uint2B") {
				item.type_name_ = "WORD";
			}
			else if ((*it).second[i] == "Uint4B") {
				item.type_name_ = "DWORD";
			}
			else if ((*it).second[i] == "Uint8B") {
				item.type_name_ = "QWORD";
			}
			else {
				item.type_name_ = (*it).second[i];
			}

		}

		items[it->first].push_back(item);
	}
}

void DbgStructPrint(std::map<ULONG, std::vector<dtLexItem>> &items, CStringA &out_str)
{
	std::map<ULONG, std::vector<dtLexItem>>::iterator it = items.begin();
	for (; it != items.end(); ++it) {
		std::vector<dtLexItem> &item = it->second;
		if (item.size() == 1) {
			dtLexItem &sub_item = item[0];
			if (sub_item.is_bitfield_) {
				CStringA type_name;
				ULONG total_bits = sub_item.bit_length_ + sub_item.bit_offset_;
				if (total_bits <= 8) {
					type_name = "BYTE";
				}
				else if (total_bits <= 16) {
					type_name = "WORD";
				}
				else if (total_bits <= 32) {
					type_name = "DWORD";
				}
				else if (total_bits <= 64) {
					type_name = "QWORD";
				}

				out_str.AppendFormat("\t%s %s:%u;\r\n", type_name.GetString(), sub_item.name_.GetString(), sub_item.bit_length_);
			}
			else {
				out_str.AppendFormat("\t%s", sub_item.type_name_.GetString());
				for (ULONG i = 0; i < sub_item.ptr_count_; i++) {
					out_str.Append("*");
				}

				out_str.AppendFormat(" %s", sub_item.name_.GetString());
				if (sub_item.is_array_) {
					out_str.AppendFormat("[%u]", sub_item.array_count_);
				}
				out_str.Append(";\r\n");
			}
		}
		else {
			std::vector<dtLexItem> bitfield_items;
			std::vector<dtLexItem> union_items;

			for (std::vector<dtLexItem>::iterator sub_it = item.begin(); sub_it != item.end(); ++sub_it) {
				if (sub_it->is_bitfield_) {
					bitfield_items.push_back(*sub_it);
				}
				else {
					union_items.push_back(*sub_it);
				}
			}

			if (bitfield_items.size() != 0 && union_items.size() != 0) {
				out_str.Append("\tunion {\r\n");

				for (size_t i = 0; i < union_items.size(); i++) {
					dtLexItem &sub_item = union_items[i];

					out_str.AppendFormat("\t\t%s", sub_item.type_name_.GetString());
					for (ULONG i = 0; i < sub_item.ptr_count_; i++) {
						out_str.Append("*");
					}

					out_str.AppendFormat(" %s", sub_item.name_.GetString());
					if (sub_item.is_array_) {
						out_str.AppendFormat("[%u]", sub_item.array_count_);
					}
					out_str.Append(";\r\n");
				}

				out_str.Append("\t\tstruct {\r\n");

				std::map<ULONG, std::vector<dtLexItem>>::iterator next_it = it;
				next_it++;
				ULONG total_bytes = 0;
				if (next_it == items.end()) {
					for (size_t i = 0; i < bitfield_items.size(); i++) {
						dtLexItem &sub_item = bitfield_items[i];
						total_bytes += sub_item.bit_length_;
					}

					total_bytes /= 8;
				}
				else {
					total_bytes = next_it->first - it->first;
				}

				CStringA type_name;
				if (total_bytes <= 1) {
					type_name = "BYTE";
				}
				else if (total_bytes <= 2) {
					type_name = "WORD";
				}
				else if (total_bytes <= 4) {
					type_name = "DWORD";
				}
				else if (total_bytes <= 8) {
					type_name = "QWORD";
				}

				for (size_t i = 0; i < bitfield_items.size(); i++) {
					dtLexItem &sub_item = bitfield_items[i];
					out_str.AppendFormat("\t\t\t%s %s:%u;\r\n", type_name.GetString(), sub_item.name_.GetString(), sub_item.bit_length_);
				}

				out_str.Append("\t\t};\r\n");

				out_str.Append("\t};\r\n");
			}
			else if (union_items.size() != 0) {
				out_str.Append("\tunion {\r\n");

				for (size_t i = 0; i < union_items.size(); i++) {
					dtLexItem &sub_item = union_items[i];

					out_str.AppendFormat("\t\t%s", sub_item.type_name_.GetString());
					for (ULONG i = 0; i < sub_item.ptr_count_; i++) {
						out_str.Append("*");
					}

					out_str.AppendFormat(" %s", sub_item.name_.GetString());
					if (sub_item.is_array_) {
						out_str.AppendFormat("[%u]", sub_item.array_count_);
					}
					out_str.Append(";\r\n");
				}

				out_str.Append("\t};\r\n");
			}
			else if (bitfield_items.size() != 0) {
				out_str.Append("\tstruct {\r\n");

				std::map<ULONG, std::vector<dtLexItem>>::iterator next_it = it;
				next_it++;
				ULONG total_bytes = 0;
				if (next_it == items.end()) {
					for (size_t i = 0; i < bitfield_items.size(); i++) {
						dtLexItem &sub_item = bitfield_items[i];
						total_bytes += sub_item.bit_length_;
					}

					total_bytes /= 8;
				}
				else {
					total_bytes = next_it->first - it->first;
				}
				CStringA type_name;
				if (total_bytes <= 1) {
					type_name = "BYTE";
				}
				else if (total_bytes <= 2) {
					type_name = "WORD";
				}
				else if (total_bytes <= 4) {
					type_name = "DWORD";
				}
				else if (total_bytes <= 8) {
					type_name = "QWORD";
				}

				for (size_t i = 0; i < bitfield_items.size(); i++) {
					dtLexItem &sub_item = bitfield_items[i];
					out_str.AppendFormat("\t\t%s %s:%u;\r\n", type_name.GetString(), sub_item.name_.GetString(), sub_item.bit_length_);
				}

				out_str.Append("\t};\r\n");
			}
		}
	}
}