#ifndef __0CCHEXT_STRUCT_SCRIPT_H__
#define __0CCHEXT_STRUCT_SCRIPT_H__

#include <Windows.h>
#include <ctype.h>
#include <string>
#include <vector>

typedef enum _LEX_STATES {
	LEX_START,
	LEX_INID,
	LEX_INNUM,
	LEX_INARRAY,
	LEX_ERROR,
	LEX_DONE
} LEX_STATES;

typedef enum _LEX_TOKEN_TYPE {
	TK_NULL,
	TK_NUMBER,
	TK_ID,
	TK_ST_BEGIN,
	TK_ST_END,
	TK_SEM,
	TK_AST,
	TK_TYPE_BYTE,
	TK_TYPE_WORD,
	TK_TYPE_DWORD,
	TK_TYPE_QWORD,
	TK_TYPE_CHAR,
	TK_TYPE_WCHAR,
	TK_TYPE_UDT,
} LEX_TOKEN_TYPE;

class StructInfo {
public:
	StructInfo() : num_(0) {}
	~StructInfo() {}
	void SetName(const char *name) {name_ = name;}
	void Add(const char *name, LEX_TOKEN_TYPE type, BOOL isptr, const char *udt_name, int count)
	{
		member_name_.push_back(name);
		member_type_.push_back(type);
		member_count_.push_back(count);
		if (udt_name == NULL) {
			member_udt_name_.push_back("NULL");
		}
		else {
			member_udt_name_.push_back(udt_name);
		}
		member_isptr_.push_back(isptr);
		num_++;
	}
	int GetCount() {return num_;}
	BOOL Get(int index, std::string &name, LEX_TOKEN_TYPE &type, BOOL &isptr, std::string &udt_name, int &count)
	{
		if (index >= num_) {
			return FALSE;
		}
		name = member_name_[index];
		type = member_type_[index];
		count = member_count_[index];
		udt_name = member_udt_name_[index];
		isptr = member_isptr_[index];
		return TRUE;
	}
	std::string GetName() {return name_;}

private:
	std::string name_;
	std::vector<std::string> member_name_;
	std::vector<LEX_TOKEN_TYPE> member_type_;
	std::vector<int> member_count_;
	std::vector<BOOL> member_isptr_;
	std::vector<std::string> member_udt_name_;
	int num_;
};
const char * GetErrorPosString();
BOOL ParseStructScript(const char *str, std::vector<StructInfo> &struct_array);



class dtLexItem {
public:
	dtLexItem() : is_array_(FALSE), 
		array_count_(0), ptr_count_(0), 
		bit_offset_(0), bit_length_(0), 
		offset_(0), is_bitfield_(FALSE) {}

	BOOL is_array_;
	ULONG array_count_;
	CStringA type_name_;
	ULONG ptr_count_;
	CStringA name_;
	BOOL is_bitfield_;
	ULONG bit_offset_;
	ULONG bit_length_;
	ULONG offset_;
};


void DbgStructToken(LPCSTR struct_str, std::vector<std::pair<ULONG, std::vector<CStringA>>> &struct_out);
void DbgStructParse(std::vector<std::pair<ULONG, std::vector<CStringA>>> &struct_out, std::map<ULONG, std::vector<dtLexItem>> &items);
void DbgStructPrint(std::map<ULONG, std::vector<dtLexItem>> &items, CStringA &out_str);
#endif
