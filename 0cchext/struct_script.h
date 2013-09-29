#ifndef __0CCHEXT_STRUCT_SCRIPT_H__
#define __0CCHEXT_STRUCT_SCRIPT_H__

#include <Windows.h>
#include <ctype.h>
#include <string>
#include <vector>

typedef enum {
	LEX_START,
	LEX_INID,
	LEX_INNUM,
	LEX_INARRAY,
	LEX_ERROR,
	LEX_DONE
} LEX_STATES;

typedef enum {
	TK_NULL,
	TK_NUMBER,
	TK_ID,
	TK_ST_BEGIN,
	TK_ST_END,
	TK_SEM,
	TK_TYPE_BYTE,
	TK_TYPE_WORD,
	TK_TYPE_DWORD,
	TK_TYPE_QWORD,

} LEX_TOKEN_TYPE;

class StructInfo {
public:
	StructInfo() : num_(0) {}
	~StructInfo() {}
	void SetName(const char *name) {name_ = name;}
	void Add(const char *name, LEX_TOKEN_TYPE type, int count = 1)
	{
		member_name_.push_back(name);
		member_type_.push_back(type);
		member_count_.push_back(count);
		num_++;
	}
	int GetCount() {return num_;}
	BOOL Get(int index, std::string &name, LEX_TOKEN_TYPE &type, int &count)
	{
		if (index >= num_) {
			return FALSE;
		}
		name = member_name_[index];
		type = member_type_[index];
		count = member_count_[index];

		return TRUE;
	}
	std::string GetName() {return name_;}

private:
	std::string name_;
	std::vector<std::string> member_name_;
	std::vector<LEX_TOKEN_TYPE> member_type_;
	std::vector<int> member_count_;
	int num_;
};
const char * GetErrorPosString();
BOOL ParseStructScript(const char *str, std::vector<StructInfo> &struct_array);
const char * GetTypeString(LEX_TOKEN_TYPE type);
#endif
