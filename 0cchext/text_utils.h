#ifndef __0CCHEXT_TEXT_UTILS_H__
#define __0CCHEXT_TEXT_UTILS_H__

#include <Windows.h>
#include <string>
#include <vector>

std::string ReadLines(PCSTR start_pos, PCSTR str, int lines);
void ReadLines(PCSTR str, std::vector<std::string> &str_vec);
std::string UrlEncodeComponent(PCSTR value);

#endif
