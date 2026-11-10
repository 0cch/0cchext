#include "stdafx.h"
#include "text_utils.h"

std::string ReadLines(PCSTR start_pos, PCSTR str, int lines)
{
	std::string buf;
	int cur_lines = 0;
	if (start_pos == NULL || str == NULL || str < start_pos || lines < 1) {
		return buf;
	}

	while (str > start_pos && str[-1] != '\n') {
		str--;
	}

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
	while (str != NULL && *str != 0) {
		if (*str == '\n') {
			str_vec.push_back(buf);
			buf.clear();
		}
		else if (*str != '\r') {
			buf += *str;
		}
		str++;
	}

	if (!buf.empty()) {
		str_vec.push_back(buf);
	}
}

std::string UrlEncodeComponent(PCSTR value)
{
	static const char hex[] = "0123456789ABCDEF";
	std::string encoded;
	if (value == NULL) {
		return encoded;
	}

	for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p != 0; ++p) {
		unsigned char c = *p;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
			encoded.push_back(static_cast<char>(c));
		}
		else {
			encoded.push_back('%');
			encoded.push_back(hex[(c >> 4) & 0x0F]);
			encoded.push_back(hex[c & 0x0F]);
		}
	}
	return encoded;
}
