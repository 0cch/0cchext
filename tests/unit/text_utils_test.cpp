#include <Windows.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "text_utils.h"

static void TestReadLines(void)
{
	const std::string text = "first line\r\nsecond line three\r\nthird line\r\n";
	const char *match = strstr(text.c_str(), "three");
	assert(match != NULL);
	assert(ReadLines(text.c_str(), match, 1) == "second line three\r");

	const char *first = strstr(text.c_str(), "first");
	assert(ReadLines(text.c_str(), first, 1) == "first line\r");

	std::vector<std::string> lines;
	ReadLines("alpha\r\nbeta\ngamma", lines);
	assert(lines.size() == 3);
	assert(lines[0] == "alpha");
	assert(lines[1] == "beta");
	assert(lines[2] == "gamma");
}

static void TestUrlEncoding(void)
{
	assert(UrlEncodeComponent("a b&c/d") == "a%20b%26c%2Fd");
	assert(UrlEncodeComponent("AZaz09-_.~") == "AZaz09-_.~");
}

int main(void)
{
	TestReadLines();
	TestUrlEncoding();
	std::cout << "text_utils tests passed\n";
	return 0;
}
