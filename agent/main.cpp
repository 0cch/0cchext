#include "debug_session.h"
#include "mcp_server.h"

#include <iostream>
#include <string>

namespace
{
void PrintUsage()
{
	std::wcerr << L"0cchext-agent [--dump PATH | --attach PID | --create COMMAND | --extension PATH]\n"
		L"Starts an MCP stdio server for DbgEng/WinDbg automation.\n";
}

int ParsePid(const wchar_t *text, unsigned long &pid)
{
	wchar_t *end = nullptr;
	const unsigned long value = wcstoul(text, &end, 0);
	if (end == text || *end != L'\0' || value == 0) return 1;
	pid = value;
	return 0;
}
}

int wmain(int argc, wchar_t **argv)
{
	DebugSession session;
	std::wstring extension_path;

	for (int i = 1; i < argc; ++i) {
		const std::wstring option = argv[i];
		if (option == L"--help" || option == L"-h") {
			PrintUsage();
			return 0;
		}
		if (option == L"--dump" && i + 1 < argc) {
			if (!session.OpenDump(argv[++i])) {
				std::cerr << session.LastError() << std::endl;
				return 1;
			}
		}
		else if (option == L"--attach" && i + 1 < argc) {
			unsigned long pid = 0;
			if (ParsePid(argv[++i], pid) != 0 || !session.Attach(pid)) {
				std::cerr << session.LastError() << std::endl;
				return 1;
			}
		}
		else if (option == L"--create" && i + 1 < argc) {
			if (!session.Create(argv[++i])) {
				std::cerr << session.LastError() << std::endl;
				return 1;
			}
		}
		else if (option == L"--extension" && i + 1 < argc) {
			extension_path = argv[++i];
		}
		else {
			PrintUsage();
			return 2;
		}
	}

	if (!extension_path.empty() && !session.LoadExtension(extension_path)) {
		std::cerr << "Unable to load extension: " << session.LastError() << std::endl;
		return 1;
	}

	McpServer server(session);
	return server.Run();
}
