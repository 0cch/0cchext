#include "stdafx.h"
#include "0cchext.h"
#include "util.h"
#include <engextcpp.hpp>
#include <regex>
#include <string>
#include <Shlwapi.h>
#include <Shellapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")

class EXT_CLASS : public ExtExtension
{
public:
	EXT_COMMAND_METHOD(hwnd);
	EXT_COMMAND_METHOD(setvprot);
	EXT_COMMAND_METHOD(dpx);
	EXT_COMMAND_METHOD(grep);
	EXT_COMMAND_METHOD(version);
	EXT_COMMAND_METHOD(url);
	EXT_COMMAND_METHOD(favcmd);
};

EXT_DECLARE_GLOBALS();


EXT_COMMAND(hwnd,
	"Show window information by handle.",
	"{;ed,r;hwnd;A handle to the window}")
{
	ULONG class_type = 0, qualifier_type = 0;
	HRESULT hr = m_Control->GetDebuggeeType(&class_type, &qualifier_type);
	if (FAILED(hr)) {
		Err("Failed to get debuggee type\n");
		return;
	}

	if (class_type != DEBUG_CLASS_KERNEL) {
		Err("This command must be used in Kernel-Mode\n");
		return;
	}

	ULONG64 wnd_handle = GetUnnamedArgU64(0);
	DEBUG_VALUE dbg_value = {0};
	hr = m_Control->Evaluate("win32k!gSharedInfo", DEBUG_VALUE_INT64, &dbg_value, NULL);
	if (FAILED(hr)) {
		Err("Failed to get win32k!gSharedInfo\n");
		return;
	}

	ExtRemoteTyped shared_info("(win32k!tagSHAREDINFO *)@$extin", dbg_value.I64);
	ULONG handle_Count = shared_info.Field("psi.cHandleEntries").GetUlong();

	if ((wnd_handle & 0xffff) >= handle_Count) {
		Err("Invalidate window handle value.\n");
		return;
	}

	ULONG entry_size = shared_info.Field("HeEntrySize").GetUlong();
	ULONG64 entries = shared_info.Field("aheList").GetUlongPtr();
	ULONG64 target_entry = entries + entry_size * (wnd_handle & 0xffff);
	ExtRemoteData wnd_data(target_entry, sizeof(PVOID));

	ExtRemoteTyped wnd_ptr("(win32k!tagWnd *)@$extin", wnd_data.GetPtr());
	Out("HWND: %p\n", wnd_ptr.Field("head.h").GetPtr());
	Dml("tagWnd * @ <link cmd=\"dt %p win32k!tagWnd\">%p</link>\n", wnd_data.GetPtr(), wnd_data.GetPtr());

	if (wnd_ptr.Field("strName.Buffer").GetPtr() != 0) {
		Out("Window Name: %mu\n", wnd_ptr.Field("strName.Buffer").GetPtr());
	}

	Dml("tagCLS * @ <link cmd=\"r @$t0=%p;dt @@C++(((win32k!tagWnd *)@$t0)->pcls) win32k!tagCLS\">%p</link>\n", 
		wnd_data.GetPtr(), wnd_ptr.Field("pcls").GetPtr());

	if (wnd_ptr.Field("pcls.lpszAnsiClassName").GetPtr() != 0) {
		Out("Window Class Name: %ma\n", wnd_ptr.Field("pcls.lpszAnsiClassName").GetPtr());
	}
	if (wnd_ptr.Field("spwndNext").GetPtr() != 0) {
		Dml("Next Wnd:     <link cmd=\"!0cchext.hwnd %p\">%p</link>\n", 
			wnd_ptr.Field("spwndNext.head.h").GetPtr(), wnd_ptr.Field("spwndNext.head.h").GetPtr());
	}
	if (wnd_ptr.Field("spwndPrev").GetPtr() != 0) {
		Dml("Previous Wnd: <link cmd=\"!0cchext.hwnd %p\">%p</link>\n", 
			wnd_ptr.Field("spwndPrev.head.h").GetPtr(), wnd_ptr.Field("spwndPrev.head.h").GetPtr());
	}
	if (wnd_ptr.Field("spwndParent").GetPtr() != 0) {
		Dml("Parent Wnd:   <link cmd=\"!0cchext.hwnd %p\">%p</link>\n", 
			wnd_ptr.Field("spwndParent.head.h").GetPtr(), wnd_ptr.Field("spwndParent.head.h").GetPtr());
	}
	if (wnd_ptr.Field("spwndChild").GetPtr() != 0) {
		Dml("Child Wnd:    <link cmd=\"!0cchext.hwnd %p\">%p</link>\n", 
			wnd_ptr.Field("spwndChild.head.h").GetPtr(), wnd_ptr.Field("spwndChild.head.h").GetPtr());
	}
	if (wnd_ptr.Field("spwndOwner").GetPtr() != 0) {
		Dml("Own Wnd:      <link cmd=\"!0cchext.hwnd %p\">%p</link>\n", 
			wnd_ptr.Field("spwndOwner.head.h").GetPtr(), wnd_ptr.Field("spwndOwner.head.h").GetPtr());
	}
	if (wnd_ptr.Field("lpfnWndProc").GetPtr() != 0) {
		Dml("pfnWndProc:   "
			"<link cmd=\"r @$t0=%p;.process /p /r @@C++(((nt!_ETHREAD *)((win32k!tagWnd *)@$t0)->head.pti->pEThread)->Tcb.Process);"
			"u @@C++(((win32k!tagWnd *)@$t0)->lpfnWndProc)\">%p</link>\n", 
			wnd_data.GetPtr(), wnd_ptr.Field("lpfnWndProc").GetPtr());
	}

	ULONG style = wnd_ptr.Field("style").GetUlong();

	Out("Visible:  %d\n", (style & (1<<28)) != 0);
	Out("Child:    %d\n", (style & (1<<30)) != 0);
	Out("Minimized:%d\n", (style & (1<<29)) != 0);
	Out("Disabled: %d\n", (style & (1<<27)) != 0);
	Out("Window Rect {%d, %d, %d, %d}\n", 
		wnd_ptr.Field("rcWindow.left").GetLong(),
		wnd_ptr.Field("rcWindow.top").GetLong(),
		wnd_ptr.Field("rcWindow.right").GetLong(),
		wnd_ptr.Field("rcWindow.bottom").GetLong());
	Out("Clent Rect  {%d, %d, %d, %d}\n",
		wnd_ptr.Field("rcClient.left").GetLong(),
		wnd_ptr.Field("rcClient.top").GetLong(),
		wnd_ptr.Field("rcClient.right").GetLong(),
		wnd_ptr.Field("rcClient.bottom").GetLong());

	Out("\n");
}

EXT_COMMAND(setvprot,
	"Set the protection on a region of committed pages in the virtual address space of the debuggee process.",
	"{;ed,r;Address;Base address of the region of pages}"
	"{;ed,r;Size;The size of the region}"
	"{;ed,r;type;The new protection type}"
	)
{
	ULONG class_type = 0, qualifier_type = 0;
	HRESULT hr = m_Control->GetDebuggeeType(&class_type, &qualifier_type);
	if (FAILED(hr)) {
		Err("Failed to get debuggee type\n");
		return;
	}

	if (class_type != DEBUG_CLASS_USER_WINDOWS) {
		Err("This command must be used in User-Mode\n");
		return;
	}

	ULONG64 base_address = GetUnnamedArgU64(0);
	ULONG64 region_size = GetUnnamedArgU64(1);
	ULONG64 protection_type = GetUnnamedArgU64(2);

	ULONG64 handle = 0;
	hr = m_System->GetCurrentProcessHandle(&handle);
	if (FAILED(hr)) {
		Err("Failed to get process handle.\n");
		return;
	}

	ULONG old_type = 0;
	if (!VirtualProtectEx((HANDLE)handle, 
		(PVOID)base_address, 
		(SIZE_T)region_size, 
		(ULONG)protection_type, 
		&old_type)) {
			Err("Failed to set virtual protection type.\n");
			return;
	}

	Dml("[%p - %p] Change %08X to %08X <link cmd=\"!vprot %p\">Detail</link>\n",
		base_address, region_size, (ULONG)old_type, (ULONG)protection_type, base_address);
}

EXT_COMMAND(dpx,
	"Display the contents of memory in the given range.",
	"{;ed,r;Address;Base address of the memory area to display}"
	"{;ed,o,d=10;range;The range of the memory area}"
	"{i;b,o;ignore;Ignore the address that do not have any info}"
	)
{
	ULONG64 base_address = GetUnnamedArgU64(0);
	ULONG64 range = GetUnnamedArgU64(1);

	ExtRemoteData base_data;
	ULONG64 query_data;
	CHAR buffer[128];
	ULONG ret_size = 0;
	ULONG64 displacement = 0;
	ULONG print_flag = 0;

	BOOL ignore_flag = HasCharArg('i');

	for (ULONG64 i = 0; i < range; i++) {
		base_data.Set(base_address + i * sizeof(PVOID), sizeof(PVOID));
		query_data = base_data.GetPtr();
		ret_size = 0;
		ZeroMemory(buffer, sizeof(buffer));
		print_flag = 0;

		if (SUCCEEDED(m_Symbols->GetNameByOffset(query_data, 
			buffer, 
			sizeof(buffer), 
			&ret_size, 
			&displacement))) {
				print_flag |= 1;
		}
		
		if (m_Data4->ReadUnicodeStringVirtual(query_data, 
			0x1000, 
			CP_ACP,
			buffer, 
			sizeof(buffer), 
			&ret_size) != E_INVALIDARG && 
			strlen(buffer) != 0 &&
			IsPrintAble(buffer, (ULONG)strlen(buffer))) {
				print_flag |= 2;
		}
		else if (m_Data4->ReadMultiByteStringVirtual(query_data, 
			0x1000, 
			buffer, 
			sizeof(buffer), 
			&ret_size) != E_INVALIDARG && 
			strlen(buffer) != 0 &&
			IsPrintAble(buffer, (ULONG)strlen(buffer))) {
				print_flag |= 4;
		}

		if (print_flag == 0) {
			if (!ignore_flag) {
				Dml("%p  %p\n", base_address + i * sizeof(PVOID), query_data);
			}
		}
		else {
			Dml("%p  %p", base_address + i * sizeof(PVOID), query_data);
			if (print_flag & 1) {
				Dml("  [S] %ly", query_data);
			}

			if (print_flag & 2) {
				Dml("  [U] \"%mu\"", query_data);
			}

			if (print_flag & 4) {
				Dml("  [A] \"%ma\"", query_data);
			}

			Dml("\n");
		}
	}
	
}

EXT_COMMAND(grep,
	"Search plain-text data sets for lines matching a regular expression.",
	"{{custom}}{{s: [/i] <Command> <Regexp> [<Lines>]}}{{l:<Command> - Windbg command to execute.\n"
	"<Regexp> - Regular expression to search.\n"
	"<Lines> - The number of lines to print.\n"
	"/a - Set aliases, like @#Grep_<result_index>_<group_index>\n"
	"/i - Make matches case-insensitive.\n"
	"/o - Omit output information.}}"
	)
{
	int argc = 0;
	LPCSTR cmd = GetRawArgStr();
	PCHAR* argv = WdbgCommandLineToArgv((PCHAR)cmd, &argc);
	if (argv == NULL) {
		Err("Failed to parse command line(0).\n");
		return;
	}

	if (argc < 2 || argc > 6) {
		Err("Failed to parse command line(1)\n");
		LocalFree(argv);
		return;
	}

	int print_lines = -1;
	BOOL case_insensitive = FALSE;
	BOOL omit_output = FALSE;
	BOOL set_alias = FALSE;
	LPCSTR cmd_text = NULL;
	LPCSTR pattern_text = NULL;
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "/i") == 0) {
			case_insensitive = TRUE;
		}
		else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "/o") == 0) {
			omit_output = TRUE;
		}
		else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "/a") == 0) {
			set_alias = TRUE;
		}
		else {
			if (cmd_text == NULL) {
				cmd_text = argv[i];
			}
			else if (pattern_text == NULL) {
				pattern_text = argv[i];
			}
			else if (print_lines == -1) {
				CHAR *end_pos = argv[i];
				print_lines = strtol(argv[i], &end_pos, 10);
				if (*end_pos != 0) {
					Err("Failed to parse print lines\n");
					LocalFree(argv);
					return;
				}
			}
			else {
				Err("Failed to parse command line(2)\n");
				LocalFree(argv);
				return;
			}
		}
	}

	if (cmd_text == NULL || pattern_text == NULL) {
		Err("Failed to parse command line(3)\n");
		LocalFree(argv);
		return;
	}

	if (print_lines < 1 || print_lines > 255) {
		print_lines = 1;
	}

	ExtCaptureOutputA capture_exec;
	capture_exec.Execute(cmd_text);
	LPCSTR out_text = capture_exec.GetTextNonNull();
	BOOL except_error = FALSE;
	std::tr1::cmatch result;
	LPCSTR cur_text = out_text;
	try {
		std::tr1::regex pattern(pattern_text, 
			case_insensitive ? std::tr1::regex::icase | std::tr1::regex::ECMAScript : std::tr1::regex::ECMAScript);

		ULONG count = 0;
		CHAR alias[64];
		while (std::tr1::regex_search(cur_text, result, pattern)) {
			count++;

			if (!omit_output) {
				std::string str = ReadLines(cur_text + result.position(0), print_lines);
				Dml("%Y{t}\n", str.c_str());
			}

			cur_text += result.position(0) + result.length();

			if (set_alias) {
				for (size_t i = 1; i < result.size(); i++) {
					sprintf_s(alias, 64, "@#Grep_%u_%u", count - 1, i - 1);
					m_Control2->SetTextReplacement(alias, result[i].str().c_str());
				}
			}
			
		}

		if (set_alias) {
			sprintf_s(alias, 64, "%u", count);
			m_Control2->SetTextReplacement("@#GrepCount", alias);
		}
		
	}
	catch (...) {
		except_error = TRUE;
	}
	
	if (except_error) {
		Err("Failed to parse regex.\n");
	}
	
	LocalFree(argv);
	
}

EXT_COMMAND(version,
	"Displays the version information for 0cchext.dll",
	NULL)
{
	CHAR filename[MAX_PATH];
	GetModuleFileNameA(ExtExtension::s_Module, filename, MAX_PATH);

	ULONG handle = 0;
	ULONG size = GetFileVersionInfoSizeA(filename, &handle);
	PVOID info = malloc(size);
	if (!GetFileVersionInfoA(filename, handle, size, info)) {
		free(info);
		return;
	}
	
	UINT len = 0;
	VS_FIXEDFILEINFO* vsfi = NULL;
	if (VerQueryValueA(info, "\\", (PVOID *)&vsfi, &len)) {
		Dml("0CCh Extension for Windbg\n"
			"Version: %u.%u.%u.%u\n"
			"Author:  nightxie\n"
			"For more information about 0CChExt,\n"
			"see the 0CCh website at <link cmd=\"!0cchext.url http://0cch.net\">http://0cch.net</link>.\n"
			"You can also enter the <link cmd=\"!0cchext.help\">!0cchext.help</link> to get help\n", 
			HIWORD(vsfi->dwFileVersionMS), LOWORD(vsfi->dwFileVersionMS),
			HIWORD(vsfi->dwFileVersionLS), LOWORD(vsfi->dwFileVersionLS));
	}
	else {
		Err("Failed to get version information.");
	}
	
	free(info);
}

EXT_COMMAND(url,
	"Open a URL in a default browser.",
	"{;x,r;url;The url of a website.}")
{
	ShellExecuteA(NULL, "open", GetUnnamedArgStr(0), NULL, NULL, SW_SHOWNORMAL);
}

EXT_COMMAND(favcmd,
	"Display the favorite debugger commands.(The config file is favcmd.ini)",
	"{;ed,o,d=8;Number;The number of the commands to display.}")
{
	size_t display_count = (size_t)GetUnnamedArgU64(0);
	
	CHAR filename[MAX_PATH];
	GetModuleFileNameA(ExtExtension::s_Module, filename, MAX_PATH);
	PathRemoveFileSpecA(filename);
	PathAppendA(filename, "favcmd.ini");

	if (!PathFileExistsA(filename)) {
		Err("Failed to open favcmd.ini.");
	}

	std::string file_data;
	if (!GetTxtFileDataA(filename, file_data)) {
		Err("Failed to read favcmd.ini.");
	}

	std::vector<std::string> str_vec;
	ReadLines(file_data.c_str(), str_vec);

	display_count = display_count < str_vec.size() ? display_count : str_vec.size();

	for (size_t i = 0; i < display_count; i++) {
		Dml("%u <link cmd=\"%s\">%s</link>\n", i, str_vec[i].c_str(), str_vec[i].c_str());
	}

	Dml("Display: %u    Total: %u", display_count, str_vec.size());
}