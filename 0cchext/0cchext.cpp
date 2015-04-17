#include "stdafx.h"
#include "0cchext.h"
#include "util.h"
#include "struct_script.h"
#include <engextcpp.hpp>
#include <regex>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <Shlwapi.h>
#include <Shellapi.h>
#include <WinInet.h>
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
	EXT_COMMAND_METHOD(dtx);
	EXT_COMMAND_METHOD(init_script_env);
	EXT_COMMAND_METHOD(autocmd);
	EXT_COMMAND_METHOD(pe_export);
	EXT_COMMAND_METHOD(pe_import);
	EXT_COMMAND_METHOD(logcmd);
	EXT_COMMAND_METHOD(google);
	EXT_COMMAND_METHOD(bing);

	virtual HRESULT Initialize(void);
	virtual void Uninitialize(void);

private:
	void PrintStruct(std::vector<StructInfo> &struct_array, const char * name, ULONG64 &addr, int level, int display_sublevel);
	ULONG GetAddressPtrSize();

	CComPtr<IDebugClient> log_client_;
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
	ExtRemoteData wnd_data(target_entry, GetAddressPtrSize());

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
		base_data.Set(base_address + i * GetAddressPtrSize(), GetAddressPtrSize());
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
				Dml("%p  %p  [D] ", base_address + i * GetAddressPtrSize(), query_data);
				for (int j = 0; j < (int)GetAddressPtrSize(); j++) {
					Dml("%c", ((CHAR *)&query_data)[j]);
				}

				Dml("\n");
			}
		}
		else {
			Dml("%p  %p", base_address + i * GetAddressPtrSize(), query_data);
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
				std::string str = ReadLines(out_text, cur_text + result.position(0), print_lines);
				Dml("%s\n", str.c_str());
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
		Err("Failed to open favcmd.ini.\n");
		return;
	}

	std::string file_data;
	if (!GetTxtFileDataA(filename, file_data)) {
		Err("Failed to read favcmd.ini.\n");
		return;
	}

	std::vector<std::string> str_vec;
	ReadLines(file_data.c_str(), str_vec);

	display_count = display_count < str_vec.size() ? display_count : str_vec.size();

	for (size_t i = 0; i < display_count; i++) {
		Dml("%u <link cmd=\"%s\">%s</link>\n", i, str_vec[i].c_str(), str_vec[i].c_str());
	}

	Dml("Display: %u    Total: %u\n", display_count, str_vec.size());
}


void EXT_CLASS::PrintStruct( std::vector<StructInfo> &struct_array, const char * name, ULONG64 &addr, int level, int display_sublevel )
{
	std::string struct_name(name);
	ULONG64 address = addr;
	size_t i;
	for (i = 0; i < struct_array.size(); i++) {
		if (_stricmp(struct_array[i].GetName().c_str(), struct_name.c_str()) == 0) {
			break;
		}
	}

	if (i == struct_array.size()) {
		Err("Failed to find structure in struct.ini. @(%s)", struct_name.c_str());
		return;
	}

	ULONG64 tmp_addr = address;
	for (int indent = 0; indent < level; indent++) {
		if (level <= display_sublevel) {
			Dml("  ");
		}
	}
	if (level <= display_sublevel) {
		Dml("STRUCT %s %p\n", struct_name.c_str(), address);
	}
	for (int j = 0; j < struct_array[i].GetCount(); j++) {
		std::string member_name;
		std::string member_type_name;
		LEX_TOKEN_TYPE member_type = TK_NULL;
		BOOL isptr = FALSE;
		int count = 0;
		if (struct_array[i].Get(j, member_name, member_type, isptr, member_type_name, count)) {
			if (count > 1) {
				char array_str[16];
				sprintf_s(array_str, 16, "[%u]", count);
				member_name += array_str;
			}
			for (int indent = 0; indent < level + 1; indent++) {
				if (level <= display_sublevel) {
					Dml("  ");
				}
			}
			if (level <= display_sublevel) {
				Dml("+%04X  %-14s - %-5s : ", (ULONG)(tmp_addr - address), 
					member_name.c_str(), isptr ? std::string(member_type_name + "*").c_str() : member_type_name.c_str());
			}
			for (int k = 0; k < count; k++) {
				switch (member_type) {
				case TK_TYPE_BYTE:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("0x%p \n", remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 1);
							tmp_addr++;
							if (level <= display_sublevel) {
								Dml("0x%02X \n", remote_data.GetUchar());
							}
						}
						
					}
					break;
				case TK_TYPE_WORD:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("0x%p \n", remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 2);
							tmp_addr += 2;
							if (level <= display_sublevel) {
								Dml("0x%04X \n", remote_data.GetUshort());
							}
						}
						
					}
					break;
				case TK_TYPE_DWORD:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("0x%p \n", remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 4);
							tmp_addr += 4;
							if (level <= display_sublevel) {
								Dml("0x%08X \n", remote_data.GetUlong());
							}
						}
						
					}
					break;
				case TK_TYPE_QWORD:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("0x%p \n", remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 8);
							tmp_addr += 8;
							if (level <= display_sublevel) {
								Dml("0x%016I64X \n", remote_data.GetUlong64());
							}
						}
						
					}
					break;
				case TK_TYPE_CHAR:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("<link cmd=\"da %p\">0x%p</link> \n", remote_data.GetPtr(), remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 1);
							tmp_addr += 1;
							if (level <= display_sublevel) {
								Dml("%c \n", remote_data.GetChar());
							}
						}
						
					}
					break;
				case TK_TYPE_WCHAR:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("<link cmd=\"du %p\">0x%p</link> \n", remote_data.GetPtr(), remote_data.GetPtr());
							}
						}
						else {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, 2);
							tmp_addr += 2;
							if (level <= display_sublevel) {
								Dml("%C \n", remote_data.GetShort());
							}
						}
						
					}
					break;
				case TK_TYPE_UDT:
					{
						if (isptr) {
							ExtRemoteData remote_data;
							remote_data.Set(tmp_addr, GetAddressPtrSize());
							tmp_addr += GetAddressPtrSize();
							if (level <= display_sublevel) {
								Dml("<link cmd=\"!0cchext.dtx %s %p\">0x%p</link> \n", 
									member_type_name.c_str(), remote_data.GetPtr(), remote_data.GetPtr());
							}
						}
						else {
							if (level <= display_sublevel) {
								Dml("0x%p \n", tmp_addr);
								PrintStruct(struct_array, member_type_name.c_str(), tmp_addr, level + 1, display_sublevel);
							}
						}
					}
					break;
				default:
					__debugbreak();
				}
			}
		}
	}

	addr = tmp_addr;
}


EXT_COMMAND(dtx,
	"Displays information about structures. (The config file is struct.ini)",
	"{r;ed,o;depth;Recursively dumps the subtype fields.}"
	"{l;b,o;List;List the structrues in the struct.ini}"
	"{a;ed,o;Array;Specifies the display number of structure.}"
	"{;s,o;Name;Specifies the name of a structure.}"
	"{;e,o;Address;Specifies the address of the structure to be displayed.}")
{
	CHAR filename[MAX_PATH];
	GetModuleFileNameA(ExtExtension::s_Module, filename, MAX_PATH);
	PathRemoveFileSpecA(filename);
	PathAppendA(filename, "struct.ini");

	if (!PathFileExistsA(filename)) {
		Err("Failed to open struct.ini.\n");
		return;
	}

	std::string file_data;
	if (!GetTxtFileDataA(filename, file_data)) {
		Err("Failed to read struct.ini.\n");
		return;
	}

	std::vector<StructInfo> struct_array;
	if (!ParseStructScript(file_data.c_str(), struct_array)) {
		Err("Failed to Parse struct.ini. @(%s)\n", GetErrorPosString());
		return;
	}

	if (HasCharArg('l')) {
		Dml("The structures in the struct.ini:\n");
		for (size_t i = 0; i < struct_array.size(); i++) {
			Dml("%u - %s\n", i, struct_array[i].GetName().c_str());
		}
	}
	else {
		ULONG64 addr = GetUnnamedArgU64(1);
		int array_number = 1;
		if (HasCharArg('a')) {
			array_number = (int)GetArgU64("a");
		}

		int display_sublevel = 0;
		if (HasCharArg('r')) {
			display_sublevel = (int)GetArgU64("r");
		}
		
		for (int i = 0; i < array_number; i++) {
			PrintStruct(struct_array, GetUnnamedArgStr(0), addr, 0, display_sublevel);
			Dml("\n");
		}
	}
}

EXT_COMMAND(init_script_env,
	"Initialize script environment.",
	"")
{
	ULONG platform_id;
	ULONG major;
	ULONG minor;
	CHAR service_pack_string[MAX_PATH];
	ULONG service_pack_string_used;
	ULONG service_pack_number;
	CHAR build_string[MAX_PATH];
	ULONG build_string_used;

	HRESULT hr = m_Control->GetSystemVersion(&platform_id, 
		&major, 
		&minor, 
		service_pack_string, 
		MAX_PATH, 
		&service_pack_string_used, 
		&service_pack_number, 
		build_string,
		MAX_PATH,
		&build_string_used);

	if (FAILED(hr)) {
		return;
	}

	CHAR buffer[64];
	sprintf_s(buffer, sizeof(buffer), "0n%u", platform_id);
	m_Control2->SetTextReplacement("@#NtPlatformId", buffer);

	sprintf_s(buffer, sizeof(buffer), "0n%u", major);
	m_Control2->SetTextReplacement("@#NtType", buffer);

	sprintf_s(buffer, sizeof(buffer), "0n%u", minor);
	m_Control2->SetTextReplacement("@#NtBuildNumber", buffer);

	sprintf_s(buffer, sizeof(buffer), "0n%u", service_pack_number);
	m_Control2->SetTextReplacement("@#NtServicePackNumber", buffer);

	m_Control2->SetTextReplacement("@#NtServicePackString", service_pack_string);

	m_Control2->SetTextReplacement("@#NtBuildString", build_string);

	hr = m_Control4->GetSystemVersionValues(&platform_id, &major, &minor, NULL, NULL);
	if (FAILED(hr)) {
		return;
	}

	sprintf_s(buffer, sizeof(buffer), "0n%u", major);
	m_Control2->SetTextReplacement("@#NtMajorVersion", buffer);

	sprintf_s(buffer, sizeof(buffer), "0n%u", minor);
	m_Control2->SetTextReplacement("@#NtMinorVersion", buffer);

	ULONG debugee_class;
	ULONG debugee_qualifier;
	hr = m_Control->GetDebuggeeType(&debugee_class, &debugee_qualifier);

	sprintf_s(buffer, sizeof(buffer), "0x%x", debugee_class);
	m_Control2->SetTextReplacement("@#DebugeeClass", buffer);

	sprintf_s(buffer, sizeof(buffer), "0x%x", debugee_qualifier);
	m_Control2->SetTextReplacement("@#DebugeeQualifier", buffer);
}

ULONG EXT_CLASS::GetAddressPtrSize()
{
	if (m_Control->IsPointer64Bit() == S_OK) {
		return 8;
	}
	else {
		return 4;
	}
}

EXT_COMMAND(autocmd,
	"Execute the debugger commands.(The config file is autocmd.ini)",
	"{v;b;Verbose mode;Show commands to client.}")
{
	bool verbose = HasArg("v");

	CHAR filename[MAX_PATH];
	GetModuleFileNameA(ExtExtension::s_Module, filename, MAX_PATH);
	PathRemoveFileSpecA(filename);
	PathAppendA(filename, "autocmd.ini");

	if (!PathFileExistsA(filename)) {
		Err("Failed to open autocmd.ini.\n");
		return;
	}

	std::string file_data;
	if (!GetTxtFileDataA(filename, file_data)) {
		Err("Failed to read autocmd.ini.\n");
		return;
	}

	std::vector<std::string> str_vec;
	ReadLines(file_data.c_str(), str_vec);
	std::string current_section_name;
	std::map<std::string, std::vector<std::string>> cmd_map;

	for (std::vector<std::string>::iterator it = str_vec.begin(); it != str_vec.end(); ++it) {
		if (it->empty()) {
			continue;
		}
		if ((*it)[0] == '[') {
			size_t pos = it->find(']');
			if (pos != std::string::npos) {
				current_section_name = it->substr(1, pos - 1);
				transform(current_section_name.begin(), current_section_name.end(), current_section_name.begin(), tolower);
				continue;
			}
		}
		
		cmd_map[current_section_name].push_back(*it);
	}

	CHAR execute_path[MAX_PATH] = {0};
	if (FAILED(m_System->GetCurrentProcessExecutableName(execute_path, MAX_PATH, NULL))) {
		Err("Failed to get execute path.\n");
		return;
	}

	_strlwr_s(execute_path, MAX_PATH);
	
	CHAR *execute_name = PathFindFileNameA(execute_path);
	if (execute_name == NULL) {
		Err("Failed to get execute name.\n");
		return;
	}

	ULONG execute_flags = DEBUG_EXECUTE_NO_REPEAT;
	if (verbose) {
		execute_flags |= DEBUG_EXECUTE_ECHO;
	}

	for (std::vector<std::string>::iterator it = cmd_map[execute_name].begin(); it != cmd_map[execute_name].end(); ++it) {
		m_Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, it->c_str(), execute_flags);
	}
}

typedef struct _FUNC_INFO
{
	PVOID address;
	std::string name;
} EXPORT_FUNC_INFO, IMPORT_FUNC_INFO;

EXT_COMMAND(pe_export,
	"Dump PE export functions",
	"{;ed;Address;Specifies the address of the module.}"
	"{;s;Pattern;Specifies the pattern.}"
	"{o;b;ordinal;Display function without name.}") 
{
	ULONG64 addr = GetUnnamedArgU64(0);
	PCSTR pattern = GetUnnamedArgStr(1);
	bool ordinal = HasArg("o");
	
	ExtRemoteData remote_data(addr, sizeof(IMAGE_DOS_HEADER));

	IMAGE_DOS_HEADER dos_header;
	remote_data.ReadBuffer(&dos_header, sizeof(dos_header), TRUE);

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		Err("Failed to get DOS signature.\n");
		return;
	}

	ULONG64 cur = addr + dos_header.e_lfanew;
	remote_data.Set(cur, sizeof(IMAGE_NT_HEADERS));

	IMAGE_NT_HEADERS nt_header;
	remote_data.ReadBuffer(&nt_header, sizeof(nt_header), TRUE);
	
	if (nt_header.Signature != IMAGE_NT_SIGNATURE) {
		Err("Failed to get NT signature.\n");
		return;
	}
	
	cur = addr + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	remote_data.Set(cur, sizeof(IMAGE_EXPORT_DIRECTORY));

	IMAGE_EXPORT_DIRECTORY dir;
	remote_data.ReadBuffer(&dir, sizeof(dir), TRUE);

	std::vector<EXPORT_FUNC_INFO> funcs_info;
	ULONG func_count = dir.NumberOfFunctions;
	cur = addr + dir.AddressOfFunctions;

	ULONG func_addr_array_size = func_count * sizeof(ULONG);
	remote_data.Set(cur, func_addr_array_size);

	ULONG *func_addr_array = (ULONG *)malloc(func_addr_array_size);
	if (func_addr_array == NULL) {
		Err("Failed to allocate functions address array.\n");
		return;
	}
	
	remote_data.ReadBuffer(func_addr_array, func_addr_array_size, TRUE);

	for (ULONG i = 0; i < func_count; i++) {
		EXPORT_FUNC_INFO info;
		info.address = (PUCHAR)addr + func_addr_array[i];
		funcs_info.push_back(info);
	}

	free(func_addr_array);

	ULONG name_count = dir.NumberOfNames;
	ULONG name_array_size = name_count * sizeof(ULONG);
	cur = addr + dir.AddressOfNames;
	remote_data.Set(cur, name_array_size);

	ULONG *name_array = (ULONG *)malloc(name_array_size);
	if (name_array == NULL) {
		Err("Failed to allocate name array.\n");
		return;
	}

	remote_data.ReadBuffer(name_array, name_array_size, TRUE);

	ULONG name_id_size = name_count * sizeof(USHORT);
	cur = addr + dir.AddressOfNameOrdinals;
	remote_data.Set(cur, name_id_size);

	USHORT *name_id_array = (USHORT *)malloc(name_id_size);
	if (name_id_array == NULL) {
		Err("Failed to allocate name id array.\n");
		return;
	}

	remote_data.ReadBuffer(name_id_array, name_id_size, TRUE);
	
	for (ULONG i = 0; i < name_count; i++) {
		ExtBuffer<char> func_name;
		remote_data.Set(addr + name_array[i], 1024);
		remote_data.GetString(&func_name);
		USHORT func_id = name_id_array[i];
		funcs_info[func_id].name = func_name.GetBuffer();
	}

	free(name_array);
	free(name_id_array);

	
	Out("ID   Address   Export Name    Symbol Name\n");
	for (size_t i = 0; i < funcs_info.size(); i++) {
		if (ordinal) {
			if (funcs_info[i].name.empty()) {
				Out("%04X %p  N/A  %y\n", i, (ULONG64)funcs_info[i].address, (ULONG64)funcs_info[i].address);
			}
			
		}
		else {
			if (MatchPattern(funcs_info[i].name.c_str(), pattern)) {
				Out("%04X %p  %s  %y\n", i, (ULONG64)funcs_info[i].address, funcs_info[i].name.c_str(), (ULONG64)funcs_info[i].address);
			}
		}
		
	}
}

EXT_COMMAND(pe_import,
	"Dump PE import modules and functions",
	"{;ed;Address;Specifies the address of the module.}"
	"{f;s;Pattern;Specifies the pattern.}"
	) 
{
	ULONG64 addr = GetUnnamedArgU64(0);
	LPCSTR pattern = NULL;
	if (HasArg("f")) {
		pattern = GetArgStr("f");
	}
	
	ExtRemoteData remote_data(addr, sizeof(IMAGE_DOS_HEADER));

	IMAGE_DOS_HEADER dos_header;
	remote_data.ReadBuffer(&dos_header, sizeof(dos_header), TRUE);

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		Err("Failed to get DOS signature.\n");
		return;
	}

	ULONG64 cur = addr + dos_header.e_lfanew;
	remote_data.Set(cur, sizeof(IMAGE_NT_HEADERS));

	IMAGE_NT_HEADERS nt_header;
	remote_data.ReadBuffer(&nt_header, sizeof(nt_header), TRUE);

	if (nt_header.Signature != IMAGE_NT_SIGNATURE) {
		Err("Failed to get NT signature.\n");
		return;
	}

	cur = addr + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ULONG64 cur_dir = cur;
	remote_data.Set(cur_dir, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	IMAGE_IMPORT_DESCRIPTOR dir;
	remote_data.ReadBuffer(&dir, sizeof(dir), TRUE);

	std::map<std::string, std::vector<IMPORT_FUNC_INFO>> func_map;

	for (;;) {
		if (dir.Name == 0) {
			break;
		}

		std::vector<IMPORT_FUNC_INFO> funcs_info;

		ExtBuffer<char> module_name;
		remote_data.Set(addr + dir.Name, 1024);
		remote_data.GetString(&module_name);

		ULONG64 cur_thunk = addr + dir.FirstThunk;
		ULONG64 cur_ori_thunk = addr + dir.OriginalFirstThunk;
		
		IMAGE_THUNK_DATA thunk_data;
		IMAGE_THUNK_DATA ori_thunk_data;

		remote_data.Set(cur_thunk, sizeof(IMAGE_THUNK_DATA));
		remote_data.ReadBuffer(&thunk_data, sizeof(thunk_data), TRUE);
		remote_data.Set(cur_ori_thunk, sizeof(IMAGE_THUNK_DATA));
		remote_data.ReadBuffer(&ori_thunk_data, sizeof(ori_thunk_data), TRUE);

		for (;;) {
			if (thunk_data.u1.Function == NULL) {
				break;
			}

			IMPORT_FUNC_INFO func_info;
			func_info.address = (PVOID)thunk_data.u1.Function;

			if (IMAGE_SNAP_BY_ORDINAL(ori_thunk_data.u1.AddressOfData)) {
				char ordinal[64];
				sprintf_s(ordinal, "%04X", IMAGE_ORDINAL(ori_thunk_data.u1.AddressOfData));
				func_info.name = ordinal;
			}
			else {
				remote_data.Set(addr + ori_thunk_data.u1.AddressOfData + sizeof(USHORT), 1024);
				ExtBuffer<char> func_name;
				remote_data.GetString(&func_name);
				func_info.name = func_name.GetBuffer();
			}

			funcs_info.push_back(func_info);

			cur_thunk += sizeof(IMAGE_THUNK_DATA);
			cur_ori_thunk += sizeof(IMAGE_THUNK_DATA);
			remote_data.Set(cur_thunk, sizeof(IMAGE_THUNK_DATA));
			remote_data.ReadBuffer(&thunk_data, sizeof(thunk_data), TRUE);
			remote_data.Set(cur_ori_thunk, sizeof(IMAGE_THUNK_DATA));
			remote_data.ReadBuffer(&ori_thunk_data, sizeof(ori_thunk_data), TRUE);
		}

		func_map[module_name.GetBuffer()] = funcs_info;

		cur_dir += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		remote_data.Set(cur_dir, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		remote_data.ReadBuffer(&dir, sizeof(dir), TRUE);
	}
	
	for (std::map<std::string, std::vector<IMPORT_FUNC_INFO>>::iterator it = func_map.begin(); it != func_map.end(); ++it) {
		Dml("%s  <link cmd=\"lmva %p;!lmi %p\">(detail)</link>\n", it->first.c_str(), addr, addr);
		if (pattern != NULL) {
			for (size_t i = 0; i < it->second.size(); i++) {
				if (MatchPattern(it->second[i].name.c_str(), pattern)) {
					Out("%04X  %p  %s  %y\n", i, (ULONG64)it->second[i].address, it->second[i].name.c_str(), (ULONG64)it->second[i].address);
				}
			}

			Out("\n");
		}
		
	}
}



class LogDebugOutputCallbacks : public IDebugOutputCallbacks2 {
public:
	LogDebugOutputCallbacks() : cmd_log_file_(0) {}
	~LogDebugOutputCallbacks() {}

	virtual HRESULT __stdcall QueryInterface(REFIID InterfaceId, PVOID *Interface)
	{
		*Interface = NULL;

		if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) || IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks))) {
			*Interface = (IDebugOutputCallbacks *)this;
			AddRef();
			return S_OK;
		}
		// 		else if (IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks2))) {
		// 			*Interface = (IDebugOutputCallbacks2 *)this;
		// 			AddRef();
		// 			return S_OK;
		// 		}
		else {
			return E_NOINTERFACE;
		}
	}

	virtual ULONG __stdcall AddRef() {
		return 1;
	}

	virtual ULONG __stdcall Release() {
		return 0;
	}

	virtual HRESULT __stdcall Output(ULONG Mask, PCSTR Text)
	{
		if (Mask == DEBUG_OUTPUT_PROMPT) {
			const CHAR *pos = strchr(Text, ' ');
			if (pos != NULL) {
				WriteCmdLog((LPSTR)pos + 1);
			}
		}

		return S_OK;
	}

	virtual HRESULT __stdcall GetInterestMask(PULONG Mask)
	{
		return S_OK;
	}

	virtual HRESULT __stdcall Output2(__in ULONG Which,
		ULONG Flags,
		ULONG64 Arg,
		PCWSTR Text)
	{
		return S_OK;
	}

	BOOL CreateCmdLogFile(LPCSTR file_path) 
	{
		CloseCmdLogFile();
		cmd_log_file_ = CreateFileA(file_path, 
			GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_ALWAYS, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);

		return cmd_log_file_ != INVALID_HANDLE_VALUE;
	}

	void CloseCmdLogFile()
	{
		if (cmd_log_file_ != NULL) {
			CloseHandle(cmd_log_file_);
			cmd_log_file_ = NULL;
		}
	}

	void ClearCmdLogFile()
	{
		if (cmd_log_file_ != NULL) {
			SetFilePointer(cmd_log_file_, 0, 0, FILE_BEGIN);
			SetEndOfFile(cmd_log_file_);
		}
	}

	BOOL WriteCmdLog(LPSTR log_str)
	{
		if (cmd_log_file_ == NULL || log_str == NULL || log_str[0] == '\0') {
			return FALSE;
		}

		if (_strnicmp(log_str, "!logcmd", 7) == 0) {
			return FALSE;
		}

		int log_str_length = (int)strlen(log_str);
		for (int i = 0; i < log_str_length; i++) {
			if (log_str[i] == '\r' || log_str[i] == '\n' || log_str[i] == '\t') {
				log_str[i] = ' ';
			}
		}

		for (int i = log_str_length - 1; i >= 0; i--) {
			if (log_str[i] == ' ') {
				log_str[i] = '\0';
			}
			else {
				break;
			}
		}

		if (last_command_ == log_str) {
			return FALSE;
		}

		log_str_length = (int)strlen(log_str);

		last_command_ = log_str;

		SetFilePointer(cmd_log_file_, 0, 0, FILE_END);
		ULONG return_length = 0;
		return WriteFile(cmd_log_file_, log_str, log_str_length + 1, &return_length, NULL);
	}

	BOOL ReadCmdLog(std::vector<std::string> &log_items)
	{
		if (cmd_log_file_ == NULL) {
			return FALSE;
		}

		ULONG log_size = GetFileSize(cmd_log_file_, NULL);
		if (log_size == 0) {
			return FALSE;
		}

		SetFilePointer(cmd_log_file_, 0, 0, FILE_BEGIN);

		CHAR *log_buffer = (CHAR *)malloc(log_size);
		if (log_buffer == NULL) {
			return FALSE;
		}

		ULONG return_length = 0;
		if (!ReadFile(cmd_log_file_, log_buffer, log_size, &return_length, NULL)) {
			free(log_buffer);
			return FALSE;
		}

		for (CHAR *cur = log_buffer; cur < log_buffer + log_size;) {
			if (*cur == '\0') {
				break;
			}

			log_items.push_back(cur);
			cur += strlen(cur) + 1;
		}


		free(log_buffer);
		return TRUE;
	}

private:
	HANDLE cmd_log_file_;
	std::string last_command_;
};

LogDebugOutputCallbacks g_log_callback;
PDEBUG_OUTPUT_CALLBACKS g_original_output_callback = NULL;

template<typename T>
int replace_all(T& str,  const T& pattern,  const T& newpat)
{
	int count = 0;
	const size_t nsize = newpat.size();
	const size_t psize = pattern.size();

	for (size_t pos = str.find(pattern, 0);  pos != T::npos; pos = str.find(pattern, pos + nsize)) {
		str.replace(pos, psize, newpat);
		count++;
	}

	return count; 
}

void HandleDmlEscape(std::string &s)
{
	replace_all<std::string>(s, "&", "&amp;");
	replace_all<std::string>(s, "<", "&lt;");
	replace_all<std::string>(s, ">", "&gt;");
	replace_all<std::string>(s, "\"", "&quot;");
}

EXT_COMMAND(logcmd,
	"Log command line to log file",
	"{i;x;Log path;Install command log.}"
	"{u;b;Uninstall;Uninstall command log.}"
	"{d;b;Delete;Delete repeat command log.}"
	"{c;b;Clear;Clear command log.}"
	"{;e,d=10;Number;The number of command to be displayed}"
	"{;s,d=*;Pattern;Specifies the pattern.}")
{
	std::vector<std::string> log_items;

	if (HasArg("u")) {
		g_log_callback.CloseCmdLogFile();
		return;
	}
	else if (HasArg("d")) {
		if (!g_log_callback.ReadCmdLog(log_items)) {
			Err("Failed to get commands.\n");
			return;
		}

		std::set<std::string> log_set;
		for (std::vector<std::string>::iterator it = log_items.begin();
			it != log_items.end(); ++it) {
				log_set.insert(*it);
		}

		g_log_callback.ClearCmdLogFile();
		for (std::set<std::string>::iterator it = log_set.begin();
			it != log_set.end(); ++it) {
			g_log_callback.WriteCmdLog((LPSTR)it->c_str());	
		}

		return;
	}
	else if (HasArg("c")) {
		g_log_callback.ClearCmdLogFile();
		return;
	}
	else if (HasArg("i")) {
		
		LPCSTR log_file_path = GetArgStr("i");
		if (!g_log_callback.CreateCmdLogFile(log_file_path)) {
			Err("Failed to open log file.\n");
		}
		return;
	}

	size_t cmd_number = (size_t)GetUnnamedArgU64(0);
	if (!g_log_callback.ReadCmdLog(log_items)) {
		Err("Failed to get commands.\n");
		return;
	}

	for (size_t i = log_items.size() > cmd_number ? log_items.size() - cmd_number : 0, j = 0; i < log_items.size(); i++) {
		if (MatchPattern(log_items[i].c_str(), GetUnnamedArgStr(1))) {
			HandleDmlEscape(log_items[i]);
			Dml("<link cmd=\"%s\">%u</link> %s\n", log_items[i].c_str(), j++, log_items[i].c_str());
		}
	}
}

EXT_COMMAND(google,
	"Use google to search.",
	"{;x;Key;Specifies the key word.}") 
{
	char url[INTERNET_MAX_URL_LENGTH] = "https://www.google.com/#q=";
	if (GetNumUnnamedArgs() >= 1) {
		PCSTR key_word = GetUnnamedArgStr(0);
		strcat_s(url, key_word);
	}
	
	ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
}

EXT_COMMAND(bing,
	"Use bing to search.",
	"{;x;Key;Specifies the key word.}") 
{
	char url[INTERNET_MAX_URL_LENGTH] = "http://global.bing.com/search?q=";
	if (GetNumUnnamedArgs() >= 1) {
		PCSTR key_word = GetUnnamedArgStr(0);
		strcat_s(url, key_word);
	}

	ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
}


HRESULT EXT_CLASS::Initialize( void )
{
	if (SUCCEEDED(DebugCreate(__uuidof(IDebugClient), (VOID **)&log_client_))) {
		if (SUCCEEDED(log_client_->GetOutputCallbacks(&g_original_output_callback))) {
			log_client_->SetOutputCallbacks((PDEBUG_OUTPUT_CALLBACKS)&g_log_callback);
		}
	}

	return S_OK;
}

void EXT_CLASS::Uninitialize( void )
{
	log_client_->SetOutputCallbacks((PDEBUG_OUTPUT_CALLBACKS)g_original_output_callback);
	g_original_output_callback = NULL;
	g_log_callback.CloseCmdLogFile();

	__super::Uninitialize();
}
