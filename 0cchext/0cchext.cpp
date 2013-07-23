#include "stdafx.h"
#include "0cchext.h"
#include <engextcpp.hpp>

class EXT_CLASS : public ExtExtension
{
public:
	EXT_COMMAND_METHOD(hwnd);
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