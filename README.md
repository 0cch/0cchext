0CCh Windbg extension
=======
Author: nightxie
site:   http://0cch.com

[![Build status](https://ci.appveyor.com/api/projects/status/lum8m63fig6bk94x?svg=true)](https://ci.appveyor.com/project/0cch/0cchext)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/0cch/0cchext/blob/master/LICENSE)
[![Language](https://img.shields.io/badge/language-C++-red.svg)](https://github.com/0cch/0cchext/blob/master/README.md)

### Usage
```
Commands for 0cchext.dll:
  !a               - Assembles instruction mnemonics and puts the resulting
                     instruction codes into memory.
  !accessmask      - Interpret ACCESS MASK value
  !addmodule       - Adds a synthetic module to the module list the debugger
                     maintains for the current process.
  !addsymbol       - Adds a synthetic symbol to a module in the current
                     process.
  !autocmd         - Execute the debugger commands.(The config file is
                     autocmd.ini)
  !bing            - Use bing to search.
  !carray          - Show data in C array style.
  !cppexcrname     - Print cpp exception name.
  !dlsym           - Download symbol by path.
  !dpx             - Display the contents of memory in the given range.
  !dttoc           - Translate 'dt' command output text to C struct.
  !dtx             - Displays information about structures. (The config file is
                     struct.ini)
  !du8             - Display UTF-8 string.
  !err             - Decodes and displays information about an error value.
  !favcmd          - Display the favorite debugger commands.(The config file is
                     favcmd.ini)
  !filepath        - Show file path by handle.
  !google          - Use google to search.
  !grep            - Search plain-text data sets for lines matching a regular
                     expression.
  !gt              - Go and interrupted after a period of time (ms).
  !help            - Displays information on available extension commands
  !hwnd            - Show window information by handle.
  !import_vs_bps   - Import visual studio breakpoints.
  !init_script_env - Initialize script environment.
  !listmodule      - List the synthetic modules.
  !listsymbol      - List the synthetic symbols.
  !logcmd          - Log command line to log file
  !memstat         - Statistics virtual memory allocation.
  !oledata         - Print tagSOleTlsData.
  !pe_export       - Dump PE export functions
  !pe_import       - Dump PE import modules and functions
  !rawpcap_start   - Start to capture IP packet. (requires administrative
                     privileges)
  !rawpcap_stop    - Stop capturing. (requires administrative privileges)
  !removemodule    - removes a synthetic module from the module list the
                     debugger maintains for the current process.
  !removesymbol    - Specifies the synthetic symbol to remove.
  !rr              - Read registers and show the information.
  !setdlsympath    - Set download symbol path.
  !setvprot        - Set the protection on a region of committed pages in the
                     virtual address space of the debuggee process.
  !stackstat       - Statistics duplicate stack data.
  !threadname      - List thread name.
  !traceclear      - Clear trace event.
  !traceclose      - Close a trace event.
  !tracecreate     - Create a trace event.
  !tracedisplay    - Display trace event.
  !url             - Open a URL in a default browser.
  !version         - Displays the version information for 0cchext.dll
  !wql             - Query system information with WMI.
!help <cmd> will give more information for a particular command

```

### Detail

----------------------------

[Chinese version](http://0cch.com/debugging/2015/10/06/0cchext.html)

----------------------------

#### !a
>  !a               - Assembles instruction mnemonics and puts the resulting
                     instruction codes into memory.

 This command assembles instruction mnemonics and puts the resulting instruction codes into memory. although Windbg has its own command 'a', but the command can not use with script. Once you enter the command 'a', Windbg will enter assembly mode,  then you can not let the script continue. So I developed '!a', the command will be assembled for a single command, and the next addresse will be stored in @#LastAsmAddr, and then execute the following commands immediately.

For example, the following script can inject DLLinto the debuggee.
```
ad /q ${/v:alloc_addr}
ad /q ${/v:@#LastAsmAddr}
x kernel32!LoadlibraryA
.foreach /pS 5 (alloc_addr {.dvalloc 0x200}) {r $.u0 = alloc_addr}
.block {aS ${/v:@#LastAsmAddr} 0; !a $u0 pushfd};
.block {!a ${@#LastAsmAddr} pushad}
.block {!a ${@#LastAsmAddr} push 0x$u0+0x100}
.block {!a ${@#LastAsmAddr} call kernel32!LoadLibraryA}
.block {!a ${@#LastAsmAddr} popad}
.block {!a ${@#LastAsmAddr} popfd}
.block { eza 0x$u0+0x100 "${$arg1}"}
r @$t0=@eip
r @eip=$u0
.block {g ${@#LastAsmAddr}}
r @eip=@$t0
.dvfree 0x$u0 0
```

----------------------------------

#### !autocmd
> !autocmd         - Execute the debugger commands.(The config file is
                     autocmd.ini)

This command execute other commands automatically. Sometimes I want to attach the debugger to process or run a program with debugger, then execute a series of commands. Although this may be performed by the script, but still too complex for me. So I can use this command. create autocmd.ini file at 0cchext.dll directory, , and then enter the following text:

```
[all]
? 88 * 66

[kernel]
!process 0 0 explorer.exe

[kernel dump]
!analyze -v

[notepad.exe]
.sympath+ c:\notepad_pdb
~*k

[calc.exe]
.sympath+ c:\calc_pdb
~*k

[calc.exe dump]
.excr

```

So, '!autocmd' can execute commands for different process. 

-----------------------------

#### !bing & !google
> !bing            - Use bing to search.
> !google          - Use google to search.

This command is very simple, just use bing and google to search for a specified string.

---------------------------------

#### !favcmd
> !favcmd           - Display the favorite debugger commands.(The config file is
                     favcmd.ini)

This command is simple, just put your favorite commands in favcmd.ini file, which must in the 0cchext.dll directory.  This command will put your favorite commands on Windbg, you can use the mouse to select commands to execute.

For example:
>~*k
!address
!heap

[![20151005162754](http://0cch.com/uploads/2015/10/20151005162754.png)](/uploads/2015/10/20151005162754.png)

------------------------------

#### !hwnd
> !hwnd            - Show window information by handle.

This command is very simple, you can enter the window handle as a parameter, view window information in kernel debugging. 

-------------------------------

#### !url
> !url             - Open a URL in a default browser.

This command opens a url, just call ShellExecute. Windbg already has '.shell' command, so this seems to be a little superfluous.

----------------------------

#### !init_script_env
> !init_script_env - Initialize script environment.

This command help the script to determine the system environment. 

[![20151005163744](http://0cch.com/uploads/2015/10/20151005163744.png)](/uploads/2015/10/20151005163744.png)

---------------------------

#### !import_vs_bps
> !import_vs_bps   - Import visual studio breakpoints.

This command transfer breakpoints from VS to Windbg. 

For example:

>!import_vs_bps c:\proj\xxx.suo

---------------------------

#### !setvprot
> !setvprot        - Set the protection on a region of committed pages in the
                     virtual address space of the debuggee process.

This command can set debuggee memory access protection. You can use it to simulate Ollydbg memory breakpoint. Set a target memory to PAGE_GUARD, so debugger can catch an exception when debuggee access this address.

For example:

>!setvprot 0x410000 0x1000 0x100

---------------------------

#### !pe_export & !pe_import
> !pe_export       - Dump PE export functions
> !pe_import       - Dump PE import modules and functions

These two command can help us view the export and import functions, and they all support wildcard.  Using parameter / b and .foreach commands, you can play your debugger like an API monitor.

For example:

>.foreach( place  { !pe_export /b kernel32 \*Create\* } ) { bp place "g" }

-----------------------------

#### !wql
> !wql             - Query system information with WMI.

This is one of my favorite features, it can query system information with WMI.
 
```
0:000> !0cchext.wql select * from win32_process where name="explorer.exe"
-------------------------------------------------------------
  Caption                                   local       CIM_STRING  explorer.exe
  CommandLine                               local       CIM_STRING  C:\Windows\Explorer.EXE
  CreationClassName                         local       CIM_STRING  Win32_Process
  CreationDate                              local       CIM_DATETIME  2015-09-17 09:41:53.959
  CSCreationClassName                       local       CIM_STRING  Win32_ComputerSystem
  ...
  ...
  ThreadCount                               local       CIM_UINT32  40
  UserModeTime                              local       CIM_UINT64  605439881
  VirtualSize                               local       CIM_UINT64  435580928
  WindowsVersion                            local       CIM_STRING  6.1.7601
  WorkingSetSize                            local       CIM_UINT64  109813760
  WriteOperationCount                       local       CIM_UINT64  399
  WriteTransferCount                        local       CIM_UINT64  1545945
-------------------------------------------------------------

```

--------------------

#### !logcmd
> !logcmd          - Log command line to log file

This command can log debug command to a file, so we can use the command next time when we debug something.

[![20151005170422](http://0cch.com/uploads/2015/10/20151005170422.png)](/uploads/2015/10/20151005170422.png)

----------------------

#### !dpx
>!dpx             - Display the contents of memory in the given range.

This command merged 'dps' 'dpa' and 'dpu' commands. 

```
0:000> !dpx esp 100
00c3f28c  7605cb33  [S] USER32!GetMessageA+0x53 (7605cb33)
...
00c3f2b4  012b6ca9  [S] usbview!WinMain+0xe3 (012b6ca9)
...
00c3f2f4  012ce723  [S] usbview!WinMainCRTStartup+0x151 (012ce723)
00c3f2f8  01260000  [S] usbview!__guard_check_icall_fptr <PERF> (usbview+0x0) 
...
00c3f320  01025618  [A] "Winsta0\Default"
00c3f324  01025640  [A] "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\usbview.exe"
00c3f328  00000000  [D] ....
```

-----------------------

#### !dtx
> !dtx             - Displays information about structures. (The config file is
                     struct.ini)

This command is a reverse engineering command. Because we cannot load symbols when we reverse something. In IDA, we can set structures to help us analyze code. But in Windbg, there is no command can help us do the same thing. So I develop this command to solve this problem. We can write the structure to the struct.ini file, then print memory data by this command. Of course, this file must be in 0cchext.dll directory.

[![20151005172455](http://0cch.com/uploads/2015/10/20151005172455.png)](/uploads/2015/10/20151005172455.png)

the script parser supports some basic types like BYTE WORD DWORD QWORD CHAR WCHAR, it also supports arrays, pointers and  nested structure.

#### !filepath
> !filepath        - Show file path by handle.

This command can help us check the path of file handle that !handle cannot.

```
0:000> !handle 1c
Handle 1c
  Type         	File
0:000> !handle 1c f
Handle 1c
  Type         	File
  Attributes   	0
  GrantedAccess	0x100020:
         Synch
         Execute/Traverse
  HandleCount  	2
  PointerCount 	3
  No Object Specific Information available
  
0:000> .load 0cchext.dll
0:000> !filepath 1c
   \\?\D:\Program Files (x86)\Windows Kits\10\Debuggers

```

#### !stackstat
> !stackstat       - Statistics duplicate stack data.

This command can statistic duplicate stack data, this is useful for troubleshooting thread leak.

```

0:000:x86> !stackstat
Duplicate threads stack:

0:	Count = 1
	4(25e0) 

1:	Count = 1
	0(25b4) 

2:	Count = 7
	9(188c) 11(27d0) 13(460) 67(279c) 72(1d90) 73(21c8) 1384(b74) 

3:	Count = 6
	74(13e4) 75(d28) 76(1e20) 77(1f4c) 78(14c0) 79(18ac) 

4:	Count = 3
	6(24dc) 51(54c) 56(d54) 

5:	Count = 7
	7(ec4) 8(1d20) 10(194c) 12(16b0) 66(1a50) 70(1c08) 71(1120) 

...

18:	Count = 1296
	83(2030) 84(1bfc) 85(1348) 86(1ea8) 87(1e7c) 88(1510) 89(1484) 90(14d4) 91(f44) 92(1768) 93(1ecc) 94(174c) 95(1758) 96(1b88) 97(1ce0) 98(4dc) 99(1bb0) 100(1354) ... ... 1329(1368) 1330(1dd8) 1331(a50) ... ... 1368(145c) 1369(1078) 1370(22a8) 1371(13e8) 1372(1f74) 1373(e68) 1374(24c8) 1375(144c) 1376(1d48) 1377(1cf4) 1378(12a0) 1383(1cd0) 

19:	Count = 1
	16(1aec) 

...

```

#### !memstat
> !memstat       - Statistics virtual memory allocation.

This command can statistic virtual memory leak.

```
0:000:x86> !memstat
Size              Count     State     Protect   Type
0000000000104000       619  00001000  00000004  00020000
0000000000004000       345  00001000  00000004  00020000
0000000000011000       281  00001000  00000004  00020000
0000000000003000       109  00001000  00000004  00020000
0000000000001000       103  00001000  00000002  01000000
0000000000039000        99  00002000  00000000  00020000
0000000000003000        99  00001000  00000104  00020000
0000000000002000        92  00001000  00000104  00020000
0000000000005000        89  00001000  00000004  00020000
00000000000fa000        86  00002000  00000000  00020000
0000000000001000        82  00001000  00000004  01000000
0000000000006000        40  00001000  00000004  00020000
0000000000002000        39  00001000  00000002  01000000
0000000000001000        29  00001000  00000008  01000000
0000000000007000        27  00001000  00000004  00020000
0000000000001000        26  00001000  00000004  00020000
0000000000008000        23  00001000  00000004  00020000
...
```
#### !tracecreate !traceclose !tracedisplat !traceclear
> !tracecreate     - Create a trace event.
> !traceclose      - Close a trace event.
> !tracecreate     - Create a trace event.
> !tracedisplay    - Display trace event.

This command can trace object with custom keys.

```
0:000> bp kernelbase!CreateFileW "gu; !tracecreate @eax; gc"
0:000> bp kernelbase!CloseHandle "!traceclose poi(@esp+4); gc"
0:000> g
...
0:023> !tracedisplay
Count = 10    KeyCount = 0    
00 kernel32!CreateFileWImplementation+0x69
01 thumbcache!QueryStreamForUnderlyingMapping+0xcc
02 thumbcache!CThumbnailCacheDataFile::_OpenFileAndMapping+0x21
03 thumbcache!CThumbnailCache::_OpenCacheFiles+0x73
04 thumbcache!CThumbnailCache::_Initialize+0x9d
05 thumbcache!CThumbnailCache::GetThumbnail+0xfd
06 SHELL32!CThumbnailCacheLookupTask::_Lookup+0xd0
07 SHELL32!CThumbnailCacheLookupTask::InternalResumeRT+0x57
08 SHELL32!CRunnableTask::Run+0xce
09 SHELL32!CShellTask::TT_Run+0x167
...

Count = 6    KeyCount = 0    
00 kernel32!CreateFileWImplementation+0x69
WARNING: Stack unwind information not available. Following frames may be wrong.
01 TortoiseSVN32+0x229f4
02 TortoiseSVN32+0x22ae5
03 TortoiseSVN32+0x22d67
04 TortoiseSVN32+0x2216d
05 TortoiseSVN32+0x21c59
06 TortoiseOverlays+0x1723
07 SHELL32!CFSIconOverlayManager::_GetFileOverlayInfo+0x11a
08 SHELL32!CFSIconOverlayManager::GetFileOverlayInfo+0x1b
09 SHELL32!CFSFolder::_GetOverlayInfo+0x10f
0a SHELL32!CFSFolder::GetOverlayIndex+0x28
0b SearchFolder!CDBFolder::GetOverlayIndex+0x47
...

Count = 5    KeyCount = 0    
00 kernel32!CreateFileWImplementation+0x69
01 thumbcache!QueryStreamForUnderlyingMapping+0xcc
02 thumbcache!CThumbnailCacheDataFile::_OpenFileAndMapping+0x21
03 thumbcache!CThumbnailCache::_OpenCacheFiles+0x73
04 thumbcache!CThumbnailCache::_Initialize+0x9d
05 thumbcache!CThumbnailCache::PageInThumbnail+0x50
06 SHELL32!CImageManager::PageInThumbnail+0x7e
07 explorerframe!CFirstPageResults::_EnumerateCollection+0x526
08 explorerframe!CFirstPageResults::RunBackgroundEnumeration+0x87
09 explorerframe!CFirstPageTask::InternalResumeRT+0x10
0a explorerframe!CRunnableTask::Run+0xce
0b SHELL32!CShellTask::TT_Run+0x167
0c SHELL32!CShellTaskThread::ThreadProc+0xa3
0d SHELL32!CShellTaskThread::s_ThreadProc+0x1b
0e SHLWAPI!ExecuteWorkItemThreadProc+0xe
0f ntdll!RtlpTpWorkCallback+0x11d
10 ntdll!TppWorkerThread+0x562
11 kernel32!BaseThreadInitThunk+0xe
12 ntdll!__RtlUserThreadStart+0x70
13 ntdll!_RtlUserThreadStart+0x1b
...
...
```

#### !setdlsympath
> !setdlsympath    - Set download symbol path.

Set download symbol path and use !dlsym to download symbol.

```

0:000> !setdlsympath D:\newsym

```


#### !dlsym
> !dlsym           - Download symbol by path.

Download symbol by EXE or DLL file path. We can set timeout timer and number of retries. Since microsoft public symbol server is not stable, windbg download symbol always fails. So I just write a downloader command, and we can set a long timeout timer to make the download symbol more stable.

```

0:000> !dlsym /t 10000 /r 10 /p 123.123.123.12:8888 C:\Windows\syswow64\kernel32.dll
Download url  : http://msdl.microsoft.com/download/symbols/wkernel32.pdb/AB6B617AB7E1496AB63555DEBF8A91B12/wkernel32.pd_
Download path : D:\newsym\wkernel32.pdb\AB6B617AB7E1496AB63555DEBF8A91B12\wkernel32.pd_
4096/670972 (0%)
8192/670972 (1%)
12288/670972 (1%)
16384/670972 (2%)
...
...
655360/670972 (97%)
659456/670972 (98%)
663552/670972 (98%)
667648/670972 (99%)
670972/670972 (100%)
Download D:\newsym\wkernel32.pdb\AB6B617AB7E1496AB63555DEBF8A91B12\wkernel32.pdb finish.

```

#### !threadname
> !threadname      - List thread name.

When you are debugging an application with multiple threads it can be handy to have a better name than just the thread id. In VS Debugger we can get the thread name, but I cannot find a command to list thread name in Windbg.

```cpp

//  
// Usage: SetThreadName ((DWORD)-1, "MainThread");  
//  
#include <windows.h>  
const DWORD MS_VC_EXCEPTION = 0x406D1388;  
#pragma pack(push,8)  
typedef struct tagTHREADNAME_INFO  
{  
    DWORD dwType; // Must be 0x1000.  
    LPCSTR szName; // Pointer to name (in user addr space).  
    DWORD dwThreadID; // Thread ID (-1=caller thread).  
    DWORD dwFlags; // Reserved for future use, must be zero.  
 } THREADNAME_INFO;  
#pragma pack(pop)  
void SetThreadName(DWORD dwThreadID, const char* threadName) {  
    THREADNAME_INFO info;  
    info.dwType = 0x1000;  
    info.szName = threadName;  
    info.dwThreadID = dwThreadID;  
    info.dwFlags = 0;  
#pragma warning(push)  
#pragma warning(disable: 6320 6322)  
    __try{  
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);  
    }  
    __except (EXCEPTION_EXECUTE_HANDLER){  
    }  
#pragma warning(pop)  
}  

```

```

0:000> !threadname
Thread id   Name
000014D8    MainThread

```


#### !carray
> !carray          - Show data in C array style.

Output data as C array. For some reason, I need read some data in the memory (e.g. some encrypted data) and translate to C array.

```

0:000> !carray 0029f694 38
const unsigned char buffer[0x38] = {
	0x94, 0xfe, 0x11, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xfd, 0xff, 
	0x7c, 0xf8, 0x29, 0x00, 0x94, 0xf6, 0x29, 0x00, 0x14, 0xc8, 0xb7, 0x01, 0x7c, 0xf8, 0x29, 0x00, 
	0xc5, 0x58, 0x94, 0x77, 0xcc, 0xb6, 0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3c, 0xf8, 0x29, 0x00, 
	0xc7, 0x0f, 0x95, 0x77, 0x00, 0xd0, 0xfd, 0xff };

```

#### !rawpcap_start
> !rawpcap_start   - Start to capture IP packet. (requires administrative privileges)

Capture IP packet and write the data to a pcap file format.

```

!rawpcap_start 192.168.34.186 d:\test.pcap

```

#### !rawpcap_stop
> !rawpcap_stop    - Stop capturing. (requires administrative privileges)


#### !dttoc
> !dttoc           - Translate 'dt' command output text to C struct.  
```
0:000> !0cchext.dttoc nt!_peb
struct _PEB {
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	union {
		BYTE BitField;
		struct {
			BYTE ImageUsesLargePages:1;
			BYTE IsProtectedProcess:1;
			BYTE IsImageDynamicallyRelocated:1;
			BYTE SkipPatchingUser32Forwarders:1;
			BYTE IsPackagedProcess:1;
			BYTE IsAppContainer:1;
			BYTE IsProtectedProcessLight:1;
			BYTE IsLongPathAwareProcess:1;
		};
	};
	VOID* Mutant;
	VOID* ImageBaseAddress;
	_PEB_LDR_DATA* Ldr;
	_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	VOID* SubSystemData;
	VOID* ProcessHeap;
	_RTL_CRITICAL_SECTION* FastPebLock;
	_SLIST_HEADER* AtlThunkSListPtr;
	VOID* IFEOKey;
	union {
		DWORD CrossProcessFlags;
		struct {
			DWORD ProcessInJob:1;
			DWORD ProcessInitializing:1;
			DWORD ProcessUsingVEH:1;
			DWORD ProcessUsingVCH:1;
			DWORD ProcessUsingFTH:1;
			DWORD ReservedBits0:27;
		};
	};
	union {
		VOID* KernelCallbackTable;
		VOID* UserSharedInfoPtr;
	};
	DWORD SystemReserved[1];
	_SLIST_HEADER* AtlThunkSListPtr32;
	VOID* ApiSetMap;
	DWORD TlsExpansionCounter;
	VOID* TlsBitmap;
	DWORD TlsBitmapBits[2];
	VOID* ReadOnlySharedMemoryBase;
	VOID* SparePvoid0;
	VOID** ReadOnlyStaticServerData;
	VOID* AnsiCodePageData;
	VOID* OemCodePageData;
	VOID* UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	DWORD NtGlobalFlag;
	_LARGE_INTEGER CriticalSectionTimeout;
	DWORD HeapSegmentReserve;
	DWORD HeapSegmentCommit;
	DWORD HeapDeCommitTotalFreeThreshold;
	DWORD HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	VOID* GdiSharedHandleTable;
	VOID* ProcessStarterHelper;
	DWORD GdiDCAttributeList;
	_RTL_CRITICAL_SECTION* LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	DWORD ImageSubsystemMinorVersion;
	DWORD ActiveProcessAffinityMask;
	DWORD GdiHandleBuffer[34];
	void* PostProcessInitRoutine;
	VOID* TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	DWORD SessionId;
	_ULARGE_INTEGER AppCompatFlags;
	_ULARGE_INTEGER AppCompatFlagsUser;
	VOID* pShimData;
	VOID* AppCompatInfo;
	_UNICODE_STRING CSDVersion;
	_ACTIVATION_CONTEXT_DATA* ActivationContextData;
	_ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	_ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	_ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	DWORD MinimumStackCommit;
	_FLS_CALLBACK_INFO* FlsCallback;
	_LIST_ENTRY FlsListHead;
	VOID* FlsBitmap;
	DWORD FlsBitmapBits[4];
	DWORD FlsHighIndex;
	VOID* WerRegistrationData;
	VOID* WerShipAssertPtr;
	VOID* pUnused;
	VOID* pImageHeaderHash;
	union {
		DWORD TracingFlags;
		struct {
			QWORD HeapTracingEnabled:1;
			QWORD CritSecTracingEnabled:1;
			QWORD LibLoaderTracingEnabled:1;
			QWORD SpareTracingBits:29;
		};
	};
	QWORD CsrServerReadOnlySharedMemoryBase;
	DWORD TppWorkerpListLock;
	_LIST_ENTRY TppWorkerpList;
	VOID* WaitOnAddressHashTable[128];
};
```

#### !rr
> !rr              - Read registers and show the information.  

```
0:000> !0cchext.rr
rax  0000000000000001  [D] ........
rbx  000000000018ef28  [D] (.......
rcx  000000000000020f  [D] ........
rdx  0000000000000000  [D] ........
rsi  0000000000000fff  [D] ........
rdi  000007fef8401e50  [D] P.@.....  [S] mscoreei!XMLParserShimFileStream::Read (000007fe`f8401e50)
rip  000007fef8401e80  [D] ..@.....  [S] mscoreei!XMLParserShimFileStream::Read+0x34 (000007fe`f8401e80)
rsp  000000000018ee50  [D] P.......
rbp  000000000018eed0  [D] ........  [U] ")"
 r8  000000000018ed88  [D] ........
 r9  000000000018eed0  [D] ........  [U] "yi)"
r10  0000000000000000  [D] ........
r11  0000000000000246  [D] F.......
r12  0000000000000000  [D] ........
r13  000000000018ef58  [D] X.......
r14  0000000000299890  [D] ..).....
r15  0000000000000fff  [D] ........
```

#### !du8
>  !du8            - Display UTF-8 string.

```
0:000> da 0x61ed08 
0061ed08  "............"
0:000> du 0x61ed08 
0061ed08  "뷤.붥룤.貕"
0:000> !du8 0x61ed08 
0061ed08  你好世界
```

#### !accessmask
>  !accessmask     - Interpret ACCESS MASK value

```
0:000> !accessmask process 0x1fffff
Access mask: 0x1fffff

Generic rights:
STANDARD_RIGHTS_READ          	(0x20000)
STANDARD_RIGHTS_WRITE         	(0x20000)
STANDARD_RIGHTS_EXECUTE       	(0x20000)
STANDARD_RIGHTS_REQUIRED      	(0xf0000)
STANDARD_RIGHTS_ALL           	(0x1f0000)
READ_CONTROL                  	(0x20000)
DELETE                        	(0x10000)
SYNCHRONIZE                   	(0x100000)
WRITE_DAC                     	(0x40000)
WRITE_OWNER                   	(0x80000)

Specific rights:
PROCESS_QUERY_LIMITED_INFORMATION	(0x1000)
PROCESS_SUSPEND_RESUME        	(0x800)
PROCESS_QUERY_INFORMATION     	(0x400)
PROCESS_SET_INFORMATION       	(0x200)
PROCESS_SET_QUOTA             	(0x100)
PROCESS_CREATE_PROCESS        	(0x80)
PROCESS_DUP_HANDLE            	(0x40)
PROCESS_VM_WRITE              	(0x20)
PROCESS_VM_READ               	(0x10)
PROCESS_VM_OPERATION          	(0x8)
PROCESS_CREATE_THREAD         	(0x2)
PROCESS_TERMINATE             	(0x1)
PROCESS_ALL_ACCESS            	(0x1fffff)

```

#### !oledata
>  !oledata        - Print tagSOleTlsData.

```
0:000> !oledata
dt combase!tagSOleTlsData 0x0000019370ad0360
dx (combase!tagSOleTlsData *)0x0000019370ad0360
0:000> dt combase!tagSOleTlsData 0x0000019370ad0360
   +0x000 pvThreadBase     : (null) 
   +0x008 pSmAllocator     : (null) 
   +0x010 dwApartmentID    : 0x1e3d4
   +0x014 dwFlags          : 0x81
   +0x018 TlsMapIndex      : 0n0
   +0x020 ppTlsSlot        : 0x00000018`66fc9758  -> 0x00000193`70ad0360 Void
   +0x028 cComInits        : 3
   +0x02c cOleInits        : 0
   +0x030 cCalls           : 0
   ...
```

#### !cppexcrname
>  !cppexcrname    - Print cpp exception name.

```
0:000> .exr -1
ExceptionAddress: 74e61812 (KERNELBASE!RaiseException+0x00000062)
   ExceptionCode: e06d7363 (C++ EH exception)
  ExceptionFlags: 00000001
NumberParameters: 3
   Parameter[0]: 19930520
   Parameter[1]: 006ff46c
   Parameter[2]: 00372294
0:000> !cppexcrname
Exception name: .?AVexception@std@@
```

#### !gt
>  !gt             - Go and interrupted after a period of time (ms).

```
0:004> .time;!gt 0n1000;.time
Debug session time: Thu Apr 15 15:09:44.839 2021 (UTC + 8:00)
System Uptime: 20 days 2:53:31.728
Process Uptime: 0 days 0:10:23.148
  Kernel time: 0 days 0:00:00.015
  User time: 0 days 0:00:00.000
(af7c.490c): Break instruction exception - code 80000003 (first chance)
Debug session time: Thu Apr 15 15:09:45.846 2021 (UTC + 8:00)
System Uptime: 20 days 2:53:32.735
Process Uptime: 0 days 0:10:24.155
  Kernel time: 0 days 0:00:00.015
  User time: 0 days 0:00:00.000

* Capture a dump every second for 10 seconds
.for(r $t0 = 0; $t0 < 0n10; r $t0 = $t0 + 1) {!0cchext.gt 0n1000 -c .dump /u f:\test.dump;}
```