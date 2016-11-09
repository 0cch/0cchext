0CCh Windbg extension
=======
Author: nightxie
site:   http://0cch.com

[![Build status](https://ci.appveyor.com/api/projects/status/lum8m63fig6bk94x?svg=true)](https://ci.appveyor.com/project/0cch/0cchext)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/0cch/0cchext/blob/master/LICENSE)
[![Language](https://img.shields.io/badge/language-C++-red.svg)]()

### Usage
```
Commands for 0cchext.dll:
  !a               - Assembles instruction mnemonics and puts the resulting
                     instruction codes into memory.
  !addmodule       - Adds a synthetic module to the module list the debugger
                     maintains for the current process.
  !addsymbol       - Adds a synthetic symbol to a module in the current
                     process.
  !autocmd         - Execute the debugger commands.(The config file is
                     autocmd.ini)
  !bing            - Use bing to search.
  !dpx             - Display the contents of memory in the given range.
  !dtx             - Displays information about structures. (The config file is
                     struct.ini)
  !err             - Decodes and displays information about an error value.
  !favcmd          - Display the favorite debugger commands.(The config file is
                     favcmd.ini)
  !filepath        - Show file path by handle.
  !google          - Use google to search.
  !grep            - Search plain-text data sets for lines matching a regular
                     expression.
  !help            - Displays information on available extension commands
  !hwnd            - Show window information by handle.
  !import_vs_bps   - Import visual studio breakpoints.
  !init_script_env - Initialize script environment.
  !listmodule      - List the synthetic modules.
  !listsymbol      - List the synthetic symbols.
  !logcmd          - Log command line to log file
  !memstat         - Statistics virtual memory allocation.
  !pe_export       - Dump PE export functions
  !pe_import       - Dump PE import modules and functions
  !removemodule    - removes a synthetic module from the module list the
                     debugger maintains for the current process.
  !removesymbol    - Specifies the synthetic symbol to remove.
  !setvprot        - Set the protection on a region of committed pages in the
                     virtual address space of the debuggee process.
  !stackstat       - Statistics duplicate stack data.
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
[notepad.exe]
.sympath+ c:\notepad_pdb
~*k

[calc.exe]
.sympath+ c:\calc_pdb
~*k
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
