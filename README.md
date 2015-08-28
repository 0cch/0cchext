0CCh Windbg extension
=======
Author: nightxie
site:   http://0cch.com

[![Build status](https://ci.appveyor.com/api/projects/status/lum8m63fig6bk94x?svg=true)](https://ci.appveyor.com/project/0cch/0cchext)

### Usage
```
Commands for 0cchext.dll:
  !a               - Assembles instruction mnemonics and puts the resulting
                     instruction codes into memory.
  !autocmd         - Execute the debugger commands.(The config file is
                     autocmd.ini)
  !bing            - Use bing to search.
  !dpx             - Display the contents of memory in the given range.
  !dtx             - Displays information about structures. (The config file is
                     struct.ini)
  !favcmd          - Display the favorite debugger commands.(The config file is
                     favcmd.ini)
  !google          - Use google to search.
  !grep            - Search plain-text data sets for lines matching a regular
                     expression.
  !help            - Displays information on available extension commands
  !hwnd            - Show window information by handle.
  !import_vs_bps   - Import visual studio breakpoints.
  !init_script_env - Initialize script environment.
  !logcmd          - Log command line to log file
  !pe_export       - Dump PE export functions
  !pe_import       - Dump PE import modules and functions
  !setvprot        - Set the protection on a region of committed pages in the
                     virtual address space of the debuggee process.
  !url             - Open a URL in a default browser.
  !version         - Displays the version information for 0cchext.dll
!help <cmd> will give more information for a particular command
```
