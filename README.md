# 0CCh WinDbg Extension

[![CI](https://github.com/0cch/0cchext/actions/workflows/ci.yml/badge.svg)](https://github.com/0cch/0cchext/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0cch/0cchext?display_name=tag&sort=semver)](https://github.com/0cch/0cchext/releases/latest)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/0cch/0cchext/blob/master/LICENSE)
[![Platform](https://img.shields.io/badge/platform-WinDbg%20%7C%20cdb%20%7C%20x86%20%7C%20x64-lightgrey.svg)](https://github.com/0cch/0cchext)
[![Stars](https://img.shields.io/github/stars/0cch/0cchext?style=social)](https://github.com/0cch/0cchext/stargazers)

`0cchext` is a practical extension pack for WinDbg and `cdb`. It adds script-friendly assembly, memory and process inspection, PE/symbol tooling, workflow helpers, and an optional Lua runtime to the debugger.

**Keywords:** WinDbg extension, cdb extension, Windows debugging, reverse engineering, x64 assembler, PE inspection, Lua automation.

The repository produces two extensions:

- `0cchext.dll` — the main extension
- `luadbg.dll` — an optional Lua 5.4 extension

## Why use it?

- **Script-friendly assembly**: `!a` and `!a64` assemble a single instruction without entering WinDbg's interactive assembly mode.
- **Modern instruction support**: the default backend uses Intel XED 2026, including AVX-512 and `lock` encodings.
- **Focused commands**: inspect memory, stacks, threads, PE images, import/export tables, handles, errors, and WMI data.
- **Workflow helpers**: run command queues, import Visual Studio breakpoints, log commands, search output, and create trace events.
- **Lua automation**: load reusable scripts with `luadbg.dll` and keep script state isolated from the main extension.
- **Reproducible builds**: pinned dependencies, static CRT, CMake presets, unit tests, and cdb smoke tests.

## Install

1. Download the latest release from [GitHub Releases](https://github.com/0cch/0cchext/releases/latest).
2. Choose the directory matching the debugger architecture:
   - `x64` for the 64-bit WinDbg or `cdb`
   - `x86` for the 32-bit WinDbg or `cdb`
3. Load the extension in the debugger:

```text
.load "C:\path\to\0cchext\x64\0cchext.dll"
!0cchext.version
!0cchext.diag
!0cchext.help
```

The debugger architecture and extension architecture must match. To use Lua:

```text
.load "C:\path\to\0cchext\x64\luadbg.dll"
!luadbg.lua C:\debug\hello.lua
!luadbg.lualist
```

## Quick start

### Assemble one instruction

```text
0:000> !a @rsp push rbp
0:000> !a @rsp mov rax, rbx
```

`!a64` is the interactive 64-bit assembler mode:

```text
0:000> !a64 @rsp
00000000`0012ff00  vaddps zmm0, zmm1, zmm2
  = 62 f1 74 48 58 c2
```

### Inspect the current state

```text
!carray @rsp 64
!stackstat
!memstat
!threadname
!0cchext.diag
```

### Work with PE images and symbols

```text
!pe_export <module-base>
!pe_import <module-base>
!filepath <handle>
!listsymbol
!listmodule
```

### Query and automate

```text
!wql "SELECT Name, ProcessId FROM Win32_Process"
!grep -i "!analyze -v" ".+Exception.+"
!url https://learn.microsoft.com/windows-hardware/drivers/debugger/
```

Use `!0cchext.help <command>` for command-specific syntax. The full command index and examples are in [docs/COMMANDS.md](docs/COMMANDS.md).

## Command overview

| Area | Commands |
|---|---|
| Assembly and data | `!a`, `!a64`, `!carray`, `!dpx`, `!du8`, `!rr`, `!accessmask`, `!dtx` |
| Diagnostics and state | `!diag`, `!version`, `!memstat`, `!stackstat`, `!threadname`, `!filepath`, `!hwnd`, `!wql` |
| PE and symbols | `!pe_export`, `!pe_import`, `!addmodule`, `!listmodule`, `!addsymbol`, `!listsymbol`, `!dlsym` |
| Workflow | `!autocmd`, `!favcmd`, `!grep`, `!logcmd`, `!gt`, `!tracecreate`, `!traceclose`, `!tracedisplay` |
| Utilities | `!url`, `!google`, `!bing`, `!setvprot`, `!err`, `!dttoc`, `!rawpcap_start`, `!rawpcap_stop` |
| Lua | `!luadbg.lua`, `!luadbg.luacmd`, `!luadbg.luaload`, `!luadbg.lualist`, `!luadbg.luaunload`, `!luadbg.luado` |

## Lua extension

`luadbg.dll` provides:

- `!luadbg.lua <file>` — execute a Lua script
- `!luadbg.luacmd` — enter interactive Lua command mode (`quit()` exits)
- `!luadbg.luaload <file>` — load and retain a script state
- `!luadbg.lualist` — list retained scripts
- `!luadbg.luaunload <name>` — unload a retained script
- `!luadbg.luado <script-name>!<code>` — execute code inside a retained script state

`luadbg` is intentionally a separate DLL from `0cchext.dll`, so Lua failures and state do not destabilize the main extension.

See [extensions/luadbg/README.md](extensions/luadbg/README.md) for the standalone extension notes.

## Build from source

Requirements: Visual Studio 2022, CMake 3.25+, Windows SDK, and Python 3 for the default XED 2026 source build.

```powershell
cmake --preset vs2022-x64
cmake --build --preset vs2022-x64-relwithdebinfo --parallel 4
ctest --preset vs2022-x64-release-tests --output-on-failure
```

For x86:

```powershell
cmake --preset vs2022-x86
cmake --build --preset vs2022-x86-relwithdebinfo --parallel 4
ctest --preset vs2022-x86-release-tests --output-on-failure
```

See [docs/BUILD.md](docs/BUILD.md) for local build modes, dependency pinning, compatibility fallbacks, and CI simulation.

## Testing and releases

- Pull requests and manual dispatches run CI.
- Ordinary branch pushes do not run a workflow.
- Pushing a dotted numeric tag runs the release workflow, builds and tests both architectures, runs a cdb smoke test, and publishes a GitHub Release.
- `VERSION` is the local default version. A three-part tag such as `v1.20.3` automatically selects the next fourth component; a four-part tag is an exact override.

See [docs/TESTING.md](docs/TESTING.md) for the test matrix and manual smoke test.

## Project layout

```text
0cchext/          Main WinDbg extension sources
extensions/luadbg Optional Lua extension
compat/windbg/    EngExtCpp compatibility sources for CI
cmake/            Build integration and dependency pinning
docs/             User, build, command, and test documentation
tests/            Unit and cdb integration tests
scripts/          Release/version helpers
```

## Contributing

Issues and pull requests are welcome. Please include:

- the WinDbg/cdb architecture and version
- the command and exact output
- a minimal reproducer when possible
- test results for changes to commands or the assembler

If this project saves you debugging time, a star helps other reverse engineers find it.

## Links

- [Command Reference](docs/COMMANDS.md)
- [Build Guide](docs/BUILD.md)
- [Testing Guide](docs/TESTING.md)
- [Chinese introduction](http://0cch.com/debugging/2015/10/06/0cchext.html)
- [0CCh website](http://0cch.com)

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
