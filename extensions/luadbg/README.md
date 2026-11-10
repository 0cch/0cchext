# luadbg

Lua 5.4 automation for WinDbg and `cdb`, built as part of the [0CCh WinDbg Extension](../../README.md).

![luadbg screenshot](https://0cch.com/uploads/2016/11/20161116113129.png)

## Install

Use the `luadbg.dll` matching the debugger architecture:

```text
.load "C:\path\to\0cchext\x64\luadbg.dll"
```

## Commands

```text
!luadbg.lua <file>
!luadbg.luacmd
!luadbg.luaload <file>
!luadbg.lualist
!luadbg.luaunload <name>
!luadbg.luado <script-name>!<code>
```

`!luadbg.luacmd` enters interactive Lua command mode; type `quit()` to exit. See the [command reference](../../docs/COMMANDS.md#luadbg-commands) for examples.

## Build

Build instructions and the dependency policy are in the [build guide](../../docs/BUILD.md). The extension uses Lua 5.4.9 and the same static CRT and architecture settings as `0cchext.dll`.

## License

GPL-3.0. See [LICENSE](LICENSE).
