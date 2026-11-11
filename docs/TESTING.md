# Testing

## Unit tests

```powershell
ctest --preset vs2022-x64-release-tests --output-on-failure
ctest --preset vs2022-x86-release-tests --output-on-failure
```

Current unit tests cover:

- command-line/text utility behavior
- URL component encoding
- MCP stdio protocol and tool discovery (`agent_mcp`)
- x86/x64 assembler regressions for `nop`, `mov`, `xor`, `push`, memory operands, branches, AVX-512, `lock` prefixes, and invalid input

## CDB smoke tests

The integration smoke test loads both extensions into `cdb.exe` and checks:

- `0cchext.dll` loads
- `!0cchext.version`
- `!0cchext.diag`
- `!0cchext.grep -F`
- `luadbg.dll` loads
- Lua file execution
- Lua load/list/unload lifecycle
- Lua syntax-error recovery without dangling state
- Lua cyclic-table listing remains bounded

Run manually:

```powershell
./tests/integration/cdb-smoke.ps1 `
  -Architecture x64 `
  -BuildDirectory "$PWD/build/x64/bin"
```

If `cdb.exe` is not installed, the script exits successfully with a warning so
the unit tests still run in environments without Debugging Tools.

## Future integration coverage

- malformed PE export/import tables
- truncated HTTP symbol downloads
- rawpcap start/stop lifecycle
- WMI array values
- logcmd file truncation and recovery
- larger Lua memory objects and error recovery
