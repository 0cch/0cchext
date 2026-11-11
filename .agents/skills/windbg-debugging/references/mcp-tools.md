# 0cchext MCP tools

## Start the server

The MCP server is the console executable `0cchext-agent.exe`. It uses newline-delimited JSON-RPC over stdio.

```text
# Create/debug a process
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --create "C:\target\app.exe"

# Attach to a process
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --attach 1234

# Open a dump
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --dump "C:\crashes\app.dmp"
```

The extension is optional for native DbgEng tools, but is required for `0cchext` commands executed through `windbg.execute`.

## Tools

| Tool | Use |
|---|---|
| `windbg.status` | Debugger state, target type, process/thread, last event |
| `windbg.snapshot` | Compact status, registers, modules, and stack |
| `windbg.registers` | Current thread register values |
| `windbg.modules` | Loaded module names and bases |
| `windbg.stack` | Symbol-resolved current-thread stack |
| `windbg.read_memory` | Hex and printable ASCII for a bounded memory range |
| `windbg.symbol` | Nearest symbol for an address |
| `windbg.evaluate` | Evaluate a WinDbg expression |
| `windbg.execute` | Execute a WinDbg/cdb command and return captured output |
| `windbg.continue` | Continue until an event or timeout |
| `windbg.open_dump` | Open a dump after the server starts |
| `windbg.attach` | Attach to a process after the server starts |
| `windbg.create` | Create a debug target after the server starts |
| `windbg.load_extension` | Load a debugger extension DLL |

## Example initialize/tool flow

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"windbg.snapshot","arguments":{"register_limit":32,"module_limit":128,"stack_limit":32}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"windbg.symbol","arguments":{"address":"0x00007ffd932a26c9"}}}
```

MCP tool results contain one text item whose text is JSON. Parse the text item as JSON rather than treating it as a human-readable table.

## Extension discovery

Inside an existing WinDbg/cdb session:

```text
.load "C:\tools\0cchext\x64\0cchext.dll"
!0cchext.agent capabilities
!0cchext.agent status
```

The `!` command name is `agent`; `capabilities` and `status` are subcommands. Do not use `!0cchext.agent.capabilities` as a WinDbg command name.

## Safety

- `windbg.execute` can run arbitrary commands and may modify the target.
- `windbg.continue` changes target execution state.
- Require explicit user intent before executing breakpoint changes, memory writes, register writes, module loads, or continuation.
- Use `timeout_ms` for continuation and stop if the target does not return to a stopped state.
