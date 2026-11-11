# Agent Integration

`0cchext-agent.exe` is a native DbgEng-based MCP stdio server for AI agents. It keeps a debugger session open and exposes structured tools instead of requiring an agent to parse WinDbg console text.

## Start a session

```text
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --create "C:\target\app.exe"
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --attach 1234
0cchext-agent.exe --extension "C:\tools\0cchext\x64\0cchext.dll" --dump "C:\crashes\app.dmp"
```

Use the architecture that matches the debugger and target.

## MCP transport

The server uses newline-delimited JSON-RPC 2.0 over stdin/stdout. It supports the standard MCP methods:

- `initialize`
- `notifications/initialized`
- `ping`
- `tools/list`
- `tools/call`
- `shutdown`

Tool calls return a text content item containing a JSON object. Agents should parse that JSON instead of parsing the surrounding MCP envelope.

## Tools

| Tool | Description |
|---|---|
| `windbg.status` | Current target and debugger state |
| `windbg.snapshot` | Status, registers, modules, and stack in one bounded result |
| `windbg.registers` | Current thread registers |
| `windbg.modules` | Loaded modules and bases |
| `windbg.stack` | Symbol-resolved current-thread stack |
| `windbg.read_memory` | Bounded memory read with hex and ASCII |
| `windbg.symbol` | Resolve an address to the nearest symbol |
| `windbg.evaluate` | Evaluate a WinDbg expression |
| `windbg.execute` | Execute a debugger command and capture output |
| `windbg.continue` | Continue with a timeout |
| `windbg.open_dump` | Open a dump after startup |
| `windbg.attach` | Attach after startup |
| `windbg.create` | Create a target after startup |
| `windbg.load_extension` | Load an extension DLL |

## MCP client configuration

Example configuration ([agent/mcp.example.json](../agent/mcp.example.json)):

```json
{
  "mcpServers": {
    "0cchext": {
      "command": "C:\\tools\\0cchext\\x64\\0cchext-agent.exe",
      "args": [
        "--extension",
        "C:\\tools\\0cchext\\x64\\0cchext.dll",
        "--create",
        "C:\\target\\app.exe"
      ]
    }
  }
}
```

For a live process, replace `--create ...` with `--attach 1234`. For a dump, use `--dump C:\\crashes\\app.dmp`.

## Extension discovery

Inside WinDbg or cdb:

```text
.load "C:\tools\0cchext\x64\0cchext.dll"
!0cchext.agent capabilities
!0cchext.agent status
```

`capabilities` and `status` are subcommands of `!0cchext.agent`. WinDbg's dot is the module/command separator; do not use `!0cchext.agent.capabilities` as a command.

## Safety

`windbg.execute` can run arbitrary debugger commands. Mutating operations such as memory writes, register writes, breakpoint changes, and continuation should only be performed with explicit user intent. Use bounded reads and continuation timeouts.

The project skill for agents is at [.agents/skills/windbg-debugging/SKILL.md](../.agents/skills/windbg-debugging/SKILL.md).
