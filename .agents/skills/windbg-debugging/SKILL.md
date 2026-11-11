---
name: windbg-debugging
description: Diagnose Windows user-mode or kernel targets, crash dumps, live processes, and WinDbg/cdb sessions using 0cchext MCP tools and structured debugger workflows.
---

# WinDbg Debugging

Use this skill when a task involves WinDbg, cdb, a Windows crash dump, a live Windows process, extension commands, breakpoints, stack analysis, memory inspection, or the `0cchext-agent` MCP server.

## Choose the interface

1. Prefer the `0cchext-agent` MCP tools when available. They return structured data and avoid console parsing.
2. Use `windbg.execute` only for commands or extension features not exposed by a structured tool.
3. If MCP is unavailable, load `0cchext.dll` into WinDbg/cdb and use `!0cchext.agent capabilities` to discover the supported surface.

Session setup examples and tool schemas are in [references/mcp-tools.md](references/mcp-tools.md).

## Operating rules

- Identify the target type first: live user-mode process, process dump, kernel target, or kernel dump.
- Match the debugger, extension DLL, and MCP executable architecture. Do not load an x64 DLL into an x86 debugger or the reverse.
- Establish symbols before interpreting addresses. State whether symbols are loaded, partial, or unavailable.
- Start with read-only tools: `windbg.status`, `windbg.snapshot`, `windbg.stack`, `windbg.modules`, `windbg.read_memory`, and `windbg.symbol`.
- Do not continue or mutate a target unless the user explicitly wants that action. `windbg.execute` can run arbitrary debugger commands, including commands that modify the target.
- Treat `windbg.continue` as an external side effect. Set a timeout and stop on unexpected target behavior.
- Do not infer that a missing symbol means a function is absent. Check module load state, symbol path, architecture, and whether the address is inside a mapped image.
- Keep large reads bounded. Prefer targeted reads and pagination over dumping whole address spaces into the conversation.

## Debugging workflow

1. Capture context with `windbg.status` or `windbg.snapshot`.
2. Confirm architecture, process/thread, execution state, exception/event, and loaded modules.
3. Resolve the faulting address with `windbg.symbol` and inspect the relevant stack with `windbg.stack`.
4. Read only the memory needed to test a hypothesis.
5. Use `windbg.execute` for symbol, type, heap, pool, PE, or extension commands that have no structured tool.
6. After any mutation, re-read the relevant registers, memory, or state and report the observable difference.

For common triage sequences, kernel/user-mode distinctions, and command selection, see [references/debugging-patterns.md](references/debugging-patterns.md).

## Reporting

Report:

- target type and architecture
- symbol state
- evidence from stack, registers, modules, and memory
- whether any target state was changed
- the next command or experiment, with its risk level

Separate observed facts from hypotheses. Never present a reconstructed call stack as a complete execution history.
