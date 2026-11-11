# WinDbg and cdb triage patterns

## Establish the session

- Confirm whether the session is user-mode or kernel-mode.
- Confirm dump versus live target.
- Match debugger, extension, and MCP architecture.
- Run `.symfix` and `.reload` when symbols are not already configured.
- Prefer `windbg.snapshot` before issuing investigative commands.

## User-mode crash or dump

Typical read-only sequence:

```text
.ecxr
!analyze -v
r
k
lm
u <faulting-address>
```

Then follow the evidence:

- access violation: inspect the faulting address, pointer validity, allocation lifetime, and nearby object fields
- stack corruption: compare stack ranges, frame pointers, and return addresses
- heap issue: inspect `!heap` output and allocation ownership before changing state
- PE or export/import issue: inspect module bases and image headers
- managed/native boundary: identify the runtime and load the appropriate extension/symbols before interpreting frames

## Live user-mode target

Use breakpoints deliberately:

```text
bp <module>!<function>
g
k
r
```

After the breakpoint hits, read only the arguments and memory needed for the current hypothesis. Remove temporary breakpoints with `bc` when done.

For scripted single-instruction assembly, `0cchext` provides `!a` and `!a64`. Prefer the structured MCP assembly/execute path when it is available.

## Kernel crash or live kernel

Typical read-only sequence:

```text
!analyze -v
!process 0 0
!thread
!irp
!pool
lm
```

Use `!process`/`!thread` to establish context before inspecting object or pool state. Kernel targets often require symbols and careful address-width handling; never infer an x64 object layout from an x86 dump.

## cdb command-line

Examples:

```text
cdb -z C:\crashes\app.dmp -c ".symfix;.reload;!analyze -v;q"
cdb -p 1234
```

For MCP, keep cdb sessions alive through the sidecar instead of launching a new one for every command.

## Common mistakes

- Treating a nearest symbol as proof of the actual function.
- Interpreting a reconstructed stack as complete execution history.
- Continuing a target before preserving evidence.
- Mixing x86 and x64 extensions.
- Running an interactive command such as `!a64` or `!luadbg.luacmd` in a non-interactive tool call without a termination strategy.
- Using `windbg.execute` for a result already available from a structured tool.
