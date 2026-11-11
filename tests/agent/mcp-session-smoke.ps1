param(
    [Parameter(Mandatory = $true)]
    [string]$AgentExe
)

$ErrorActionPreference = "Stop"
$request = @"
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"windbg.snapshot","arguments":{"register_limit":2,"module_limit":2,"stack_limit":2}}}
"@

$responses = $request | & $AgentExe --create "cmd.exe /c exit" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "0cchext-agent stopped with code $LASTEXITCODE"
}
$snapshotLine = @($responses | Where-Object { $_ -match '"id":2' }) | Select-Object -First 1
if (-not $snapshotLine) {
    throw "No snapshot response was returned."
}
$snapshot = $snapshotLine | ConvertFrom-Json
if ($snapshot.result.isError) {
    throw "windbg.snapshot returned an error."
}
$text = $snapshot.result.content[0].text | ConvertFrom-Json
if (-not $text.ok -or $text.data.status.data.architecture -ne "x64" -and $text.data.status.data.architecture -ne "x86") {
    throw "Snapshot did not contain a valid debugger status."
}

Write-Output "agent MCP session smoke passed"
