param(
    [Parameter(Mandatory = $true)]
    [string]$AgentExe
)

$ErrorActionPreference = "Stop"
$request = @"
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"windbg.status","arguments":{}}}
"@

$responses = $request | & $AgentExe 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "0cchext-agent exited with code $LASTEXITCODE"
}

$jsonLines = @($responses | Where-Object { $_ -match '^\s*\{' })
if ($jsonLines.Count -lt 2) {
    throw "0cchext-agent did not return the expected JSON-RPC responses."
}

$initialize = $jsonLines[0] | ConvertFrom-Json
$tools = $jsonLines[1] | ConvertFrom-Json
if ($initialize.result.serverInfo.name -ne "0cchext-agent") {
    throw "Unexpected MCP server identity."
}
$toolNames = @($tools.result.tools | ForEach-Object { $_.name })
foreach ($required in @("windbg.snapshot", "windbg.read_memory", "windbg.execute")) {
    if ($toolNames -notcontains $required) {
        throw "Missing MCP tool: $required"
    }
}

Write-Output "agent MCP smoke passed"
