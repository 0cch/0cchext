param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64")]
    [string]$Architecture,

    [Parameter(Mandatory = $true)]
    [string]$BuildDirectory
)

$ErrorActionPreference = "Stop"

$debuggerRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Debuggers"
$cdb = Join-Path $debuggerRoot "$Architecture\cdb.exe"
if (-not (Test-Path -LiteralPath $cdb)) {
    Write-Warning "cdb.exe was not found at $cdb; skipping integration smoke test."
    exit 0
}

$dll = Join-Path $BuildDirectory "0cchext.dll"
$luaDll = Join-Path $BuildDirectory "luadbg.dll"
if (-not (Test-Path -LiteralPath $dll)) {
    throw "0cchext.dll was not found at $dll"
}
if (-not (Test-Path -LiteralPath $luaDll)) {
    throw "luadbg.dll was not found at $luaDll"
}

$stackPointer = if ($Architecture -eq "x64") { "@rsp" } else { "@esp" }
$dllCommandPath = $dll.Replace("\", "/")
$luaDllCommandPath = $luaDll.Replace("\", "/")
$luaScript = Join-Path $env:TEMP ("0cchext-lua-" + [guid]::NewGuid().ToString("N") + ".lua")
Set-Content -Encoding ascii $luaScript "print('lua-smoke')"
$luaScriptCommandPath = $luaScript.Replace("\", "/")
$luaScriptName = [System.IO.Path]::GetFileNameWithoutExtension($luaScript)
$badLuaScript = Join-Path $env:TEMP ("0cchext-bad-lua-" + [guid]::NewGuid().ToString("N") + ".lua")
Set-Content -Encoding ascii $badLuaScript "function bad("
$badLuaScriptCommandPath = $badLuaScript.Replace("\", "/")
$cycleLuaScript = Join-Path $env:TEMP ("0cchext-cycle-lua-" + [guid]::NewGuid().ToString("N") + ".lua")
Set-Content -Encoding ascii $cycleLuaScript "cycle = {}; cycle.self = cycle"
$cycleLuaScriptCommandPath = $cycleLuaScript.Replace("\", "/")
$cycleLuaScriptName = [System.IO.Path]::GetFileNameWithoutExtension($cycleLuaScript)
$scriptPath = Join-Path $env:TEMP ("0cchext-cdb-" + [guid]::NewGuid().ToString("N") + ".txt")
$outputPath = Join-Path $env:TEMP ("0cchext-cdb-" + [guid]::NewGuid().ToString("N") + ".log")
@"
.load "$dllCommandPath"
!0cchext.version
!0cchext.diag
!0cchext.agent capabilities
!0cchext.agent status
!0cchext.grep -F lm cmd
!0cchext.accessmask process 0x1fffff
!0cchext.carray $stackPointer 16
!0cchext.stackstat -t 2
!0cchext.memstat -t 5
!0cchext.url ftp://example.com
.load "$luaDllCommandPath"
!luadbg.lua "$luaScriptCommandPath"
!luadbg.luaload "$luaScriptCommandPath"
!luadbg.lualist
!luadbg.luaunload "$luaScriptName"
!luadbg.luaload "$badLuaScriptCommandPath"
!luadbg.lualist
!luadbg.luaload "$cycleLuaScriptCommandPath"
!luadbg.lualist
!luadbg.luaunload "$cycleLuaScriptName"
q
"@ | Set-Content -Encoding ascii $scriptPath

try {
    & $cdb -cf $scriptPath cmd.exe /c exit 2>&1 | Tee-Object -FilePath $outputPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "cdb exited with code $LASTEXITCODE"
    }

    $output = Get-Content -Raw $outputPath
    if ($output -notmatch "0CCh Extension diagnostics" -or $output -notmatch "Version:" -or $output -notmatch "Only http and https URLs" -or $output -notmatch "lua-smoke" -or $output -notmatch "mcp_server") {
        throw "Extension smoke test did not produce the expected diagnostics output."
    }
}
finally {
    Remove-Item -LiteralPath $scriptPath, $outputPath, $luaScript, $badLuaScript, $cycleLuaScript -Force -ErrorAction SilentlyContinue
}
