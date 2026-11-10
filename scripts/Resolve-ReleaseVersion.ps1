param(
    [Parameter(Mandatory = $true)]
    [string]$Tag
)

$ErrorActionPreference = "Stop"

$version = $Tag.Trim() -replace '^[vV]', ''
$parts = $version.Split('.')
if ($parts.Count -lt 3 -or $parts.Count -gt 4 -or ($parts | Where-Object { $_ -notmatch '^\d+$' })) {
    throw "Release tag must contain three or four numeric components: $Tag"
}
if ($parts | Where-Object { [uint64]$_ -gt 65535 }) {
    throw "Windows file-version components must not exceed 65535: $Tag"
}

if ($parts.Count -eq 4) {
    $version
    exit 0
}

$base = ($parts | ForEach-Object { [uint64]$_ }) -join '.'
$repoRoot = (& git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw "Unable to locate the git repository."
}
$revisions = @(
    git -C $repoRoot tag --list |
        ForEach-Object {
            if ($_ -match "^[vV]?$([regex]::Escape($base))\.(\d+)$") {
                [uint64]$Matches[1]
            }
        }
)

$nextRevision = if ($revisions.Count -eq 0) { 0 } else { ($revisions | Measure-Object -Maximum).Maximum + 1 }
if ($nextRevision -gt 65535) {
    throw "Automatic revision exceeds the Windows file-version limit."
}
"$base.$nextRevision"
