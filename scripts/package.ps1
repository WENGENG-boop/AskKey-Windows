# Builds the release helper and App and bundles them into an MSI.
# Usage: .\scripts\package.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$triple = (rustc -vV | Select-String "^host: (.+)$").Matches[0].Groups[1].Value

cargo build --release -p askkey-helper
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Tauri expects external binaries named with the target triple.
$binaries = Join-Path $root "app\binaries"
New-Item -ItemType Directory -Force $binaries | Out-Null
Copy-Item "target\release\askkey.exe" (Join-Path $binaries "askkey-$triple.exe") -Force

$overlay = Join-Path $root "target\tauri.release.json"
'{"bundle":{"externalBin":["binaries/askkey"]}}' | Set-Content -Encoding utf8 $overlay

Push-Location app
try {
    npx --yes @tauri-apps/cli@2.12.3 build --config $overlay
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
Get-ChildItem "target\release\bundle\msi\*.msi" | ForEach-Object { Write-Output $_.FullName }
