# Builds VaultKeep with the C# compiler that ships with Windows (.NET Framework 4.8). No SDK needed.
#   bin\VaultKeep.exe        the real app (install / ship this one)
#   bin\test\VaultKeep.exe   test build (TESTHOOKS): adds options only the tests may use, such as
#                            VAULTKEEP_HOME, --key-dir, --no-drive-scan and adding keys without
#                            Windows sign-in. Never install or ship it.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc" }

$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
$refs = '/r:System.dll', '/r:System.Core.dll', '/r:System.Security.dll', '/r:Microsoft.CSharp.dll',
        '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll'

foreach ($variant in @(@{ Dir = 'bin'; Define = $null }, @{ Dir = 'bin\test'; Define = '/define:TESTHOOKS' })) {
    $out = Join-Path $root $variant.Dir
    New-Item -ItemType Directory -Force $out | Out-Null
    $cscArgs = @('/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', "/out:$out\VaultKeep.exe") + $refs
    if ($variant.Define) { $cscArgs += $variant.Define }
    & $csc @cscArgs $sources
    if ($LASTEXITCODE -ne 0) { throw "Build failed ($($variant.Dir))." }
    Write-Host "Built $out\VaultKeep.exe"
}
