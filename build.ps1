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

# A running VaultKeep (an open item, or one watching for late saves) keeps its exe locked. Windows allows
# renaming a running exe, so move it aside: the running copy keeps working from the renamed file, and the
# right-click menu picks up the new build. Old renamed copies are removed once nothing uses them.
function Clear-OutputExe([string]$exe) {
    Get-ChildItem (Split-Path $exe) -Filter 'VaultKeep.old-*.exe' -ErrorAction SilentlyContinue |
        ForEach-Object { try { Remove-Item $_.FullName -ErrorAction Stop } catch { } }
    if (-not (Test-Path $exe)) { return }
    try { [IO.File]::Open($exe, 'Open', 'ReadWrite', 'None').Close(); return } catch { }
    $aside = Join-Path (Split-Path $exe) ('VaultKeep.old-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.exe')
    Move-Item $exe $aside
    Write-Host "VaultKeep is running; moved the old exe aside ($(Split-Path $aside -Leaf))."
}

foreach ($variant in @(@{ Dir = 'bin'; Define = $null }, @{ Dir = 'bin\test'; Define = '/define:TESTHOOKS' })) {
    $out = Join-Path $root $variant.Dir
    New-Item -ItemType Directory -Force $out | Out-Null
    Clear-OutputExe (Join-Path $out 'VaultKeep.exe')
    $cscArgs = @('/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', "/out:$out\VaultKeep.exe") + $refs
    if ($variant.Define) { $cscArgs += $variant.Define }
    & $csc @cscArgs $sources
    if ($LASTEXITCODE -ne 0) { throw "Build failed ($($variant.Dir))." }
    Write-Host "Built $out\VaultKeep.exe"
}
