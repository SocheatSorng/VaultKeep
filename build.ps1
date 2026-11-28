# Builds VaultKeep with the C# compiler that ships with Windows (.NET Framework 4.8). No SDK needed.
#   bin\VaultKeep.exe        the real app (install / ship this one)
#   bin\test\VaultKeep.exe   test build (TESTHOOKS): adds options only the tests may use, such as
#                            VAULTKEEP_HOME, --key-dir, --no-drive-scan and adding keys without
#                            Windows sign-in. Never install or ship it.
#   -Installer               also dist\VaultKeep-Setup-<version>.exe + dist\SHA256SUMS.txt (Inno Setup 6),
#                            from bin\VaultKeep.exe only. <version> comes from src\Program.cs.
param([switch]$Installer)
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

if (-not $Installer) { return }

# --- Installer (Inno Setup 6)
$programCs = Get-Content (Join-Path $root 'src\Program.cs') -Raw
if ($programCs -notmatch 'AssemblyInformationalVersion\("(\d+\.\d+\.\d+)"\)') { throw 'Version not found in src\Program.cs' }
$version = $Matches[1]
$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found (winget install JRSoftware.InnoSetup).' }
$dist = Join-Path $root 'dist'
if (Test-Path $dist) {
    # A junction/link named dist: remove only the link, never the files it points to.
    if ((Get-Item $dist -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { [IO.Directory]::Delete($dist) }
    else { Remove-Item -Recurse -Force $dist }
}
Push-Location $root
try { & $iscc /Q "/DAppVersion=$version" installer.iss } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed.' }
$setup = Join-Path $dist "VaultKeep-Setup-$version.exe"
if (-not (Test-Path $setup)) { throw "Installer not found: $setup" }
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
# LF line ending and no BOM, so `sha256sum -c SHA256SUMS.txt` works too.
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$hash  $(Split-Path $setup -Leaf)`n")
Write-Host "Built $setup"
Write-Host "SHA-256 $hash"
