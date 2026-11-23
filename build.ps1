# Builds VaultKeep.exe with the C# compiler that ships with Windows (.NET Framework 4.8).
# No SDK install needed. Output: bin\VaultKeep.exe
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc" }

$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
& $csc /nologo /target:winexe /optimize+ /platform:anycpu "/out:$bin\VaultKeep.exe" `
    /r:System.dll /r:System.Core.dll /r:System.Security.dll /r:Microsoft.CSharp.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll `
    $sources
if ($LASTEXITCODE -ne 0) { throw "Build failed." }
Write-Host "Built $bin\VaultKeep.exe"
