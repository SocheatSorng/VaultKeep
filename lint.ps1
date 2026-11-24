# Lint: compiles with every warning enabled and treated as an error, then checks basic formatting
# rules from .editorconfig (no tabs, no trailing whitespace, final newline, UTF-8 without mojibake).
# Usage: .\lint.ps1   (exit code 0 = clean)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$problems = 0

# 1. Compiler warnings as errors, for both the real build and the test build (TESTHOOKS); output discarded.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
foreach ($define in @($null, '/define:TESTHOOKS')) {
    $out = Join-Path ([IO.Path]::GetTempPath()) ('vk-lint-' + [Guid]::NewGuid().ToString('N') + '.exe')
    $cscArgs = @('/nologo', '/target:winexe', '/warn:4', '/warnaserror+', "/out:$out",
        '/r:System.dll', '/r:System.Core.dll', '/r:System.Security.dll', '/r:Microsoft.CSharp.dll',
        '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll')
    if ($define) { $cscArgs += $define }
    & $csc @cscArgs $sources
    if ($LASTEXITCODE -ne 0) { Write-Host "lint: compiler warnings/errors found $define" -ForegroundColor Red; $problems++ }
    Remove-Item $out -ErrorAction SilentlyContinue
}

# 2. Text formatting.
$files = Get-ChildItem $root -Recurse -File -Include *.cs, *.ps1, *.md, *.yml, *.yaml, *.json |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|\.git|tests\\out)\\' }
# UTF-8 text misread as Windows-1252, e.g. an arrow turning into three junk characters.
$mojibake = [string][char]0x00E2 + [char]0x20AC + '|' + [char]0x00C3 + '[\x80-\xBF]'
foreach ($f in $files) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -eq 0) { continue }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    $rel = $f.FullName.Substring($root.Length + 1)
    $lines = $text -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if ($line -match "`t") { Write-Host "${rel}:$($i + 1): tab character"; $problems++ }
        if ($line -match '\s+$') { Write-Host "${rel}:$($i + 1): trailing whitespace"; $problems++ }
        if ($line -match $mojibake) { Write-Host "${rel}:$($i + 1): garbled characters (encoding problem)"; $problems++ }
    }
    if ($bytes[$bytes.Length - 1] -ne 10) { Write-Host "${rel}: missing final newline"; $problems++ }
}

if ($problems -gt 0) { Write-Host "lint: $problems problem(s)" -ForegroundColor Red; exit 1 }
Write-Host 'lint: clean' -ForegroundColor Green
