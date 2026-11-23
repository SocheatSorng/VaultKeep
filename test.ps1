# Runs the test suite against bin\VaultKeep.exe (build first with .\build.ps1).
#   .\test.ps1             all tests (the session tests open Notepad/Explorer briefly, ~2 min)
#   .\test.ps1 -Headless   only tests that need no desktop (what CI runs)
param([switch]$Headless)
$ErrorActionPreference = 'Stop'
$tests = Get-ChildItem (Join-Path $PSScriptRoot 'tests') -Filter 'test_*.ps1' | Sort-Object Name
if ($Headless) { $tests = $tests | Where-Object Name -ne 'test_session.ps1' }

$failed = 0; $passed = 0
foreach ($t in $tests) {
    Write-Host "== $($t.Name)" -ForegroundColor Cyan
    . $t.FullName
    $failed += $script:Failures; $passed += $script:Passes
}
$outDir = Join-Path $PSScriptRoot 'tests\out'
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir -ErrorAction SilentlyContinue }

Write-Host ''
if ($failed -gt 0) { Write-Host "$passed passed, $failed FAILED" -ForegroundColor Red; exit 1 }
Write-Host "$passed passed, 0 failed" -ForegroundColor Green
