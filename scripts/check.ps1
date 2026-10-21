# Runs fmt, clippy, tests and docs.
# Usage: powershell -ExecutionPolicy Bypass -File scripts/check.ps1

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

# x64 only; 32-bit (i686-pc-windows-msvc) isn't supported yet.
$targets = @('x86_64-pc-windows-msvc')

function Invoke-Step([string]$name, [scriptblock]$command) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step 'cargo fmt --check' { cargo fmt --all --check }

foreach ($target in $targets) {
    Invoke-Step "clippy ($target)" { cargo clippy --all-targets --target $target -- -D warnings }
    Invoke-Step "test ($target)" { cargo test --target $target }
}

$env:RUSTDOCFLAGS = '-D warnings'
Invoke-Step 'cargo doc' { cargo doc --no-deps }

Write-Host 'All checks passed.' -ForegroundColor Green
