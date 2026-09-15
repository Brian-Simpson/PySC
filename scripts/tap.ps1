# tap.ps1 - run the TAP audit toolkit CLI (python -m tap) from anywhere.
# All arguments pass through, e.g.:  tap refresh   tap gap production   tap report all

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$repo = Split-Path -Parent $PSScriptRoot

# Find Python: check hardcoded path first, then PATH
$python = $null
$fallback = 'C:\Program Files\Python39\python.exe'
if (Test-Path $fallback) {
    $python = $fallback
} else {
    try {
        $python = (Get-Command python -ErrorAction Stop).Source
    } catch {
        $python = $null
    }
}

if (-not $python) {
    Write-Error "Python not found in PATH or at C:\Program Files\Python39\python.exe"
    exit 1
}

if (-not (Test-Path $repo)) {
    Write-Error "TAP repository not found: $repo"
    exit 1
}

Push-Location $repo
try {
    & $python -m tap @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Warning "TAP exited with code $exitCode"
    }
    exit $exitCode
}
catch {
    Write-Error "Failed to run TAP: $_"
    exit 1
}
finally {
    Pop-Location
}
