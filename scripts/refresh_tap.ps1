# refresh_tap.ps1 - run the TAP audit refresh pipeline with logging
# Invoked by the refresh-tap profile function; extra arguments pass through to pysc.

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$repo = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo '..' 'TAPARCHIVE' 'Output'
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$logFile = "$logDir\refresh_tap_$timestamp.log"
$errFile = "$logDir\refresh_tap_$timestamp.err.log"

# Find Python: check PATH first, then fall back to hardcoded location
$python = $null
try {
    $python = (Get-Command python -ErrorAction Stop).Source
} catch {
    $fallback = 'C:\Program Files\Python39\python.exe'
    if (Test-Path $fallback) {
        $python = $fallback
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

# Create log directory
try {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
} catch {
    Write-Error "Failed to create log directory: $_"
    exit 1
}

Write-Host "Starting TAP refresh at $timestamp"
Write-Host "Logging to: $logFile"

Push-Location $repo
try {
    $process = Start-Process -FilePath $python `
        -ArgumentList @("-m", "tap", "refresh") + $Arguments `
        -RedirectStandardOutput $logFile `
        -RedirectStandardError $errFile `
        -NoNewWindow `
        -PassThru

    $exitCode = $process.ExitCode

    # Display output and errors
    if (Test-Path $logFile) {
        Get-Content $logFile
    }
    if (Test-Path $errFile -and (Get-Item $errFile).Length -gt 0) {
        Write-Host "`n--- ERRORS ---" -ForegroundColor Yellow
        Get-Content $errFile
    }

    if ($exitCode -eq 0) {
        Write-Host "`nTAP refresh completed successfully" -ForegroundColor Green
    } else {
        Write-Host "`nTAP refresh failed with exit code $exitCode" -ForegroundColor Red
    }

    exit $exitCode
}
catch {
    Write-Error "Failed to run TAP refresh: $_"
    exit 1
}
finally {
    Pop-Location
}
