# tap-unified.ps1 - unified TAP audit toolkit launcher
# Handles both ad-hoc commands and refresh pipeline with centralized error handling
# Usage:
#   tap-unified refresh [args...]        # Run refresh with logging
#   tap-unified <command> [args...]      # Run any TAP command (gap, report, etc.)

param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$repo = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo '..' 'TAPARCHIVE' 'Output'
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

# Configuration
$config = @{
    Python = $null
    Repo = $repo
    LogDir = $logDir
    Timestamp = $timestamp
}

# Find Python: check PATH first, then fall back to hardcoded location
function Find-Python {
    $python = $null
    try {
        $python = (Get-Command python -ErrorAction Stop).Source
    } catch {
        $fallback = 'C:\Program Files\Python39\python.exe'
        if (Test-Path $fallback) {
            $python = $fallback
        }
    }
    return $python
}

# Validate prerequisites
function Test-Prerequisites {
    if (-not $config.Python) {
        Write-Error "Python not found in PATH or at C:\Program Files\Python39\python.exe"
        return $false
    }

    if (-not (Test-Path $config.Repo)) {
        Write-Error "TAP repository not found: $($config.Repo)"
        return $false
    }

    try {
        New-Item -ItemType Directory -Force -Path $config.LogDir | Out-Null
    } catch {
        Write-Error "Failed to create log directory: $_"
        return $false
    }

    return $true
}

# Run refresh with logging and error separation
function Invoke-TapRefresh {
    param([string[]]$Args)

    $logFile = "$($config.LogDir)\refresh_tap_$($config.Timestamp).log"
    $errFile = "$($config.LogDir)\refresh_tap_$($config.Timestamp).err.log"

    Write-Host "Starting TAP refresh at $($config.Timestamp)" -ForegroundColor Cyan
    Write-Host "Output log: $logFile"
    Write-Host "Error log:  $errFile`n"

    Push-Location $config.Repo
    try {
        $process = Start-Process -FilePath $config.Python `
            -ArgumentList @("-m", "tap", "refresh") + $Args `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError $errFile `
            -NoNewWindow `
            -PassThru

        $exitCode = $process.ExitCode

        # Display output
        if (Test-Path $logFile) {
            Get-Content $logFile
        }

        # Display errors if any
        if (Test-Path $errFile -and (Get-Item $errFile).Length -gt 0) {
            Write-Host "`n--- STDERR ---" -ForegroundColor Yellow
            Get-Content $errFile
        }

        if ($exitCode -eq 0) {
            Write-Host "`nRefresh completed successfully at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green
        } else {
            Write-Host "`nRefresh failed with exit code $exitCode" -ForegroundColor Red
        }

        return $exitCode
    }
    finally {
        Pop-Location
    }
}

# Run generic TAP command
function Invoke-TapCommand {
    param(
        [string]$Cmd,
        [string[]]$Args
    )

    Push-Location $config.Repo
    try {
        & $config.Python -m tap $Cmd @Args
        return $LASTEXITCODE
    }
    catch {
        Write-Error "Failed to run TAP $Cmd : $_"
        return 1
    }
    finally {
        Pop-Location
    }
}

# Main
$config.Python = Find-Python

if (-not (Test-Prerequisites)) {
    exit 1
}

if ([string]::IsNullOrEmpty($Command)) {
    Write-Host @"
TAP Unified Launcher

Usage:
    tap-unified refresh [args...]        Run refresh pipeline with logging
    tap-unified <command> [args...]      Run any TAP command (gap, report, help, etc.)

Examples:
    tap-unified refresh
    tap-unified gap production
    tap-unified report all
    tap-unified help
"@ -ForegroundColor Cyan
    exit 0
}

$exitCode = switch ($Command.ToLower()) {
    "refresh" {
        Invoke-TapRefresh -Args $Arguments
    }
    default {
        Invoke-TapCommand -Cmd $Command -Args $Arguments
    }
}

exit $exitCode
