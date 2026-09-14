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

# Find Python: check hardcoded path first, then PATH
function Find-Python {
    $fallback = 'C:\Program Files\Python39\python.exe'
    if (Test-Path $fallback) {
        return $fallback
    }

    $python = $null
    try {
        $python = (Get-Command python -ErrorAction Stop).Source
        if ($python -and (Test-Path $python)) {
            return $python
        }
    } catch {
        # Continue to fallback
    }

    return $null
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
        $argList = @("-m", "tap", "refresh") + $Args

        Write-Host "Processing" -NoNewline -ForegroundColor Cyan

        $process = Start-Process -FilePath $config.Python `
            -ArgumentList $argList `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError $errFile `
            -NoNewWindow `
            -PassThru

        # Show spinner while waiting
        $spinner = @('|', '/', '-', '\')
        $i = 0
        while (-not $process.HasExited) {
            Write-Host "`b$($spinner[$i % 4])" -NoNewline -ForegroundColor Cyan
            $i++
            Start-Sleep -Milliseconds 250
        }
        Write-Host "`b " # Clear spinner

        $exitCode = $process.ExitCode

        # Display output
        if (Test-Path $logFile) {
            Get-Content $logFile
        }

        # Display errors if any
        if ((Test-Path $errFile) -and ((Get-Item $errFile).Length -gt 0)) {
            Write-Host "`n--- STDERR ---" -ForegroundColor Yellow
            Get-Content $errFile
        }

        if ($exitCode -eq 0) {
            Write-Host "`n✅ Refresh completed successfully at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green

            # Post-process audits to fix and consolidate
            Write-Host "`nConsolidating audit files..." -ForegroundColor Cyan
            Invoke-AuditConsolidation

        } else {
            Write-Host "`n❌ Refresh failed with exit code $exitCode" -ForegroundColor Red
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

# Consolidate and fix audit files
function Invoke-AuditConsolidation {
    $consolidatorScript = Join-Path $config.Repo 'scripts' 'audit_consolidator.py'
    $inputAudit = Join-Path $config.Repo 'Output' 'Processed' 'For_Gap' 'PAFW.audit'
    $cisBenchmark = 'C:\Users\brian.simpson\OneDrive - Hilltop Holdings\Downloads\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1-normalized (1).audit'
    $outputFile = 'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit'

    if (-not (Test-Path $consolidatorScript)) {
        Write-Host "⚠️  Consolidator script not found: $consolidatorScript" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $inputAudit)) {
        Write-Host "⚠️  Input audit not found: $inputAudit" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $cisBenchmark)) {
        Write-Host "⚠️  CIS benchmark not found: $cisBenchmark" -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "  Processing PAFW audits..." -NoNewline
        & $config.Python $consolidatorScript "PAFW" $inputAudit $cisBenchmark $outputFile 2>&1 | ForEach-Object {
            if ($_ -match "✅|❌|⚠️") {
                Write-Host "`n  $_" -ForegroundColor Cyan
            }
        }
        Write-Host "  Consolidation complete" -ForegroundColor Green
    }
    catch {
        Write-Host "`n  ⚠️  Consolidation skipped: $_" -ForegroundColor Yellow
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
