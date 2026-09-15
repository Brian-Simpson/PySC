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

# Consolidate and fix audit files for all types
function Invoke-AuditConsolidation {
    $consolidatorScript = Join-Path $config.Repo 'scripts' 'audit_consolidator.py'

    # Find latest Unique_Controls_Catalog
    $catalogDir = Join-Path $config.Repo 'Output' 'Processed' 'Normalized'
    $catalogs = @(Get-ChildItem -Path $catalogDir -Filter 'Unique_Controls_Catalog*.xlsx' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $controlsCatalog = if ($catalogs.Count -gt 0) { $catalogs[0].FullName } else { $null }

    # Audit types to process
    $auditTypes = @(
        @{ Type = 'PAFW'; CISPattern = 'CIS_Palo_Alto_Firewall_11_Benchmark_v*.audit' },
        @{ Type = 'NXOS'; CISPattern = 'CIS_Cisco_NX-OS_v*.audit' },
        @{ Type = 'IOS'; CISPattern = 'CIS_Cisco_IOS_*.audit' },
        @{ Type = 'ASA'; CISPattern = 'CIS_Cisco_ASA_*.audit' },
        @{ Type = 'F5'; CISPattern = 'CIS_F5_Networks_*.audit' },
        @{ Type = 'RHEL'; CISPattern = 'CIS_Red_Hat*.audit' },
        @{ Type = 'MSWRK'; CISPattern = 'CIS_Microsoft_Windows_*.audit' },
        @{ Type = 'MSSRV'; CISPattern = 'CIS_Microsoft_SQL_Server_*.audit' },
        @{ Type = 'SQL'; CISPattern = 'CIS_Microsoft_SQL_Server_*.audit' }
    )

    if (-not (Test-Path $consolidatorScript)) {
        Write-Host "⚠️  Consolidator not found" -ForegroundColor Yellow
        return
    }

    $normalizedDir = Join-Path $config.Repo 'Output' 'Processed' 'Normalized'
    $forGapDir = Join-Path $config.Repo 'Output' 'Processed' 'For_Gap'
    $consolidatedDir = Join-Path $config.Repo 'Output' 'Consolidated'

    # Ensure consolidated directory exists
    if (-not (Test-Path $consolidatedDir)) {
        New-Item -ItemType Directory -Force -Path $consolidatedDir | Out-Null
    }

    foreach ($auditType in $auditTypes) {
        $typeCode = $auditType.Type
        $inputAudit = Join-Path $forGapDir "$typeCode.audit"

        if (-not (Test-Path $inputAudit)) {
            continue
        }

        # Find matching CIS benchmark
        $cisBenchmark = Get-Item (Join-Path $normalizedDir $auditType.CISPattern) -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cisBenchmark) {
            Write-Host "  [$typeCode] ⚠️  CIS benchmark not found" -ForegroundColor Yellow
            continue
        }

        $outputFile = Join-Path $consolidatedDir "${typeCode}_all_audits.audit"

        try {
            Write-Host "  [$typeCode] " -NoNewline -ForegroundColor Cyan
            $args = @($consolidatorScript, $typeCode, $inputAudit, $cisBenchmark.FullName, $outputFile)
            if ($controlsCatalog -and (Test-Path $controlsCatalog)) {
                $args += $controlsCatalog
            }
            $output = & $config.Python @args 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅" -ForegroundColor Green
            } else {
                Write-Host "⚠️ " -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "❌ Exception" -ForegroundColor Red
        }
    }

    Write-Host "  Consolidation complete" -ForegroundColor Green
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
