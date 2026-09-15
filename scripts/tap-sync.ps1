# tap-sync.ps1 - Git sync helper with clear status messages
# Usage: C:\PySC\TAP\scripts\tap-sync.ps1

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$git = 'C:\Programs\MinGit\cmd\git.exe'

function Run-GitCommand {
    param(
        [string]$Command,
        [string]$Description
    )

    Write-Host "[$Description]" -ForegroundColor Cyan -NoNewline
    Write-Host " ... " -NoNewline

    $output = & $git @Command.Split() 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host "✅ PASS" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ FAIL" -ForegroundColor Red
        if ($output) {
            Write-Host "  Error: $output" -ForegroundColor Yellow
        }
        return $false
    }
}

function Sync-All {
    Write-Host "`n=== TAP GIT SYNC ===" -ForegroundColor Cyan
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

    $success = $true

    # Step 1: Status
    Run-GitCommand "status" "Step 1: Check status" | Out-Null

    # Step 2: Stage
    if (Run-GitCommand "add scripts/*.ps1" "Step 2: Stage changes") {
        # Step 3: Commit
        if (Run-GitCommand "commit -m 'Update TAP scripts'" "Step 3: Commit") {
            # Step 4: Pull
            if (Run-GitCommand "pull origin main --no-rebase" "Step 4: Pull from GitHub") {
                # Step 5: Push
                if (Run-GitCommand "push origin main" "Step 5: Push to GitHub") {
                    # Step 6: Verify
                    Run-GitCommand "status" "Step 6: Verify sync" | Out-Null
                    Write-Host "`n✅ ALL STEPS PASSED - SYNC COMPLETE" -ForegroundColor Green
                } else {
                    $success = $false
                }
            } else {
                Write-Host "`n⚠️  Conflicts detected - resolve manually" -ForegroundColor Yellow
                $success = $false
            }
        } else {
            $success = $false
        }
    } else {
        Write-Host "`n⚠️  No changes to commit" -ForegroundColor Yellow
    }

    if (-not $success) {
        Write-Host "`n❌ SYNC INCOMPLETE - CHECK ERRORS ABOVE" -ForegroundColor Red
    }
}

cd C:\PySC\TAP
Sync-All
