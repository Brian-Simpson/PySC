
# Script to inventory .exe and .bat files on local Windows 11 device
# Local-only version with enhanced performance and detailed reporting

param(
    [string]$SearchPath = "C:\",        # Default to C:\ but can be changed
    [string]$OutputPath = "C:\PySC\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$MaxThreads = 8,               # Number of parallel threads to use
    [int]$ProgressInterval = 100        # Show progress every 100 files
)

Write-Host "`n===== LOCAL FILE INVENTORY SCANNER =====" -ForegroundColor Cyan
Write-Host "Scanning .exe and .bat files on: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Search path: $SearchPath" -ForegroundColor Yellow
Write-Host "Output file: $OutputPath" -ForegroundColor Yellow
Write-Host "Max threads: $MaxThreads" -ForegroundColor Yellow

# Define directories to exclude for performance
$excludedDirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64", 
    "C:\Windows\WinSxS"
)

Write-Host "`nExcluding directories:" -ForegroundColor Yellow
foreach ($dir in $excludedDirs) {
    Write-Host "  - $dir" -ForegroundColor Yellow
}

# Ensure output directory exists
$outputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outputDir)) {
    try {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Host "`nCreated output directory: $outputDir" -ForegroundColor Green
    }
    catch {
        Write-Host "Error creating output directory: $_" -ForegroundColor Red
        exit 1
    }
}

# Get computer information
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$deviceName = $computerSystem.Name
try {
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $fqdn = "$($computerSystem.Name).$domain"
}
catch {
    $fqdn = $computerSystem.Name
    Write-Host "Could not determine domain. Using computer name only: $fqdn" -ForegroundColor Yellow
}

Write-Host "`nDevice: $deviceName" -ForegroundColor Cyan
Write-Host "FQDN: $fqdn" -ForegroundColor Cyan

# Create the CSV file with headers
$headers = @(
    'DeviceName',
    'FQDN', 
    'ApplicationName',
    'Publisher',
    'FileName',
    'InstallationPath',
    'SHA256',
    'MD5'
)

try {
    $headers -join ',' | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Successfully created CSV file with headers" -ForegroundColor Green
}
catch {
    Write-Host "Failed to create CSV file: $_" -ForegroundColor Red
    exit 1
}

# Function to check if a path is in an excluded directory
function Test-ExcludedPath {
    param ([string]$Path)
    foreach ($excludedDir in $excludedDirs) {
        if ($Path.StartsWith($excludedDir, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

$startTime = Get-Date
$searchStartTime = Get-Date

Write-Host "`nStarting file inventory scan..." -ForegroundColor Cyan

# Verify the search path exists
if (-not (Test-Path -Path $SearchPath)) {
    Write-Host "ERROR: Search path does not exist: $SearchPath" -ForegroundColor Red
    exit 1
}

Write-Host "Search path verified: $SearchPath exists" -ForegroundColor Green

# Create a list to store all files
$allFiles = New-Object System.Collections.ArrayList
$fileCounter = 0
$exeFoundCount = 0
$batFoundCount = 0

# OPTIMIZED SEARCH APPROACH - Skip excluded directories upfront
Write-Host "Searching for .exe and .bat files..." -ForegroundColor Yellow
try {
    $searchStartTime = Get-Date
    
    # Get all drives/root directories to search
    $searchPaths = @()
    if ($SearchPath -eq "C:\") {
        # For C:\ drive, add specific directories and skip problematic ones
        $rootDirs = Get-ChildItem -Path "C:\" -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -notmatch "^(Windows|`$Recycle\.Bin|System Volume Information|PerfLogs)$" }
        $searchPaths += $rootDirs.FullName
        
        # Add specific Windows directories we want to include
        $windowsDirs = @(
            "C:\Windows\System32\WindowsPowerShell",
            "C:\Windows\System32\drivers",
            "C:\Windows\System32\DriverStore"
        )
        foreach ($dir in $windowsDirs) {
            if (Test-Path $dir) {
                $searchPaths += $dir
            }
        }
    } else {
        $searchPaths += $SearchPath
    }
    
    Write-Host "Searching in $($searchPaths.Count) directory paths..." -ForegroundColor Yellow
    
    $allFoundFiles = @()
    foreach ($path in $searchPaths) {
        Write-Host "Scanning: $path" -ForegroundColor Gray
        $pathFiles = Get-ChildItem -Path $path -Include @("*.exe", "*.bat") -File -Recurse -ErrorAction SilentlyContinue
        $allFoundFiles += $pathFiles
        Write-Host "  Found $($pathFiles.Count) files in this path" -ForegroundColor Gray
    }
    
    Write-Host "Initial search returned $($allFoundFiles.Count) total files" -ForegroundColor Magenta
    Write-Host "Now applying final exclusions..." -ForegroundColor Yellow
    
    # Apply exclusions only to the found files
    $fileCounter = 0
    foreach ($file in $allFoundFiles) {
        if (-not (Test-ExcludedPath -Path $file.DirectoryName)) {
            [void]$allFiles.Add($file)
            $fileCounter++
            
            if ($file.Extension -eq ".exe") {
                $exeFoundCount++
            } else {
                $batFoundCount++
            }
            
            # Only show progress every 100 files to reduce console overhead
            if ($fileCounter % $ProgressInterval -eq 0) {
                Write-Host "Processed $fileCounter files..." -ForegroundColor Cyan
            }
        }
    }
    
    $searchEndTime = Get-Date
    $searchDuration = ($searchEndTime - $searchStartTime).TotalSeconds
    Write-Host "Search completed in $($searchDuration.ToString("0.00")) seconds" -ForegroundColor Green
}
catch {
    Write-Host "Error searching for files: $_" -ForegroundColor Red
    exit 1
}

$totalFiles = $allFiles.Count
Write-Host "Found a total of $totalFiles files to process ($exeFoundCount .exe, $batFoundCount .bat)" -ForegroundColor Green

if ($totalFiles -eq 0) {
    Write-Host "No files found! Try running the script with administrator privileges." -ForegroundColor Red
    Write-Host "Results file created with headers only: $OutputPath" -ForegroundColor Yellow
    exit 0
}

# Process files in parallel using runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$runspacePool.Open()

# Split files into batches for parallel processing
$batchSize = [Math]::Max(1, [Math]::Ceiling($totalFiles / $MaxThreads / 5))
$fileBatches = [System.Collections.ArrayList]::new()

for ($i = 0; $i -lt $allFiles.Count; $i += $batchSize) {
    $batch = $allFiles[$i..([Math]::Min($i + $batchSize - 1, $allFiles.Count - 1))]
    [void]$fileBatches.Add($batch)
}

Write-Host "Processing $($fileBatches.Count) batches of files with batch size $batchSize..." -ForegroundColor Yellow

$runspaces = @()
$scriptBlock = {
    param($files, $deviceName, $fqdn)
    
    $results = @()
    $exeCount = 0
    $batCount = 0
    $processedFiles = @()
    
    foreach ($file in $files) {
        try {
            $fileName = $file.Name
            $installPath = $file.DirectoryName
            $fullPath = $file.FullName
            
            # Count file types
            if ($fileName -like "*.exe") {
                $exeCount++
            } elseif ($fileName -like "*.bat") {
                $batCount++
            }
            
            # Get file information - optimized for speed
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath)
            $appName = if ($versionInfo.ProductName) { $versionInfo.ProductName } 
                      elseif ($versionInfo.FileDescription) { $versionInfo.FileDescription }
                      else { [System.IO.Path]::GetFileNameWithoutExtension($fullPath) }
            
            # Get publisher information from file version info
            $publisher = if ($versionInfo.CompanyName) { 
                $versionInfo.CompanyName 
            } else { 
                "Unknown" 
            }
            
            # Calculate hashes
            $sha256Hash = (Get-FileHash -Path $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $md5Hash = (Get-FileHash -Path $fullPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            
            # Create file info object
            $fileInfo = [PSCustomObject]@{
                'DeviceName' = $deviceName
                'FQDN' = $fqdn
                'ApplicationName' = $appName
                'Publisher' = $publisher
                'FileName' = $fileName
                'InstallationPath' = $installPath
                'SHA256' = $sha256Hash
                'MD5' = $md5Hash
            }
            
            $results += $fileInfo
            $processedFiles += $fileName
        }
        catch {
            # Skip files with errors
        }
    }
    
    return @{
        Results = $results
        FileCount = $results.Count
        ExeCount = $exeCount
        BatCount = $batCount
        ProcessedFiles = $processedFiles
    }
}

# Start processing batches
$processedCount = 0
$processedExe = 0
$processedBat = 0
$processingStartTime = Get-Date

foreach ($batch in $fileBatches) {
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($batch).AddArgument($deviceName).AddArgument($fqdn)
    $runspace.RunspacePool = $runspacePool
    
    $runspaces += [PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        BatchSize = $batch.Count
    }
}

# Process results as they complete
$completed = 0
while ($completed -lt $runspaces.Count) {
    for ($i = 0; $i -lt $runspaces.Count; $i++) {
        $runspace = $runspaces[$i]
        if ($null -ne $runspace.Handle -and $runspace.Handle.IsCompleted) {
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            
            # Write results to CSV
            if ($result.Results.Count -gt 0) {
                foreach ($fileResult in $result.Results) {
                    # Escape commas and quotes in CSV data
                    $escapedAppName = ($fileResult.ApplicationName -replace '"', '""' -replace ',', '')
                    $escapedPublisher = ($fileResult.Publisher -replace '"', '""' -replace ',', '')
                    $escapedFileName = ($fileResult.FileName -replace '"', '""' -replace ',', '')
                    $escapedInstallPath = ($fileResult.InstallationPath -replace '"', '""' -replace ',', '')
                    
                    $csvLine = "$($fileResult.DeviceName),$($fileResult.FQDN),$escapedAppName,$escapedPublisher,$escapedFileName,$escapedInstallPath,$($fileResult.SHA256),$($fileResult.MD5)"
                    [System.IO.File]::AppendAllText($OutputPath, $csvLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
                }
            }
        }
            # Update counters
            $processedCount += $result.FileCount
            $processedExe += $result.ExeCount
            $processedBat += $result.BatCount
            $completed++
            
            # Show progress
            Write-Host "Completed batch $completed of $($runspaces.Count) - processed $($result.FileCount) files" -ForegroundColor Green
            
            # Optionally show file names (can be disabled for less verbose output)
            if ($result.ProcessedFiles.Count -le 10) {
                foreach ($fileName in $result.ProcessedFiles) {
                    Write-Host "  ✓ $fileName" -ForegroundColor White
                }
            } else {
                Write-Host "  ✓ Processed $($result.ProcessedFiles.Count) files in this batch" -ForegroundColor White
            }
            
            # Clean up
            $runspace.Runspace.Dispose()
            $runspaces[$i].Handle = $null
    }
}

# Don't burn CPU
Start-Sleep -Milliseconds 100

# Close the runspace pool
$runspacePool.Close()
$runspacePool.Dispose()

$endTime = Get-Date
$duration = $endTime - $startTime
$searchDuration = $processingStartTime - $searchStartTime
$processingDuration = $endTime - $processingStartTime

# Display final statistics
Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Cyan
Write-Host "Device: $deviceName ($fqdn)" -ForegroundColor Green
Write-Host "Total files processed: $processedCount" -ForegroundColor Green
Write-Host "  - EXE files: $processedExe" -ForegroundColor Green
Write-Host "  - BAT files: $processedBat" -ForegroundColor Green
$durationMinutes = $duration.TotalMinutes.ToString("0.00")
$durationSeconds = $duration.TotalSeconds.ToString("0.00")
Write-Host "Total scan duration: $durationMinutes minutes ($durationSeconds seconds)" -ForegroundColor Green
Write-Host "  - Search time: $($searchDuration.TotalSeconds.ToString("0.00")) seconds" -ForegroundColor Green
Write-Host "  - Processing time: $($processingDuration.TotalSeconds.ToString("0.00")) seconds" -ForegroundColor Green
$processingRate = [math]::Round($processedCount / $duration.TotalSeconds, 2)
Write-Host "Average processing rate: $processingRate files/second" -ForegroundColor Green
Write-Host "Results saved to: $OutputPath" -ForegroundColor Green

# Enhanced file size display
try {
    $fileSize = (Get-Item $OutputPath).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Host "File size: $fileSizeMB MB" -ForegroundColor Green
} catch {
    Write-Host "Could not determine file size" -ForegroundColor Yellow
}

# Display results file location
Write-Host "Results file location: $OutputPath" -ForegroundColor Cyan

Write-Host "`nLocal inventory scan complete!" -ForegroundColor Cyan

# END OF SCRIPT
