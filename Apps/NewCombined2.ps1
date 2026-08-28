# Script to inventory .exe and .bat files across Windows 11 endpoints
# Simplified version for reliable file finding

param(
    [string]$SearchPath = "C:\",        # Default to C:\ but can be changed
    [string]$OutputPath = "C:\PySC\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$MaxThreads = 4,                # Number of parallel threads to use
    [int]$Maxfiles = 1000               # Limit to first 1000 files
)

# Define directories to exclude
$excludedDirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS"
)

Write-Host "SIMPLIFIED INVENTORY: Scanning all .exe and .bat files in $SearchPath" -ForegroundColor Yellow
Write-Host "Using $MaxThreads parallel threads for processing" -ForegroundColor Yellow
Write-Host "Excluding directories:" -ForegroundColor Yellow
foreach ($dir in $excludedDirs) {
    Write-Host "  - $dir" -ForegroundColor Yellow
}

# Ensure output directory exists
$outputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outputDir)) {
    try {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $outputDir" -ForegroundColor Green
    }
    catch {
        Write-Host "Error creating output directory: $_" -ForegroundColor Red
        exit
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

Write-Host "Device: $deviceName" -ForegroundColor Cyan
Write-Host "FQDN: $fqdn" -ForegroundColor Cyan
Write-Host "Output will be saved to: $OutputPath" -ForegroundColor Cyan

# Create counters with thread safety
$script:fileCount = 0
$script:exeCount = 0
$script:batCount = 0
$script:lastProgressUpdate = Get-Date

# Create the CSV file with headers
$headers = [PSCustomObject]@{
    'DeviceName' = "DeviceName"
    'FQDN' = "FQDN"
    'ApplicationName' = "ApplicationName"
    'Publisher' = "Publisher"
    'FileName' = "FileName"
    'InstallationPath' = "InstallationPath"
    'SHA256' = "SHA256"
    'MD5' = "MD5"
}

try {
    $headers | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Successfully created CSV file with headers" -ForegroundColor Green
}
catch {
    Write-Host "Failed to create CSV file: $_" -ForegroundColor Red
    exit
}

# Function to check if a path is in an excluded directory
function Test-ExcludedPath {
    param (
        [string]$Path
    )
    
    foreach ($excludedDir in $excludedDirs) {
        if ($Path.StartsWith($excludedDir, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

# Function to process a batch of files
function Process-FileBatch {
    param (
        [array]$Files,
        [string]$DeviceName,
        [string]$FQDN,
        [string]$OutputPath
    )
    
    $results = @()
    
    foreach ($file in $Files) {
        try {
            $fileName = $file.Name
            $installPath = $file.DirectoryName
            $fullPath = $file.FullName
            
            # Get file information - optimized for speed
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath)
            $appName = if ($versionInfo.ProductName) { $versionInfo.ProductName } 
                      elseif ($versionInfo.FileDescription) { $versionInfo.FileDescription }
                      else { [System.IO.Path]::GetFileNameWithoutExtension($fullPath) }
            
            # Skip publisher for better performance
            $publisher = "Not Collected"
            
            # Calculate hashes
            $sha256Hash = (Get-FileHash -Path $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $md5Hash = (Get-FileHash -Path $fullPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            
            # Create file info object
            $fileInfo = [PSCustomObject]@{
                'DeviceName' = $DeviceName
                'FQDN' = $FQDN
                'ApplicationName' = $appName
                'Publisher' = $publisher
                'FileName' = $fileName
                'InstallationPath' = $installPath
                'SHA256' = $sha256Hash
                'MD5' = $md5Hash
            }
            
            $results += $fileInfo
        }
        catch {
            # Skip files with errors
        }
    }
    
    return $results
}

$script:startTime = Get-Date

Write-Host "Starting file inventory scan..." -ForegroundColor Cyan

# DIRECT SEARCH APPROACH - Find all files first, then process them
Write-Host "Searching for .exe and .bat files (this may take a while)..." -ForegroundColor Yellow

# Create a list to store all files
$allFiles = New-Object System.Collections.ArrayList

# Search for files directly with proper filtering
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -like "?:\" }

foreach ($drive in $drives) {
    $drivePath = $drive.Root
    
    if ($drivePath -eq "C:\") {
        Write-Host "Scanning $drivePath..." -ForegroundColor Yellow
        
        # Use Where-Object to filter out excluded directories
        try {
            # Use -Path with wildcard and -Include for better file finding
            $exeFiles = Get-ChildItem -Path "$drivePath*" -Include "*.exe" -File -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { -not (Test-ExcludedPath -Path $_.DirectoryName) }
            
            $batFiles = Get-ChildItem -Path "$drivePath*" -Include "*.bat" -File -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { -not (Test-ExcludedPath -Path $_.DirectoryName) }
            
            [void]$allFiles.AddRange($exeFiles)
            [void]$allFiles.AddRange($batFiles)
            
            Write-Host "Found $($exeFiles.Count) .exe files and $($batFiles.Count) .bat files in $drivePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error searching $drivePath`: $_" -ForegroundColor Red
        }
    }
}

$totalFiles = $allFiles.Count
Write-Host "Found a total of $totalFiles files to process" -ForegroundColor Cyan

if ($totalFiles -eq 0) {
    Write-Host "No files found! Try running the script with administrator privileges." -ForegroundColor Red
    exit
}

# Process files in parallel using runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$runspacePool.Open()

# Split files into batches for parallel processing
$batchSize = [Math]::Max(1, [Math]::Ceiling($totalFiles / $MaxThreads / 10))
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
            
            # Skip publisher for better performance
            $publisher = "Not Collected"
            
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
    }
}

# Start processing batches
$processedCount = 0
$processedExe = 0
$processedBat = 0

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
        if ($runspace.Handle -ne $null -and $runspace.Handle.IsCompleted) {
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            
            # Write results to CSV
            if ($result.Results.Count -gt 0) {
                $result.Results | Export-Csv -Path $OutputPath -NoTypeInformation -Append
            }
            
            # Update counters
            $processedCount += $result.FileCount
            $processedExe += $result.ExeCount
            $processedBat += $result.BatCount
            $completed++
            
            # Show progress
            $percentComplete = [Math]::Round(($processedCount / $totalFiles) * 100, 1)
            $elapsedTime = (Get-Date) - $script:startTime
            $rate = if ($elapsedTime.TotalSeconds -gt 0) { [Math]::Round($processedCount / $elapsedTime.TotalSeconds, 2) } else { 0 }
            
            Write-Host "Progress: $processedCount of $totalFiles files ($percentComplete%) - $processedExe .exe, $processedBat .bat - $rate files/sec" -ForegroundColor Green
            
            # Clean up
            $runspace.Runspace.Dispose()
            $runspaces[$i].Handle = $null
        }
    }
    
    # Don't burn CPU
    Start-Sleep -Milliseconds 100
}

# Close the runspace pool
$runspacePool.Close()
$runspacePool.Dispose()

$endTime = Get-Date
$duration = $endTime - $script:startTime

# Display final statistics
Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Cyan
Write-Host "Total files found: $processedCount" -ForegroundColor Green
Write-Host "  - EXE files: $processedExe" -ForegroundColor Green
Write-Host "  - BAT files: $processedBat" -ForegroundColor Green
$durationMinutes = $duration.TotalMinutes.ToString("0.00")
$durationSeconds = $duration.TotalSeconds.ToString("0.00")
Write-Host "Scan duration: $durationMinutes minutes ($durationSeconds seconds)" -ForegroundColor Green
$processingRate = [math]::Round($processedCount / $duration.TotalSeconds, 2)
Write-Host "Average processing rate: $processingRate files/second" -ForegroundColor Green
Write-Host "Results saved to: $OutputPath" -ForegroundColor Green
