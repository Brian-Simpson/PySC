# Script to inventory .exe and .bat files across Windows 11 endpoints
# Revised version with improved error handling and debugging

param(
    [string]$SearchPath = "C:\",        # Default to C:\ but can be changed
    [string]$OutputPath = "C:\PySC\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$Debug = $true              # Enable debug mode by default
)

# Define directories to exclude
$excludedDirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS"
)

Write-Host "FULL INVENTORY MODE: Scanning all .exe and .bat files in $SearchPath" -ForegroundColor Yellow
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
        $errorMsg = $_.Exception.Message
        Write-Host "Error creating output directory: $errorMsg" -ForegroundColor Red
        Write-Host "Please ensure you have permissions to create the directory or run as administrator" -ForegroundColor Red
        exit
    }
}

# Create a log file for debugging
$logPath = Join-Path -Path $outputDir -ChildPath "FileInventory_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Debug) {
        Add-Content -Path $logPath -Value $logMessage
    }
    
    if ($Level -eq "ERROR") {
        Write-Host $logMessage -ForegroundColor Red
    }
    elseif ($Level -eq "WARNING") {
        Write-Host $logMessage -ForegroundColor Yellow
    }
    elseif ($Level -eq "SUCCESS") {
        Write-Host $logMessage -ForegroundColor Green
    }
    else {
        Write-Host $logMessage
    }
}

Write-Log ("Script started. Logging to " + $logPath) "INFO"

# Get computer information
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$deviceName = $computerSystem.Name
try {
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $fqdn = "$($computerSystem.Name).$domain"
}
catch {
    $fqdn = $computerSystem.Name
    Write-Log ("Could not determine domain. Using computer name only: " + $fqdn) "WARNING"
}

Write-Log ("Device: " + $deviceName) "INFO"
Write-Log ("FQDN: " + $fqdn) "INFO"
Write-Log ("Output will be saved to: " + $OutputPath) "INFO"

# Create an array to store results
$results = @()
$fileCount = 0
$exeCount = 0
$batCount = 0
$directoriesScanned = 0
$batchSize = 100  # Write to CSV every 100 files to manage memory

# Define a function to get file publisher information
function Get-FilePublisher {
    param (
        [string]$FilePath
    )
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($signature.Status -ne "NotSigned" -and $signature.SignerCertificate -ne $null) {
            $publisher = $signature.SignerCertificate.Subject
            # Extract CN from the subject
            if ($publisher -match "CN=([^,]+)") {
                return $Matches[1].Trim()
            }
            return $publisher
        }
        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

# Define a function to get application name
function Get-ApplicationName {
    param (
        [string]$FilePath
    )
    
    try {
        $versionInfo = (Get-Item $FilePath -ErrorAction SilentlyContinue).VersionInfo
        if ($versionInfo.ProductName) {
            return $versionInfo.ProductName
        }
        else {
            # If ProductName is not available, use FileDescription or filename without extension
            if ($versionInfo.FileDescription) {
                return $versionInfo.FileDescription
            }
            else {
                return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
            }
        }
    }
    catch {
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
}

# Define a function to calculate SHA256 hash
function Get-FileHash256 {
    param (
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        return $hash.Hash
    }
    catch {
        return "Error calculating hash"
    }
}

# Define a function to calculate MD5 hash
function Get-FileHashMD5 {
    param (
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm MD5 -ErrorAction SilentlyContinue
        return $hash.Hash
    }
    catch {
        return "Error calculating hash"
    }
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

# Function to write results directly to CSV
function Write-ResultToCSV {
    param (
        [PSCustomObject]$FileInfo,
        [string]$Path,
        [bool]$CreateHeader = $false
    )
    
    try {
        if ($CreateHeader) {
            # Create the file with headers
            $FileInfo | Export-Csv -Path $Path -NoTypeInformation
        } else {
            # Append without headers
            $FileInfo | Export-Csv -Path $Path -NoTypeInformation -Append
        }
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log ("Error writing to CSV: " + $errorMsg) "ERROR"
        return $false
    }
}

Write-Log ("Starting file inventory on " + $fqdn + "...") "INFO"
Write-Log ("Scanning " + $SearchPath + "...") "INFO"

$startTime = Get-Date
$progressInterval = 50 # Show progress every 50 files
$csvCreated = $false

# Create a test file to verify we can write to the output directory
$testFilePath = Join-Path -Path $outputDir -ChildPath "test_write.txt"
try {
    "Test write access" | Out-File -FilePath $testFilePath -Force
    Remove-Item -Path $testFilePath -Force
    Write-Log "Successfully verified write access to output directory" "SUCCESS"
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Log ("Cannot write to output directory. Please check permissions: " + $errorMsg) "ERROR"
    exit
}

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
    Write-Log "Successfully created CSV file with headers" "SUCCESS"
    $csvCreated = $true
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Log ("Failed to create CSV file: " + $errorMsg) "ERROR"
    exit
}

try {
    # First, get all directories excluding the ones we want to skip
    Write-Log "Finding directories to scan..." "INFO"
    
    # Start with the root directory if it's not excluded
    $directories = @()
    if (-not (Test-ExcludedPath -Path $SearchPath)) {
        $directories += $SearchPath
    }
    
    # Get immediate subdirectories first
    Write-Log "Getting first level directories..." "INFO"
    $firstLevelDirs = Get-ChildItem -Path $SearchPath -Directory -ErrorAction SilentlyContinue | 
                      Where-Object { -not (Test-ExcludedPath -Path $_.FullName) }
    
    $directories += $firstLevelDirs.FullName
    Write-Log ("Found " + $firstLevelDirs.Count + " first-level directories") "INFO"
    
    # Process each directory level by level to avoid memory issues
    $currentLevel = $firstLevelDirs
    $maxDepth = 10  # Limit depth to avoid infinite recursion
    $currentDepth = 1
    
    while ($currentLevel.Count -gt 0 -and $currentDepth -lt $maxDepth) {
        Write-Log ("Getting directories at depth " + ($currentDepth+1) + "...") "INFO"
        $nextLevel = @()
        
        foreach ($dir in $currentLevel) {
            try {
                $subDirs = Get-ChildItem -Path $dir.FullName -Directory -ErrorAction SilentlyContinue | 
                           Where-Object { -not (Test-ExcludedPath -Path $_.FullName) }
                
                if ($subDirs) {
                    $nextLevel += $subDirs
                    $directories += $subDirs.FullName
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
                Write-Log ("Error accessing directory " + $dir.FullName + ": " + $errorMsg) "WARNING"
            }
        }
        
        $currentLevel = $nextLevel
        $currentDepth++
        Write-Log ("Found " + $nextLevel.Count + " directories at depth " + $currentDepth) "INFO"
    }
    
    $totalDirectories = $directories.Count
    Write-Log ("Found " + $totalDirectories + " directories to scan") "INFO"
    
    # Process each directory
    foreach ($dir in $directories) {
        $dirPath = $dir
        $directoriesScanned++
        
        if ($directoriesScanned % 10 -eq 0) {
            Write-Log ("Scanning directory " + $directoriesScanned + " of " + $totalDirectories + ": " + $dirPath) "INFO"
        }
        
        # Get files in this directory only (not recursive)
        try {
            $dirFiles = Get-ChildItem -Path $dirPath -Include "*.exe", "*.bat" -File -ErrorAction SilentlyContinue
            
            if ($dirFiles.Count -gt 0) {
                Write-Log ("Found " + $dirFiles.Count + " files in " + $dirPath) "INFO"
            }
            
            foreach ($file in $dirFiles) {
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
                    
                    # Increment file count
                    $fileCount++
                    
                    # Show progress
                    if ($fileCount % $progressInterval -eq 0) {
                        $elapsedTime = (Get-Date) - $startTime
                        $rate = if ($elapsedTime.TotalSeconds -gt 0) { [math]::Round($fileCount / $elapsedTime.TotalSeconds, 2) } else { 0 }
                        Write-Log ("Progress: " + $fileCount + " files processed (" + $exeCount + " .exe, " + $batCount + " .bat) - " + $rate + " files/sec") "SUCCESS"
                    }
                    
                    # Get additional file information
                    $appName = Get-ApplicationName -FilePath $fullPath
                    $publisher = Get-FilePublisher -FilePath $fullPath
                    $sha256Hash = Get-FileHash256 -FilePath $fullPath
                    $md5Hash = Get-FileHashMD5 -FilePath $fullPath
                    
                    # Create a custom object with the file information
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
                    
                    # Write directly to CSV
                    Write-ResultToCSV -FileInfo $fileInfo -Path $OutputPath
                    
                    # Display sample data for the first few files
                    if ($fileCount -le 5) {
                        Write-Log ("Sample data for file: " + $fileName) "INFO"
                        Write-Log ("  Application: " + $appName) "INFO"
                        Write-Log ("  Publisher: " + $publisher) "INFO"
                        Write-Log ("  Path: " + $installPath) "INFO"
                        $sha256Prefix = if ($sha256Hash.Length -ge 16) { $sha256Hash.Substring(0, 16) + "..." } else { $sha256Hash }
                        Write-Log ("  SHA256: " + $sha256Prefix) "INFO"
                        Write-Log ("  MD5: " + $md5Hash) "INFO"
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-Log ("Error processing file " + $file.FullName + ": " + $errorMsg) "WARNING"
                }
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Log ("Error accessing files in directory " + $dirPath + ": " + $errorMsg) "WARNING"
        }
    }
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Log ("Critical error during scanning: " + $errorMsg) "ERROR"
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Verify the output file exists and has content
if (Test-Path -Path $OutputPath) {
    $fileSize = (Get-Item -Path $OutputPath).Length
    $lineCount = (Get-Content -Path $OutputPath | Measure-Object -Line).Lines
    
    Write-Log ("Output file exists. Size: " + $fileSize + " bytes, Lines: " + $lineCount) "INFO"
    
    if ($lineCount -le 1) {
        Write-Log "WARNING: Output file appears to be empty (only header row)" "WARNING"
    }
} else {
    Write-Log "ERROR: Output file does not exist!" "ERROR"
}

# Display final statistics
Write-Log "`n===== SCAN COMPLETE =====" "SUCCESS"
Write-Log ("Total files found: " + $fileCount) "SUCCESS"
Write-Log ("  - EXE files: " + $exeCount) "SUCCESS"
Write-Log ("  - BAT files: " + $batCount) "SUCCESS"
Write-Log ("Directories scanned: " + $directoriesScanned) "SUCCESS"
$durationMinutes = $duration.TotalMinutes.ToString("0.00")
$durationSeconds = $duration.TotalSeconds.ToString("0.00")
Write-Log ("Scan duration: " + $durationMinutes + " minutes (" + $durationSeconds + " seconds)") "SUCCESS"
$processingRate = [math]::Round($fileCount / $duration.TotalSeconds, 2)
Write-Log ("Average processing rate: " + $processingRate + " files/second") "SUCCESS"
Write-Log ("Results saved to: " + $OutputPath) "SUCCESS"

Write-Host "`nScript completed. Check log file for details: $logPath" -ForegroundColor Cyan
