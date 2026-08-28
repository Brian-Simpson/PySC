# File Inventory Scanner for Tenable Custom Audit
# This script finds .exe and .bat files and collects metadata about them

# Define output path in temp directory
$OutputPath = "$env:TEMP\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$MaxThreads = 4
$SearchPath = "C:\"

# Define directories to exclude
$excludedDirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64", 
    "C:\Windows\WinSxS"
)

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

# Get computer information
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$deviceName = $env:COMPUTERNAME
try {
    $domain = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
    $fqdn = "$deviceName.$domain"
}
catch {
    $fqdn = $deviceName
}

# Create CSV headers
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
}
catch {
    # If we can't write to temp, try another location
    $OutputPath = "$env:USERPROFILE\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $headers -join ',' | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Start collecting files
$allFiles = New-Object System.Collections.ArrayList
$fileCounter = 0
$exeFoundCount = 0
$batFoundCount = 0

try {
    # Define search paths to optimize performance
    $searchPaths = @()
    if ($SearchPath -eq "C:\") {
        $rootDirs = Get-ChildItem -Path "C:\" -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -notmatch "^(Windows|`$Recycle\.Bin|System Volume Information|PerfLogs)$" }
        $searchPaths += $rootDirs.FullName
        
        # Include some important Windows directories
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
    
    # Search for files in each path
    $allFoundFiles = @()
    foreach ($path in $searchPaths) {
        $pathFiles = Get-ChildItem -Path $path -Include @("*.exe", "*.bat") -File -Recurse -ErrorAction SilentlyContinue
        $allFoundFiles += $pathFiles
    }
    
    # Apply exclusions to the found files
    foreach ($file in $allFoundFiles) {
        if (-not (Test-ExcludedPath -Path $file.DirectoryName)) {
            [void]$allFiles.Add($file)
            $fileCounter++
            
            if ($file.Extension -eq ".exe") {
                $exeFoundCount++
            } else {
                $batFoundCount++
            }
        }
    }
}
catch {
    # Continue with any files we found
}

# Process files in parallel using runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$runspacePool.Open()

# Split files into batches for parallel processing
$batchSize = [Math]::Max(1, [Math]::Ceiling($allFiles.Count / $MaxThreads / 5))
$fileBatches = [System.Collections.ArrayList]::new()

for ($i = 0; $i -lt $allFiles.Count; $i += $batchSize) {
    $batch = $allFiles[$i..([Math]::Min($i + $batchSize - 1, $allFiles.Count - 1))]
    [void]$fileBatches.Add($batch)
}

$runspaces = @()
$scriptBlock = {
    param($files, $deviceName, $fqdn)
    
    $results = @()
    
    foreach ($file in $files) {
        try {
            $fileName = $file.Name
            $installPath = $file.DirectoryName
            $fullPath = $file.FullName
            
            # Get file information
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath)
            $appName = if ($versionInfo.ProductName) { $versionInfo.ProductName } 
                      elseif ($versionInfo.FileDescription) { $versionInfo.FileDescription }
                      else { [System.IO.Path]::GetFileNameWithoutExtension($fullPath) }
            
            # Get publisher information
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
        }
        catch {
            # Skip files with errors
        }
    }
    
    return $results
}

# Start processing batches
$processedResults = @()

foreach ($batch in $fileBatches) {
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($batch).AddArgument($deviceName).AddArgument($fqdn)
    $runspace.RunspacePool = $runspacePool
    
    $runspaces += [PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
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
            if ($result.Count -gt 0) {
                foreach ($fileResult in $result) {
                    # Escape commas and quotes in CSV data
                    $escapedAppName = ($fileResult.ApplicationName -replace '"', '""' -replace ',', '')
                    $escapedPublisher = ($fileResult.Publisher -replace '"', '""' -replace ',', '')
                    $escapedFileName = ($fileResult.FileName -replace '"', '""' -replace ',', '')
                    $escapedInstallPath = ($fileResult.InstallationPath -replace '"', '""' -replace ',', '')
                    
                    $csvLine = "$($fileResult.DeviceName),$($fileResult.FQDN),$escapedAppName,$escapedPublisher,$escapedFileName,$escapedInstallPath,$($fileResult.SHA256),$($fileResult.MD5)"
                    [System.IO.File]::AppendAllText($OutputPath, $csvLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
                }
            }
            
            $completed++
            
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

# For Tenable, we need to output the results in a format it can parse
# Read the CSV file and output its contents
if (Test-Path $OutputPath) {
    $fileContents = Get-Content -Path $OutputPath -Raw
    Write-Output "FILE_INVENTORY_RESULTS:"
    Write-Output $fileContents
    
    # Clean up the temp file
    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
}
else {
    Write-Output "FILE_INVENTORY_RESULTS:No files found or error occurred"
}
