# $username = "hilltop.global\HTH-Priv2-BSimpson" # Replace with actual domain and username
# $password = ConvertTo-SecureString "l.$!H|nzITva4M*]RqBs" -AsPlainText -Force # Replace with actual password
# HTHJP86DK3
# HTH9S9CGB3
# HTH4VCR9K3
# HTH992QSV3
# HTH2RR46D3


# Script to inventory .exe and .bat files across Windows 11 endpoints
# Fixed version with frequent count notifications and multi-computer support

param(
    [string]$SearchPath = "C:\",        # Default to C:\ but can be changed
    [string]$OutputPath = "C:\PySC\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$MaxThreads = 8,               # Number of parallel threads to use
    [int]$ProgressInterval = 100,       # Show progress every 100 files
    [string[]]$ComputerNames = @(),     # Array of computer names to scan
    [PSCredential]$Credential          # Credentials for remote execution
)

# Enhanced parameter handling for ComputerNames
Write-Host "Debug: ComputerNames parameter received: $($ComputerNames -join ', ')" -ForegroundColor Gray
Write-Host "Debug: ComputerNames count: $($ComputerNames.Count)" -ForegroundColor Gray
Write-Host "Debug: ComputerNames type: $($ComputerNames.GetType().Name)" -ForegroundColor Gray

# Convert single string with commas to array if needed
if ($ComputerNames.Count -eq 1 -and $ComputerNames[0] -match ',') {
    $ComputerNames = $ComputerNames[0] -split ',' | ForEach-Object { $_.Trim() }
    Write-Host "Debug: Converted comma-separated string to array: $($ComputerNames -join ', ')" -ForegroundColor Gray
}

# Remove any empty entries
$ComputerNames = $ComputerNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

# Predefined list of devices for remote execution
$predefinedDevices = @(
    "HTHJP86DK3.hilltop.global",
    "HTH9S9CGB3.hilltop.global",
    "HTH4VCR9K3.hilltop.global",
    "HTH992QSV3.hilltop.global",
    "HTH2RR46D3.hilltop.global"
)

# Enhanced computer selection with predefined list
if ($ComputerNames.Count -eq 0) {
    Write-Host "`n===== COMPUTER SELECTION =====" -ForegroundColor Cyan
    Write-Host "Choose an option:" -ForegroundColor Yellow
    Write-Host "1. Select from predefined device list" -ForegroundColor White
    Write-Host "2. Enter custom computer names" -ForegroundColor White
    Write-Host "3. Run locally only" -ForegroundColor White
    
    do {
        $choice = Read-Host "`nEnter choice (1-3)"
    } while ($choice -notmatch '^[123]$')
    
    switch ($choice) {
        "1" {
            Write-Host "`n===== PREDEFINED DEVICE LIST =====" -ForegroundColor Cyan
            Write-Host "Available devices:" -ForegroundColor Yellow
            
            for ($i = 0; $i -lt $predefinedDevices.Count; $i++) {
                Write-Host "  $($i + 1). $($predefinedDevices[$i])" -ForegroundColor White
            }
            
            Write-Host "`nSelect devices by number (comma-separated, e.g., 1,3,5) or 'all' for all devices:" -ForegroundColor Yellow
            $deviceSelection = Read-Host "Device selection"
            
            if ($deviceSelection.ToLower() -eq "all") {
                $ComputerNames = $predefinedDevices
                Write-Host "Selected all devices" -ForegroundColor Green
            }
            else {
                $selectedIndices = $deviceSelection -split ',' | ForEach-Object { 
                    $index = $_.Trim()
                    if ($index -match '^\d+$' -and [int]$index -ge 1 -and [int]$index -le $predefinedDevices.Count) {
                        [int]$index - 1
                    }
                } | Where-Object { $_ -ne $null }
                
                if ($selectedIndices.Count -gt 0) {
                    $ComputerNames = $selectedIndices | ForEach-Object { $predefinedDevices[$_] }
                    Write-Host "Selected devices:" -ForegroundColor Green
                    foreach ($device in $ComputerNames) {
                        Write-Host "  - $device" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "No valid devices selected. Running locally." -ForegroundColor Yellow
                    $ComputerNames = @()
                }
            }
        }
        
        "2" {
            Write-Host "`n===== CUSTOM COMPUTER ENTRY =====" -ForegroundColor Cyan
            Write-Host "Enter computer names to scan (one per line, empty line to finish):" -ForegroundColor Yellow
            
            $inputComputers = @()
            do {
                $computerName = Read-Host "Computer name"
                if (![string]::IsNullOrWhiteSpace($computerName)) {
                    $inputComputers += $computerName.Trim()
                    Write-Host "Added: $($computerName.Trim())" -ForegroundColor Green
                }
            } while (![string]::IsNullOrWhiteSpace($computerName))
            
            $ComputerNames = $inputComputers
        }
        
        "3" {
            Write-Host "Selected local execution only" -ForegroundColor Cyan
            $ComputerNames = @()
        }
    }
}

# If no computers specified after selection, run locally
if ($ComputerNames.Count -eq 0) {
    Write-Host "No remote computers specified. Running locally on: $env:COMPUTERNAME" -ForegroundColor Cyan
    $ComputerNames = @($env:COMPUTERNAME)
    $isLocal = $true
} else {
    $isLocal = $false
    Write-Host "`nWill scan the following computers:" -ForegroundColor Cyan
    foreach ($comp in $ComputerNames) {
        Write-Host "  - $comp" -ForegroundColor Yellow
    }
    
    # Confirm selection for remote execution
    Write-Host "`nProceed with scanning these $($ComputerNames.Count) computer(s)? (y/n):" -ForegroundColor Yellow
    $confirm = Read-Host "Confirm"
    if ($confirm.ToLower() -ne 'y' -and $confirm.ToLower() -ne 'yes') {
        Write-Host "Operation cancelled by user." -ForegroundColor Red
        exit
    }
}
# Get credentials for remote execution if needed
if (-not $isLocal) {
    if ($null -eq $Credential) {
        # FOR TESTING ONLY - Updated with better error handling
        $testUsername = "YOURDOMAIN\yourusername"  # Update this with actual credentials
        $testPassword = "YourActualPassword!"      # Update this with actual password
        
        Write-Host "`nUsing hardcoded test credentials for: $testUsername" -ForegroundColor Yellow
        Write-Host "WARNING: This is for testing only - credentials are stored in plain text!" -ForegroundColor Red
        
        try {
            $securePassword = ConvertTo-SecureString $testPassword -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($testUsername, $securePassword)
            Write-Host "Test credentials created successfully" -ForegroundColor Green
            
            # Test the credentials format
            Write-Host "Username: $($Credential.UserName)" -ForegroundColor Cyan
        }
        catch {
            Write-Host "Failed to create test credentials: $_" -ForegroundColor Red
            Write-Host "Falling back to credential prompt..." -ForegroundColor Yellow
            $Credential = Get-Credential -Message "Enter credentials for remote computers"
            if ($null -eq $Credential) {
                Write-Host "No credentials provided. Exiting." -ForegroundColor Red
                exit
            }
        }
    }
}

# Function to execute inventory on a single computer
function Invoke-ComputerInventory {
    param(
        [string]$ComputerName,
        [bool]$IsLocal,
        [PSCredential]$Credential,
        [string]$SearchPath,
        [int]$MaxThreads,
        [int]$ProgressInterval
    )
    
    $inventoryScriptBlock = {
        param($SearchPath, $MaxThreads, $ProgressInterval, $TargetComputer)
        
        # Define directories to exclude
        $excludedDirs = @(
            "C:\Windows\System32",
            "C:\Windows\SysWOW64",
            "C:\Windows\WinSxS"
        )
        
        Write-Host "`n===== SCANNING: $TargetComputer =====" -ForegroundColor Cyan
        Write-Host "Scanning all .exe and .bat files in $SearchPath" -ForegroundColor Yellow
        Write-Host "Using $MaxThreads parallel threads for processing" -ForegroundColor Yellow
        Write-Host "Progress updates every $ProgressInterval files" -ForegroundColor Yellow
        Write-Host "Excluding directories:" -ForegroundColor Yellow
        foreach ($dir in $excludedDirs) {
            Write-Host "  - $dir" -ForegroundColor Yellow
        }
        
        # Create output path for this computer
        $computerOutputPath = "C:\Temp\FileInventory_$($TargetComputer)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        # Ensure output directory exists
        $outputDir = Split-Path -Path $computerOutputPath -Parent
        if (-not (Test-Path -Path $outputDir)) {
            try {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
                Write-Host "Created output directory: $outputDir" -ForegroundColor Green
            }
            catch {
                Write-Host "Error creating output directory: $_" -ForegroundColor Red
                return $null
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
        Write-Host "Output will be saved to: $computerOutputPath" -ForegroundColor Cyan
        
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
            $headers -join ',' | Out-File -FilePath $computerOutputPath -Encoding UTF8
            Write-Host "Successfully created CSV file with headers" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create CSV file: $_" -ForegroundColor Red
            return $null
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
        
        $script:startTime = Get-Date
        $script:searchStartTime = Get-Date
        
        Write-Host "Starting file inventory scan..." -ForegroundColor Cyan
        Write-Host "Search will start from: $SearchPath" -ForegroundColor Cyan
        
        # Verify the search path exists
        if (-not (Test-Path -Path $SearchPath)) {
            Write-Host "ERROR: Search path does not exist: $SearchPath" -ForegroundColor Red
            return $null
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
                    if ($fileCounter % 100 -eq 0) {
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
            return $null
        }
        
        $totalFiles = $allFiles.Count
        Write-Host "Found a total of $totalFiles files to process ($exeFoundCount .exe, $batFoundCount .bat)" -ForegroundColor Green
        
        if ($totalFiles -eq 0) {
            Write-Host "No files found! Try running the script with administrator privileges." -ForegroundColor Red
            return $computerOutputPath
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
                    
                    # Write results to CSV - Fixed to use actual result data
                    if ($result.Results.Count -gt 0) {
                        foreach ($fileResult in $result.Results) {
                            # Escape commas and quotes in CSV data
                            $escapedAppName = ($fileResult.ApplicationName -replace '"', '""' -replace ',', '')
                            $escapedPublisher = ($fileResult.Publisher -replace '"', '""' -replace ',', '')
                            $escapedFileName = ($fileResult.FileName -replace '"', '""' -replace ',', '')
                            $escapedInstallPath = ($fileResult.InstallationPath -replace '"', '""' -replace ',', '')
                            
                            $csvLine = "$($fileResult.DeviceName),$($fileResult.FQDN),$escapedAppName,$escapedPublisher,$escapedFileName,$escapedInstallPath,$($fileResult.SHA256),$($fileResult.MD5)"
                            [System.IO.File]::AppendAllText($computerOutputPath, $csvLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
                        }
                    }
                    
                    # Update counters
                    $processedCount += $result.FileCount
                    $processedExe += $result.ExeCount
                    $processedBat += $result.BatCount
                    $completed++
                    
                    # Show detailed progress with file names
                    Write-Host "Processed batch $completed of $($runspaces.Count) with $($result.FileCount) files:" -ForegroundColor Green
                    foreach ($fileName in $result.ProcessedFiles) {
                        Write-Host "  - $fileName" -ForegroundColor White
                    }
                    
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
        $searchDuration = $processingStartTime - $script:searchStartTime
        $processingDuration = $endTime - $processingStartTime
        
        # Display final statistics
        Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Cyan
        Write-Host "Total files found: $processedCount" -ForegroundColor Green
        Write-Host "  - EXE files: $processedExe" -ForegroundColor Green
        Write-Host "  - BAT files: $processedBat" -ForegroundColor Green
        $durationMinutes = $duration.TotalMinutes.ToString("0.00")
        $durationSeconds = $duration.TotalSeconds.ToString("0.00")
        Write-Host "Total scan duration: $durationMinutes minutes ($durationSeconds seconds)" -ForegroundColor Green
        Write-Host "  - Search time: $($searchDuration.TotalSeconds.ToString("0.00")) seconds" -ForegroundColor Green
        Write-Host "  - Processing time: $($processingDuration.TotalSeconds.ToString("0.00")) seconds" -ForegroundColor Green
        $processingRate = [math]::Round($processedCount / $duration.TotalSeconds, 2)
        Write-Host "Average processing rate: $processingRate files/second" -ForegroundColor Green
        Write-Host "Results saved to: $computerOutputPath" -ForegroundColor Green
        
        return $computerOutputPath
    }
    
    if ($IsLocal) {
        # Execute locally
        return & $inventoryScriptBlock -SearchPath $SearchPath -MaxThreads $MaxThreads -ProgressInterval $ProgressInterval -TargetComputer $ComputerName
    } else {
        # Execute remotely
        Write-Host "Testing connection to $ComputerName..." -ForegroundColor Yellow
        
        # Test basic connectivity first
        try {
            if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop) {
                Write-Host "✓ Network connectivity confirmed to $ComputerName" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "✗ Network connectivity failed to $ComputerName" -ForegroundColor Red
            Write-Host "Skipping $ComputerName - not reachable via network" -ForegroundColor Yellow
            return $null
        }
        
        # Test WinRM service and authentication
        try {
                        # Enhanced WinRM testing with more diagnostics
            Write-Host "Testing WinRM configuration..." -ForegroundColor Yellow
            
            # Test if WinRM is listening
            $winrmTest = Test-NetConnection -ComputerName $ComputerName -Port 5985 -ErrorAction SilentlyContinue
            if ($winrmTest.TcpTestSucceeded) {
                Write-Host "✓ WinRM port 5985 is accessible" -ForegroundColor Green
            } else {
                Write-Host "✗ WinRM port 5985 is not accessible" -ForegroundColor Red
                
                # Try HTTPS port
                $winrmHttpsTest = Test-NetConnection -ComputerName $ComputerName -Port 5986 -ErrorAction SilentlyContinue
                if ($winrmHttpsTest.TcpTestSucceeded) {
                    Write-Host "✓ WinRM HTTPS port 5986 is accessible" -ForegroundColor Green
                } else {
                    Write-Host "✗ Neither WinRM port (5985/5986) is accessible" -ForegroundColor Red
                    Write-Host "  Check firewall settings on target computer" -ForegroundColor Yellow
                }
            }
            
            # Test WinRM authentication

            if ($Credential) {
                $testConnection = Test-WSMan -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
                Write-Host "✓ WinRM authentication successful with provided credentials" -ForegroundColor Green
                $useCredentials = $true
            } else {
                # Try with current user context (for domain environments)
                $testConnection = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
                Write-Host "✓ WinRM authentication successful with current user context" -ForegroundColor Green
                $useCredentials = $false
            }
        }
        catch {
            Write-Host "✗ WinRM connection failed to $ComputerName" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            
            # Simplified troubleshooting since WinRM is already configured
            Write-Host "`nTroubleshooting steps for $ComputerName" -ForegroundColor Yellow
            Write-Host "1. Verify credentials are correct: $($Credential.UserName)" -ForegroundColor Cyan
            Write-Host "2. Check if computer is online and accessible" -ForegroundColor Cyan
            Write-Host "3. Verify firewall allows WinRM traffic (port 5985/5986)" -ForegroundColor Cyan
            Write-Host "4. Ensure both computers have network connectivity" -ForegroundColor Cyan
            
            Write-Host "Skipping $ComputerName due to connection failure" -ForegroundColor Yellow
            return $null
        }
        
        # Quick PowerShell remoting test (simplified since WinRM is ready)
        try {
            Write-Host "Testing PowerShell remoting..." -ForegroundColor Yellow
            $testScriptBlock = { $env:COMPUTERNAME }
            
            if ($useCredentials) {
                $remoteComputerName = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $testScriptBlock -ErrorAction Stop
            } else {
                $remoteComputerName = Invoke-Command -ComputerName $ComputerName -ScriptBlock $testScriptBlock -ErrorAction Stop
            }
            
            Write-Host "✓ PowerShell remoting successful - connected to: $remoteComputerName" -ForegroundColor Green
        }
        catch {
            Write-Host "✗ PowerShell remoting test failed: $_" -ForegroundColor Red
            Write-Host "Skipping $ComputerName" -ForegroundColor Yellow
            return $null
        }
        
        # Execute the main inventory script remotely
        try {
            Write-Host "`nExecuting inventory script on $ComputerName..." -ForegroundColor Cyan
            Write-Host "This may take several minutes depending on the number of files..." -ForegroundColor Yellow
            
            if ($useCredentials) {
                $remoteResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $inventoryScriptBlock -ArgumentList $SearchPath, $MaxThreads, $ProgressInterval, $ComputerName -ErrorAction Stop
            } else {
                $remoteResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock $inventoryScriptBlock -ArgumentList $SearchPath, $MaxThreads, $ProgressInterval, $ComputerName -ErrorAction Stop
            }
            
            Write-Host "✓ Remote inventory execution completed successfully on $ComputerName" -ForegroundColor Green
            return $remoteResult
        }
        catch {
            Write-Host "✗ Remote inventory execution failed on $ComputerName" -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
            return $null
        }
    }
}

# Execute inventory on all specified computers
Write-Host "`n===== STARTING MULTI-COMPUTER INVENTORY =====" -ForegroundColor Cyan
Write-Host "Total computers to scan: $($ComputerNames.Count)" -ForegroundColor Yellow

$allResults = @()
$successfulScans = 0
$failedScans = 0

foreach ($computerName in $ComputerNames) {
    Write-Host "`n--- Processing: $computerName ---" -ForegroundColor Magenta
    
    $result = Invoke-ComputerInventory -ComputerName $computerName -IsLocal $isLocal -Credential $Credential -SearchPath $SearchPath -MaxThreads $MaxThreads -ProgressInterval $ProgressInterval
    
    if ($result) {
        $allResults += [PSCustomObject]@{
            ComputerName = $computerName
            OutputFile = $result
            Status = "Success"
        }
        $successfulScans++
        
        # Copy remote file to local machine if not local execution
        if (-not $isLocal) {
            try {
                $localCopyPath = $OutputPath -replace "\.csv$", "_$computerName.csv"
                $remoteFilePath = "\\$computerName\C$\Temp\$(Split-Path $result -Leaf)"
                
                # Enhanced file copy with better error handling
                if ($Credential) {
                    Copy-Item -Path $remoteFilePath -Destination $localCopyPath -Credential $Credential -ErrorAction Stop
                } else {
                    Copy-Item -Path $remoteFilePath -Destination $localCopyPath -ErrorAction Stop
                }
                Write-Host "✓ Copied results from $computerName to: $localCopyPath" -ForegroundColor Green
            }
            catch {
                Write-Host "✗ Failed to copy results from $computerName`: $_" -ForegroundColor Red
                Write-Host "  Results remain on remote computer at: $result" -ForegroundColor Yellow
            }
        }
    } else {
        $allResults += [PSCustomObject]@{
            ComputerName = $computerName
            OutputFile = "Failed"
            Status = "Failed"
        }
        $failedScans++
    }
}

# Display final summary
Write-Host "`n===== MULTI-COMPUTER SCAN COMPLETE =====" -ForegroundColor Cyan
Write-Host "Total computers scanned: $($ComputerNames.Count)" -ForegroundColor Green
Write-Host "Successful scans: $successfulScans" -ForegroundColor Green
Write-Host "Failed scans: $failedScans" -ForegroundColor Red

Write-Host "`nScan Results:" -ForegroundColor Yellow
foreach ($result in $allResults) {
    $statusColor = if ($result.Status -eq "Success") { "Green" } else { "Red" }
    Write-Host "  $($result.ComputerName): $($result.Status)" -ForegroundColor $statusColor
    if ($result.Status -eq "Success") {
        Write-Host "    Output: $($result.OutputFile)" -ForegroundColor Gray
    }
}

Write-Host "`nInventory scan complete. Check the output files for detailed results." -ForegroundColor Cyan

# END OF SCRIPT
