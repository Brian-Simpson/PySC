# Application Inventory Script with Hash Values
# This script collects application inventory from remote systems and saves to a single CSV file

# Function to write log messages with timestamps
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with color based on level
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage }
    }
}

# Define the computers to test
$domain = "HillTop.Global"
$computers = @(
    "HTH9S9CGB3.$domain",
    "HTH4VCR9K3.$domain",
    "HTH2RR46D3.$domain"
)

# Set up credentials
$username = "HTH-Priv2-BSimpson"
$password = ConvertTo-SecureString "j-8@e#kalr&|sTFQ[{" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
Write-Log "Using credentials for user: $username" -Level "INFO"

# Define output file paths
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$resultsFile = "RemoteExecutionResults_$timestamp.csv"
$inventoryFile = "Application_Inventory_$timestamp.csv"

Write-Log "Results will be saved to: $resultsFile" -Level "INFO"
Write-Log "Application inventory will be saved to: $inventoryFile" -Level "INFO"

# Define the remote command to collect application inventory
$remoteCommand = @"
# Get basic system info
`$computerName = `$env:COMPUTERNAME
`$osInfo = Get-WmiObject -Class Win32_OperatingSystem
`$osVersion = `$osInfo.Caption

# Define directories to search
`$directories = @(
    "C:\Program Files",
    "C:\Program Files (x86)"
)

# Add user profiles if they exist
if (Test-Path "C:\Users") {
    `$userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                    Where-Object { `$_.Name -ne "Public" -and `$_.Name -ne "Default" -and `$_.Name -ne "Default User" }
    foreach (`$profile in `$userProfiles) {
        `$directories += `$profile.FullName
    }
}

# Output CSV header
Write-Output "ComputerName,ExecutableName,Directory,FileSize,Publisher,FileVersion,ProductVersion,MD5Hash,SHA256Hash,LastModified"

# Process each directory
`$totalFiles = 0
foreach (`$directory in `$directories) {
    if (Test-Path `$directory) {
        try {
            # Find all executable files (limit to first 100 per directory to avoid timeouts)
            `$exeFiles = Get-ChildItem -Path `$directory -Include "*.exe" -Recurse -ErrorAction SilentlyContinue | 
                        Select-Object -First 100
            
            foreach (`$file in `$exeFiles) {
                try {
                    `$fileVersionInfo = `$file | Get-ItemProperty | Select-Object -Property VersionInfo, Length, LastWriteTime
                    `$publisher = if (`$fileVersionInfo.VersionInfo.CompanyName) { `$fileVersionInfo.VersionInfo.CompanyName.Replace(",", ";") } else { "Unknown" }
                    `$fileVersion = if (`$fileVersionInfo.VersionInfo.FileVersion) { `$fileVersionInfo.VersionInfo.FileVersion.Replace(",", ";") } else { "Unknown" }
                    `$productVersion = if (`$fileVersionInfo.VersionInfo.ProductVersion) { `$fileVersionInfo.VersionInfo.ProductVersion.Replace(",", ";") } else { "Unknown" }
                    
                    # Calculate hash values
                    `$md5Hash = (Get-FileHash -Algorithm MD5 -Path `$file.FullName -ErrorAction SilentlyContinue).Hash
                    `$sha256Hash = (Get-FileHash -Algorithm SHA256 -Path `$file.FullName -ErrorAction SilentlyContinue).Hash
                    
                    # Output CSV line directly
                    Write-Output "`$computerName,`$(`$file.Name.Replace(",", ";")),`$(`$file.DirectoryName.Replace(",", ";")),`$(`$fileVersionInfo.Length),`$publisher,`$fileVersion,`$productVersion,`$md5Hash,`$sha256Hash,`$(`$fileVersionInfo.LastWriteTime)"
                    `$totalFiles++
                }
                catch {
                    # Skip files that cause errors
                    continue
                }
            }
        }
        catch {
            # Skip directories that cause errors
            continue
        }
    }
}

# Return summary information
Write-Output "--------------------------------------"
Write-Output "Total executables found: `$totalFiles"
"@

# Create a collection for all application data
$allApplicationData = @()
$csvHeader = "ComputerName,ExecutableName,Directory,FileSize,Publisher,FileVersion,ProductVersion,MD5Hash,SHA256Hash,LastModified"

# Add header to the inventory file
$csvHeader | Out-File -FilePath $inventoryFile -Encoding ASCII

# Results collection for execution status
$results = @()

# Process each computer
foreach ($computer in $computers) {
    Write-Log "Processing computer: $computer" -Level "INFO"
    
    $result = New-Object PSObject -Property @{
        ComputerName = $computer
        Success = $false
        PingStatus = "Not Tested"
        WinRMStatus = "Not Tested"
        ExecutionTime = $null
        Error = $null
        ApplicationCount = 0
    }
    
    try {
        # Test connection first
        $pingResult = Test-Connection -ComputerName $computer -Count 1 -Quiet
        $result.PingStatus = if ($pingResult) { "Success" } else { "Failed" }
        
        if (-not $pingResult) {
            $result.Error = "Cannot ping host"
            Write-Log "Cannot ping $computer - skipping" -Level "WARNING"
            $results += $result
            continue
        }
        
        # Test WinRM
        try {
            $winrmTest = Test-WSMan -ComputerName $computer -ErrorAction Stop
            $result.WinRMStatus = "Enabled"
        }
        catch {
            $result.WinRMStatus = "Disabled/Error"
            $result.Error = "WinRM error: $($_.Exception.Message)"
            Write-Log "WinRM not available on $computer - $($_.Exception.Message)" -Level "ERROR"
            $results += $result
            continue
        }
        
        # Execute the remote command
        Write-Log "Executing inventory command on $computer..." -Level "INFO"
        $startTime = Get-Date
        
        $output = Invoke-Command -ComputerName $computer -ScriptBlock ([ScriptBlock]::Create($remoteCommand)) -Credential $credential -ErrorAction Stop
        
        $endTime = Get-Date
        $executionTime = ($endTime - $startTime).TotalSeconds
        $result.ExecutionTime = $executionTime
        Write-Log "Command completed in $executionTime seconds" -Level "INFO"
        
        # Process the output
        if ($output -and $output.Count -gt 0) {
            # Extract CSV lines (lines containing commas)
            $csvLines = $output | Where-Object { $_ -match "," -and $_ -ne $csvHeader -and -not $_.StartsWith("---") }
            
            if ($csvLines -and $csvLines.Count -gt 0) {
                # Append to the inventory file
                $csvLines | Out-File -FilePath $inventoryFile -Encoding ASCII -Append
                
                $result.ApplicationCount = $csvLines.Count
                Write-Log "Found $($csvLines.Count) applications on $computer" -Level "INFO"
            }
            else {
                Write-Log "No application data found in output from $computer" -Level "WARNING"
            }
        }
        else {
            Write-Log "No output received from $computer" -Level "WARNING"
        }
        
        $result.Success = $true
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Log "Error processing $computer - $($_.Exception.Message)" -Level "ERROR"
    }
    
    $results += $result
}

# Save execution results
$results | Export-Csv -Path $resultsFile -NoTypeInformation
Write-Log "Execution results saved to: $resultsFile" -Level "INFO"

# Count total applications
$totalApplications = (Get-Content -Path $inventoryFile | Measure-Object).Count - 1
Write-Log "Total applications found across all systems: $totalApplications" -Level "INFO"

# Display summary
Write-Log "Remote Execution Test Results Summary:" -Level "INFO"
Write-Log "----------------------------------------" -Level "INFO"
Write-Log "Total computers tested: $($results.Count)" -Level "INFO"
Write-Log "Successful connections: $($results.Where({$_.Success -eq $true}).Count)" -Level "INFO"
Write-Log "Failed connections: $($results.Where({$_.Success -eq $false}).Count)" -Level "INFO"
Write-Log "Total applications found: $totalApplications" -Level "INFO"
Write-Log "----------------------------------------" -Level "INFO"

# Display detailed results
$results | Format-Table -Property ComputerName, Success, PingStatus, WinRMStatus, ExecutionTime, ApplicationCount, Error -AutoSize

Write-Log "Application inventory collection completed" -Level "INFO"
Write-Log "Application inventory saved to: $inventoryFile" -Level "INFO"
