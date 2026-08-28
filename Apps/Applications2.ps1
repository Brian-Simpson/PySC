# PowerShell Script to Test Remote Execution on Multiple Devices
# This script tests the ability to execute commands on remote devices
# and reports success or failure for each device

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

# Function to test remote execution on a device
function Test-RemoteExecution {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [string]$TestCommand,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $result = New-Object PSObject -Property @{
        ComputerName = $ComputerName
        Success = $false
        Output = $null
        Error = $null
        ExecutionTime = $null
        WinRMStatus = "Not Tested"
        PingStatus = "Not Tested"
        AppInventoryPath = $null
    }
    
    # Check basic connectivity first
    try {
        Write-Log "Testing connectivity to $ComputerName..." -Level "INFO"
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
        $result.PingStatus = if ($pingResult) { "Success" } else { "Failed" }
        
        if (-not $pingResult) {
            $result.Error = "Cannot ping host"
            Write-Log "Cannot ping $ComputerName" -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.PingStatus = "Error"
        $result.Error = "Ping error: $($_.Exception.Message)"
        Write-Log "Error pinging $ComputerName`: $($_.Exception.Message)" -Level "ERROR"
        return $result
    }
    
    # Check WinRM status
    try {
        Write-Log "Testing WinRM connectivity to $ComputerName..." -Level "INFO"
        $winrmTest = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        $result.WinRMStatus = "Enabled"
    }
    catch {
        $result.WinRMStatus = "Disabled/Error"
        $result.Error = "WinRM error: $($_.Exception.Message)"
        Write-Log "WinRM not available on $ComputerName`: $($_.Exception.Message)" -Level "ERROR"
        return $result
    }
    
    # Now try the actual remote execution
    try {
        Write-Log "Testing remote execution on $ComputerName..." -Level "INFO"
        
        $startTime = Get-Date
        
        # Prepare the parameters for Invoke-Command
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = [ScriptBlock]::Create($TestCommand)
            ErrorAction = "Stop"
        }
        
        # Add credential if provided
        if ($Credential) {
            $params.Add("Credential", $Credential)
        }
        
        # Execute the command remotely
        $output = Invoke-Command @params
        
        $endTime = Get-Date
        $executionTime = ($endTime - $startTime).TotalSeconds
        
        # Update result with success information
        $result.Success = $true
        $result.Output = $output
        $result.ExecutionTime = $executionTime
        $result.Error = $null
        
        # If the output contains a path to an app inventory CSV, store it
        if ($output -match "AppInventory CSV saved to: (.+\.csv)") {
            $result.AppInventoryPath = $matches[1]
            Write-Log "Application inventory created at $($matches[1]) on $ComputerName" -Level "INFO"
        }
        
        Write-Log "Successfully executed command on $ComputerName (took $executionTime seconds)" -Level "INFO"
    }
    catch {
        $endTime = Get-Date
        $executionTime = ($endTime - $startTime).TotalSeconds
        
        $result.Error = $_.Exception.Message
        $result.ExecutionTime = $executionTime
        
        Write-Log "Failed to execute command on $ComputerName`: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $result
}

# Main script execution
Write-Log "Starting remote execution test script" -Level "INFO"
Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level "INFO"

# Define the list of computers to test
# Adding domain suffix to each computer name
$domain = "HillTop.Global"
$computers = @(
   # "HTHHS4RVW3.$domain", #Anon test
   # "HTH992QSV3.$domain",
   # "HTH72LCGB3.$domain",
    "HTH9S9CGB3.$domain",
    "HTH4VCR9K3.$domain",
   # "HTHJP86DK3.$domain",
   # "HTH7QGZVV3.$domain", # Anon test
    "HTH2RR46D3.$domain"
)

Write-Log "Total endpoints to test: $($computers.Count)" -Level "INFO"

# Set up credentials as specified
$username = "HTH-Priv2-BSimpson"
$password = ConvertTo-SecureString "j-8@e#kalr&|sTFQ[{" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
Write-Log "Using credentials for user: $username" -Level "INFO"

# Define the enhanced PowerShell command for application inventory
$testCommand = @"
# Create a timestamp for unique filenames
`$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
`$computerName = `$env:COMPUTERNAME
`$outputPath = "`$env:TEMP\AppInventory_`${computerName}_`${timestamp}.csv"

# Create CSV file with headers
"ComputerName,ExecutableName,Directory,FileSize,Publisher,FileVersion,ProductVersion,LastModified" | Out-File -FilePath `$outputPath -Encoding ASCII

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

# Process each directory
`$totalFiles = 0
foreach (`$directory in `$directories) {
    if (Test-Path `$directory) {
        try {
            # Find all executable files (limit to first 500 per directory to avoid timeouts)
            `$exeFiles = Get-ChildItem -Path `$directory -Include "*.exe" -Recurse -ErrorAction SilentlyContinue | 
                        Select-Object -First 500
            
            foreach (`$file in `$exeFiles) {
                try {
                    `$fileVersionInfo = `$file | Get-ItemProperty | Select-Object -Property VersionInfo, Length, LastWriteTime
                    `$publisher = if (`$fileVersionInfo.VersionInfo.CompanyName) { `$fileVersionInfo.VersionInfo.CompanyName.Replace(",", ";") } else { "Unknown" }
                    `$fileVersion = if (`$fileVersionInfo.VersionInfo.FileVersion) { `$fileVersionInfo.VersionInfo.FileVersion.Replace(",", ";") } else { "Unknown" }
                    `$productVersion = if (`$fileVersionInfo.VersionInfo.ProductVersion) { `$fileVersionInfo.VersionInfo.ProductVersion.Replace(",", ";") } else { "Unknown" }
                    
                    # Create CSV line (replace commas in fields to avoid CSV parsing issues)
                    "`$computerName,`$(`$file.Name.Replace(",", ";")),`$(`$file.DirectoryName.Replace(",", ";")),`$(`$fileVersionInfo.Length),`$publisher,`$fileVersion,`$productVersion,`$(`$fileVersionInfo.LastWriteTime)" | 
                    Out-File -FilePath `$outputPath -Encoding ASCII -Append
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

# Return information about the CSV file
Write-Output "AppInventory CSV saved to: `$outputPath"
Write-Output "Total executables found: `$totalFiles"

# Return the content of the CSV file directly
Get-Content -Path `$outputPath
"@

Write-Log "Using enhanced application inventory command" -Level "INFO"

# Results collection
$results = @()

# Test each computer
foreach ($computer in $computers) {
    Write-Log "Processing computer: $computer" -Level "INFO"
    
    $params = @{
        ComputerName = $computer
        TestCommand = $testCommand
        Credential = $credential
    }
    
    $result = Test-RemoteExecution @params
    $results += $result
}

# Display summary
Write-Log "Remote Execution Test Results Summary:" -Level "INFO"
Write-Log "----------------------------------------" -Level "INFO"
Write-Log "Total computers tested: $($results.Count)" -Level "INFO"
Write-Log "Successful connections: $($results.Where({$_.Success -eq $true}).Count)" -Level "INFO"
Write-Log "Failed connections: $($results.Where({$_.Success -eq $false}).Count)" -Level "INFO"
Write-Log "----------------------------------------" -Level "INFO"

# Display detailed results
$results | Format-Table -Property ComputerName, Success, PingStatus, WinRMStatus, ExecutionTime, Error -AutoSize

# Always export results to CSV
$csvPath = "RemoteExecutionResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Log "Results exported to $csvPath" -Level "INFO"

# Create directory for application inventory
$appInventoryDir = "AppInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $appInventoryDir -Force | Out-Null
Write-Log "Created directory for application inventory: $appInventoryDir" -Level "INFO"

# Process successful results to extract application inventory
$successfulResults = $results | Where-Object { $_.Success -eq $true }
$inventoryFilesCreated = 0

foreach ($result in $successfulResults) {
    $computerName = $result.ComputerName
    $output = $result.Output
    
    # Skip if no output
    if (-not $output) {
        Write-Log "No output received from $computerName" -Level "WARNING"
        continue
    }
    
    # Extract CSV content from the output
    $csvContent = $output | Where-Object { $_ -match "," }
    
    if ($csvContent -and $csvContent.Count -gt 0) {
        $inventoryFilePath = Join-Path -Path $appInventoryDir -ChildPath "AppInventory_$($computerName.Split('.')[0]).csv"
        $csvContent | Out-File -FilePath $inventoryFilePath -Encoding ASCII
        Write-Log "Saved application inventory for $computerName to $inventoryFilePath" -Level "INFO"
        $inventoryFilesCreated++
    }
    else {
        Write-Log "No CSV content found in output from $computerName" -Level "WARNING"
    }
}

# Check if any inventory files were created
if ($inventoryFilesCreated -gt 0) {
    # Get all inventory files
    $inventoryFiles = Get-ChildItem -Path $appInventoryDir -Filter "AppInventory_*.csv"
    
    if ($inventoryFiles -and $inventoryFiles.Count -gt 0) {
        # Combine all CSV files into one master file
        $combinedCsvPath = Join-Path -Path $appInventoryDir -ChildPath "Combined_AppInventory.csv"
        $header = $null
        $first = $true
        
        foreach ($file in $inventoryFiles) {
            $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
            
            if ($content -and $content.Count -gt 0) {
                if ($first) {
                    $header = $content[0]
                    $content | Out-File -FilePath $combinedCsvPath -Encoding ASCII
                    $first = $false
                }
                else {
                    $content | Select-Object -Skip 1 | Out-File -FilePath $combinedCsvPath -Encoding ASCII -Append
                }
            }
        }
        
        Write-Log "Combined application inventory saved to $combinedCsvPath" -Level "INFO"
    }
    else {
        Write-Log "No inventory files found to combine" -Level "WARNING"
    }
}
else {
    Write-Log "No application inventory files were created" -Level "WARNING"
}

Write-Log "Remote execution test script completed" -Level "INFO"
