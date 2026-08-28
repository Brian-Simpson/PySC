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
    
    # Optionally, you can also write to a log file
    # Add-Content -Path "RemoteExecutionTest_$(Get-Date -Format 'yyyyMMdd').log" -Value $logMessage
}

# Function to test remote execution on a device
function Test-RemoteExecution {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [string]$TestCommand = "Get-ComputerInfo | Select csname",
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 30,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        Success = $false
        Output = $null
        Error = $null
        ExecutionTime = $null
    }
    
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
        
        # Check if TimeoutSec parameter is supported
        $cmdletInfo = Get-Command Invoke-Command
        $hasTimeoutParam = $cmdletInfo.Parameters.Keys -contains "TimeoutSec"
        
        # Add timeout if supported
        if ($TimeoutSeconds -gt 0 -and $hasTimeoutParam) {
            $params.Add("TimeoutSec", $TimeoutSeconds)
        }
        
        # Execute the command remotely
        $output = Invoke-Command @params
        
        $endTime = Get-Date
        $executionTime = ($endTime - $startTime).TotalSeconds
        
        # Update result with success information
        $result.Success = $true
        $result.Output = $output
        $result.ExecutionTime = $executionTime
        
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

# Define the list of computers to test
# You can replace this with a parameter, read from a file, or query from AD
$computers = @(
    "HTHHS4RVW3", #Anon test
    "HTH992QSV3",
    "HTH72LCGB3",
    "HTH9S9CGB3",
    "HTH4VCR9K3",
    "HTHJP86DK3",
    "HTH7QGZVV3", # Anon test
    "HTH2RR46D3"
    # Add more computers as needed
)

# Optional: Prompt for credentials
$useCredentials = Read-Host "Do you want to use specific credentials? (Y/N)"
$credential = $null

if ($useCredentials -eq "Y" -or $useCredentials -eq "y") {
    $credential = Get-Credential -Message "Enter credentials for remote execution"
}

# Optional: Define a custom test command
$defaultCommand = "Get-ComputerInfo | Select csname"
$customCommand = Read-Host "Enter a custom PowerShell command to execute remotely (leave blank for default)"

if ([string]::IsNullOrWhiteSpace($customCommand)) {
    $testCommand = $defaultCommand
} else {
    $testCommand = $customCommand
}

# Results collection
$results = @()

# Test each computer
foreach ($computer in $computers) {
    $params = @{
        ComputerName = $computer
        TestCommand = $testCommand
    }
    
    if ($credential) {
        $params.Add("Credential", $credential)
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
$results | Format-Table -Property ComputerName, Success, ExecutionTime, Error -AutoSize

# Export results to CSV (optional)
$exportCsv = Read-Host "Do you want to export results to CSV? (Y/N)"
if ($exportCsv -eq "Y" -or $exportCsv -eq "y") {
    $csvPath = "RemoteExecutionResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Log "Results exported to $csvPath" -Level "INFO"
}

# Optional: Create an HTML report
$createHtml = Read-Host "Do you want to create an HTML report? (Y/N)"
if ($createHtml -eq "Y" -or $createHtml -eq "y") {
    $htmlPath = "RemoteExecutionResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Remote Execution Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        th { background-color: #4CAF50; color: white; }
        .success { color: green; }
        .failure { color: red; }
    </style>
</head>
<body>
    <h1>Remote Execution Test Results</h1>
    <p>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <h2>Summary</h2>
    <ul>
        <li>Total computers tested: $($results.Count)</li>
        <li>Successful connections: $($results.Where({$_.Success -eq $true}).Count)</li>
        <li>Failed connections: $($results.Where({$_.Success -eq $false}).Count)</li>
    </ul>
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Computer Name</th>
            <th>Status</th>
            <th>Execution Time (s)</th>
            <th>Error</th>
        </tr>
"@

    $htmlRows = ""
    foreach ($result in $results) {
        $statusClass = if ($result.Success) { "success" } else { "failure" }
        $status = if ($result.Success) { "Success" } else { "Failed" }
        $htmlRows += @"
        <tr>
            <td>$($result.ComputerName)</td>
            <td class="$statusClass">$status</td>
            <td>$($result.ExecutionTime)</td>
            <td>$($result.Error)</td>
        </tr>
"@
    }

    $htmlFooter = @"
    </table>
    <h2>Test Command</h2>
    <pre>$testCommand</pre>
</body>
</html>
"@

    $htmlContent = $htmlHeader + $htmlRows + $htmlFooter
    $htmlContent | Out-File -FilePath $htmlPath
    Write-Log "HTML report created at $htmlPath" -Level "INFO"
}

Write-Log "Remote execution test script completed" -Level "INFO"
