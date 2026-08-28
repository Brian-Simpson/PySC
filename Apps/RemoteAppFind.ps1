# Specify the path to your CSV file
$filePath = "C:\PySC\AppInventory1_2025.csv"
# Specify the path to your remote script (if using a file)
$remoteScriptPath = "C:\PySC\NewCombined3.ps1"

# --- Control Flag for Remote Execution ---
$RunRemoteScript = $true # Set to $true to enable remote execution for testing

# --- Embedded Credentials for Remote Test (USE WITH CAUTION - NOT RECOMMENDED FOR PRODUCTION) ---
$username = "hilltop.global\HTH-Priv2-BSimpson" # Replace with actual domain and username
$password = ConvertTo-SecureString "l.$!H|nzITva4M*]RqBs" -AsPlainText -Force # Replace with actual password
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

# --- Output File Path on Your Local Computer ---
$outputFilePath = "C:\PySC\RemoteScriptResults.txt" # Replace with your desired path and filename

# --- Initial Status Update ---
Write-Host "Starting CSV processing. Initializing..."
Write-Host "Loading and filtering CSV data..."

# --- Optimized CSV Processing with Filtering (using StreamReader and Header Check) ---

$uniqueEndpointNames = New-Object System.Collections.Generic.HashSet[string]
$fileStream = New-Object System.IO.StreamReader($filePath)

# Read the header row and determine column indices
$headerLine = $fileStream.ReadLine()
$headers = $headerLine -split ',' # Assuming comma delimiter

Write-Host "Detected Headers: $($headers -join ', ')" # Debugging line - Keep this for now!

# Find the index of the 'endpointName' and 'osVersion' columns
$endpointNameIndex = -1
$osVersionIndex = -1

# Corrected for loop syntax:
for ($i = 0; $i -lt $headers.Length; $i++) {
    if ($headers[$i].Trim() -eq "endpointName") {
        $endpointNameIndex = $i
    }
    if ($headers[$i].Trim() -eq "osVersion") {
        $osVersionIndex = $i
    }
}

Write-Host "endpointName index: $endpointNameIndex" # Debugging line - Keep this for now!
Write-Host "osVersion index: $osVersionIndex"     # Debugging line - Keep this for now!

# Check if both required columns were found
if ($endpointNameIndex -eq -1 -or $osVersionIndex -eq -1) {
    Write-Error "Could not find 'endpointName' or 'osVersion' column in the header row. Please check CSV and header names."
    $fileStream.Close()
    exit # Exit the script if required columns are missing
}

# Process the data rows
while (($line = $fileStream.ReadLine()) -ne $null) {
    $fields = $line -split ',' # Assuming comma delimiter

    # Add extra check to ensure the row has enough columns
    if ($fields.Length -gt $endpointNameIndex -and $fields.Length -gt $osVersionIndex) {
        $endpointName = $fields[$endpointNameIndex].Trim()
        $osVersion = $fields[$osVersionIndex].Trim()

        # Write-Host "Processing: EndpointName='$endpointName', OSVersion='$osVersion'" # Debugging line

        # Apply filtering conditions with the corrected osVersion value
        if (($osVersion -eq "Windows 11 Enterprise 22631") -and (($endpointName -like "HTH*"))) {
            [void]$uniqueEndpointNames.Add($endpointName) # Add unique endpointName to the HashSet
        }
    } else {
        Write-Warning "Skipping a row with insufficient columns: $line"
    }
}

$fileStream.Close()

# --- Convert HashSet to an array ---
$uniqueEndpointNamesArray = @($uniqueEndpointNames)

# Count the number of unique endpoint names
$uniqueCount = $uniqueEndpointNamesArray.Count

# Display the unique endpoint names
Write-Host "`nUnique endpoint names (Windows 11 Enterprise 22631 and starting with 'HTH*'):"
$uniqueEndpointNamesArray

Write-Host "`nTotal count of unique endpoint names (Windows 11 Enterprise 22631 and starting with 'HTH*'): $uniqueCount"

# --- Remote Script Execution (without explicit Test-WSMan) ---

if ($RunRemoteScript) {
    if ($uniqueEndpointNamesArray.Count -eq 0) {
        Write-Warning "No unique endpoints found. Remote script will not run."
    } else {
        Write-Host "`nAttempting to run remote script on all unique endpoints (WinRM test skipped): $($uniqueEndpointNamesArray.Count) found."

        # Define the script block to be executed on remote computers
        $scriptToRun = {
            # Place the contents of your C:\PySC\Combined.ps1 script here
            # Example:
            # Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, Status
            Write-Host "Combined.ps1 script executed on $($env:COMPUTERNAME)"
        }

        try {
            # Invoke-Command directly on all unique endpoints
            # Assign the output to a variable
            $remoteResults = Invoke-Command -ComputerName $uniqueEndpointNamesArray -Credential $credential -ScriptBlock $scriptToRun -ThrottleLimit 64

            # Write the collected output to the local file
            $remoteResults | Out-File -Path $outputFilePath -Append

            Write-Host "Remote script output saved to: $outputFilePath"
        }
        catch {
            Write-Error "Error during Invoke-Command to unique endpoints: $($_.Exception.Message)"
        }
    }
} else {
    Write-Warning "`nRemote script execution is disabled by the \$RunRemoteScript flag. Skipping."
}

Write-Host "`nRemote script execution complete."
Write-Host "Script execution complete."