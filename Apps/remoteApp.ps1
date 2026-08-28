# Specify the path to your CSV file
$filePath = "C:\PySC\AppInventory_2025.csv"

# --- Initial Status Update ---
Write-Host "Starting CSV processing. Initializing..."
Write-Host "Loading and filtering CSV data..."

# --- Optimized CSV Processing with Filtering (using StreamReader and Header Check) ---

$uniqueEndpointNames = New-Object System.Collections.Generic.HashSet[string]
$fileStream = New-Object System.IO.StreamReader($filePath)

# Read the header row and determine column indices
$headerLine = $fileStream.ReadLine()
$headers = $headerLine -split ',' # Assuming comma delimiter

# Find the index of the 'endpointName' and 'osVersion' columns
$endpointNameIndex = -1
$osVersionIndex = -1

for ($i = 0; $i -lt $headers.Length; $i++) {
    if ($headers[$i].Trim() -eq "endpointName") {
        $endpointNameIndex = $i
    }
    if ($headers[$i].Trim() -eq "osVersion") {
        $osVersionIndex = $i
    }
}

# Check if both required columns were found
if ($endpointNameIndex -eq -1 -or $osVersionIndex -eq -1) {
    Write-Error "Could not find 'endpointName' or 'osVersion' column in the header row."
    $fileStream.Close()
    exit # Exit the script if required columns are missing
}

# Process the data rows
while (($line = $fileStream.ReadLine()) -ne $null) {
    $fields = $line -split ',' # Assuming comma delimiter

    # Extract the relevant fields using their indices
    # Add error handling in case a row has fewer columns than the header
    if ($fields.Length -gt $endpointNameIndex -and $fields.Length -gt $osVersionIndex) {
        $endpointName = $fields[$endpointNameIndex].Trim()
        $osVersion = $fields[$osVersionIndex].Trim()

        # Apply filtering conditions
        if (($osVersion -eq "Windows 11 Enterprise 22631") -and ($endpointName -like "HTH*")) {
            [void]$uniqueEndpointNames.Add($endpointName) # Add unique endpointName to the HashSet
        }
    } else {
        Write-Warning "Skipping a row with insufficient columns: $line"
    }
}

$fileStream.Close()

# --- Convert HashSet to an array and display results ---

$uniqueEndpointNamesArray = @($uniqueEndpointNames)

# Count the number of unique endpoint names
$uniqueCount = $uniqueEndpointNamesArray.Count

# Display the unique endpoint names
Write-Host "`nUnique endpoint names (Windows 11 Enterprise and starting with 'HTH' only):"
$uniqueEndpointNamesArray

# Display the total count of unique endpoint names
Write-Host "`nTotal count of unique endpoint names (Windows 11 Enterprise and starting with 'HTH' only): $uniqueCount"

Write-Host "Script execution complete."
