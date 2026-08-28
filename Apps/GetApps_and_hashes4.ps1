# Define parameters for flexibility
[CmdletBinding()]
Param(
    # Specify the path to search for executable files
    [Parameter(Mandatory=$false)]
    [string]$SearchPath = "C:\",  # Or your desired default path

    # Specify the directory for the output file
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "C:\PySC\Apps\",

    # Specify the hash algorithm to use (default is SHA256)
    [Parameter(Mandatory=$false)]
    [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160")]
    [string]$HashAlgorithm = "SHA256"
)

# Get the script start time
$ScriptStartTime = Get-Date

# Display the script start time
Write-Host "Script started at: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"

# Get the computer name
$ComputerName = $env:COMPUTERNAME

# Get the sortable date in yymmdd format
$SortableDate = (Get-Date -Format "yyMMdd")

# Construct the output file name
$OutputFileName = "${ComputerName}_Applications_${SortableDate}.csv"

# Combine the directory and file name to get the full output path
$OutputFile = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

# Initialize and start the stopwatch for the ticker
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Get all files recursively, handling potential access errors, and then filter
$AllFiles = Get-ChildItem -Path $SearchPath -Recurse -File -ErrorAction SilentlyContinue

# Filter for executable file extensions
$ExecutableFiles = $AllFiles | Where-Object { $_.Extension -in (".exe", ".bat") } #, ".com", ".ps1" ?

# Create an empty array to store results
$Results = @()

# Counter for tracking progress
$Counter = 0
$TotalFiles = $ExecutableFiles.Count

# Iterate through each executable file, calculate its hash, get app name, publisher, and other info
foreach ($File in $ExecutableFiles) {
    $Counter++
    $ResultObject = [PSCustomObject]@{
        FileName = $File.Name
        Path = $File.FullName
        ApplicationName = "" # Initialize ApplicationName column
        Publisher = "" # Initialize Publisher column
        Hash = "" # Initialize Hash column
        HashAlgorithm = $HashAlgorithm # Include the used algorithm in the output
        Status = "Processed" # Initialize Status column
    }

    try {
        # Get the file hash using the specified algorithm
        # Use -LiteralPath here as well to be safe
        $FileHash = Get-FileHash -LiteralPath $File.FullName -Algorithm $HashAlgorithm
        $ResultObject.Hash = $FileHash.Hash

        # Get file version information using System.Diagnostics.FileVersionInfo
        # Use a nested try-catch for more granular error handling of version info retrieval
        try {
            $FileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)

            if ($FileVersionInfo) {
                # Try ProductName first, then FileDescription
                if (-not [string]::IsNullOrEmpty($FileVersionInfo.ProductName)) {
                    $ResultObject.ApplicationName = $FileVersionInfo.ProductName
                } elseif (-not [string]::IsNullOrEmpty($FileVersionInfo.FileDescription)) {
                    $ResultObject.ApplicationName = $FileVersionInfo.FileDescription
                }

                # Get the Publisher
                if (-not [string]::IsNullOrEmpty($FileVersionInfo.CompanyName)) {
                    $ResultObject.Publisher = $FileVersionInfo.CompanyName
                }
            }
        }
        catch {
            # Log specific error if version info retrieval fails
            Write-Warning "Could not get version information for $($File.FullName). Error: $($_.Exception.Message)"
            $ResultObject.ApplicationName = "N/A (Error getting version info)"
            $ResultObject.Publisher = "N/A (Error getting version info)"
        }

        # If ApplicationName is still empty, use the file name as a fallback
        if ([string]::IsNullOrEmpty($ResultObject.ApplicationName)) {
            $ResultObject.ApplicationName = $File.BaseName
        }

    }
    catch {
        # Log error with details if hash calculation fails or primary error occurs
        Write-Error "Could not process file: $($File.FullName). Error: $($_.Exception.Message)"
        $ResultObject.Status = "Permission Denied" # Update Status column
        $ResultObject.Hash = "Permission Denied" # Update Hash column
        $ResultObject.ApplicationName = "Permission Denied" # Update ApplicationName column
        $ResultObject.Publisher = "Permission Denied" # Update Publisher column
    }
    $Results += $ResultObject

    # Display progress with Write-Progress (Ticker)
    $elapsedTime = $stopwatch.Elapsed
    $activity = "Processing executable files"
    $status = "$Counter/$TotalFiles files processed. Elapsed: $($elapsedTime.ToString('hh\:mm\:ss'))" # Format as HH:mm:ss
    $percentComplete = ($Counter / $TotalFiles) * 100

    Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete
}

# Stop the stopwatch
$stopwatch.Stop()

# Close the progress bar
Write-Progress -Activity $activity -Completed

# Get the script end time
$ScriptEndTime = Get-Date

# Calculate the total execution time
$TotalExecutionTime = $ScriptEndTime - $ScriptStartTime

# Display the script end time and total execution time
Write-Host "`nScript finished at: $($ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Total execution time: $($TotalExecutionTime.ToString('hh\:mm\:ss'))"

# Export the results to a CSV file
# Ensure the output directory exists before exporting
$OutputDirectory = Split-Path -Path $OutputFile -Parent
if (-not (Test-Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory | Out-Null
}

try {
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -UseCulture
}
catch [System.IO.IOException] {
    Write-Error "Could not export CSV: $($_.Exception.Message). Please ensure the file is not in use."
}


Write-Host "Results saved to $OutputFile"
