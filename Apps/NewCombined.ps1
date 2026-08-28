# --- Configuration ---
# Specify the path to recursively search for executable files
$SearchPath = "C:\" 

# Exclude these directories from the search
$ExcludeDirectories = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS"
)

# Specify the directory for the output file
$OutputDirectory = "C:\PySC\Apps\" 

# Define the interval for screen notifications in seconds
$NotificationIntervalSeconds = 15 

# Note: ParallelThrottleLimit is no longer used in this PowerShell 5.1 compatible version.
# It's kept here as a comment for context, but its value will have no effect.
# $ParallelThrottleLimit = 8


# --- Script Logic ---
# Ensure the output directory exists
if (-not (Test-Path $OutputDirectory)) {
    Write-Host "Output directory '$OutputDirectory' does not exist. Creating it now."
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

# Get the script start time
$ScriptStartTime = Get-Date

# Get the computer name
$ComputerName = $env:COMPUTERNAME

# Display the script start time and computername
Write-Host "Script started at: $($ScriptStartTime)"
Write-Host "Running on computer: $ComputerName"

# Get the sortable date in yyyyMMddHHmmss format for the filename
$SortableDate = (Get-Date -Format "yyyyMMddHHmmss")

# Construct the output file name
$OutputFileName = "${ComputerName}_Applications_${SortableDate}.csv"
$OutputFilePath = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

Write-Host "Output file will be saved to: $OutputFilePath"

# Initialize an empty list to store results (using a generic list for better performance than `+=`)
$AllResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Initialize and start the stopwatch for timing the process
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Variable to track the last time a notification was displayed
$LastNotificationTime = $Stopwatch.Elapsed


# Get all files recursively, handling potential access errors, filtering exclusions, and then displaying discovery
Write-Host "Searching for executable files. This may take a while..."

# Initialize a counter for found files during the discovery phase
$FoundFileCount = 0

$AllFiles = Get-ChildItem -Path $SearchPath -Recurse -Include "*.exe", "*.bat" -File -ErrorAction SilentlyContinue |
    Where-Object { 
        # Exclude specified directories from the search path BEFORE displaying discovery
        $Exclude = $false
        foreach ($dir in $ExcludeDirectories) {
            # Use -like "$dir*" to match paths starting with the excluded directory
            if ($_.DirectoryName -like "$dir*" ) {
                $Exclude = $true
                break
            }
        }
        -not $Exclude # Only include files not in excluded directories
    } |
    # Increment counter and display the running count instead of each file path
    ForEach-Object {
        $FoundFileCount++
        # Display the count every 10 files
        if ($FoundFileCount % 10 -eq 0) {
            Write-Host "Discovered $($FoundFileCount) executable files..."
        }
        $_ # Pass the file object along the pipeline for further processing
    } |
    # Select-Object -First 100 | # <-- Temporarily limit to the first 100 files
    Select-Object -Property FullName, Name, LastWriteTime, Length

# The $TotalFiles count will now be accurate after the discovery, filtering, AND the 'Select-First 100'
$TotalFiles = $AllFiles.Count

Write-Host "Found a total of $TotalFiles executable files after exclusions and limiting to the first 100."


# Process files in a standard foreach loop (compatible with PowerShell 5.1 and earlier)
$ProcessedCount = 0 
$ProgressId = 1 # Using a static ID for the progress bar

foreach ($file in $AllFiles) {
    # Increment the counter
    $ProcessedCount++ 

    # Update progress bar every file
    $CurrentProcessedCount = $ProcessedCount # Renaming for clarity as $ProcessedCount is now local
    $ElapsedTime = $Stopwatch.Elapsed.ToString("hh\:mm\:ss")
    $PercentComplete = [int](($CurrentProcessedCount / $TotalFiles) * 100)
    Write-Progress -Activity "Calculating File Hashes and Info" -Status "Processing file $CurrentProcessedCount of $TotalFiles. Elapsed: $ElapsedTime" -PercentComplete $PercentComplete -CurrentOperation "Processing $($file.Name)" -Id $ProgressId

    # Check if 15 seconds have passed since the last notification
    if (($Stopwatch.Elapsed - $LastNotificationTime).TotalSeconds -ge $NotificationIntervalSeconds) {
        $notificationTime = Get-Date -Format "HH:mm:ss"
        Write-Host "[ $notificationTime ] Status Update: Processed $CurrentProcessedCount of $TotalFiles files. Elapsed: $ElapsedTime"
        $LastNotificationTime = $Stopwatch.Elapsed # Reset the timer for the next interval
    }

    # Perform the file processing tasks (hashing, getting version info)
    try {
        # Get file version information using System.Diagnostics.FileVersionInfo
        $FileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)

        # Get the file hash using the specified algorithm SHA256 and MD5. 
        $SHA256Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $MD5Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm MD5).Hash

        # Create a custom object with relevant information
        $obj = [PSCustomObject]@{
            FileName = $file.Name
            FilePath = $file.FullName
            ApplicationName = $FileVersionInfo.ProductName
            Publisher = $FileVersionInfo.CompanyName
            FileDescription = $FileVersionInfo.FileDescription
            FileVersion = $FileVersionInfo.FileVersion
            SHA256Hash = $SHA256Hash
            MD5Hash = $MD5Hash
            LastWriteTime = $file.LastWriteTime
            LengthMB = [math]::Round(($file.Length / 1MB), 2) # File size in MB
            Status = "Processed"
        }
        # Add the object to the results list
        $AllResults.Add($obj)
    }
    catch {
        Write-Warning "Could not process file $($file.FullName): $($_.Exception.Message)"

        # Add a record for failed files as well
        $failedObj = [PSCustomObject]@{
            FileName = $file.Name
            FilePath = $file.FullName
            ApplicationName = ""
            Publisher = ""
            FileDescription = ""
            FileVersion = ""
            SHA256Hash = ""
            MD5Hash = ""
            LastWriteTime = $file.LastWriteTime
            LengthMB = [math]::Round(($file.Length / 1MB), 2)
            Status = "Error: $($_.Exception.Message)"
        }
        $AllResults.Add($failedObj)
    }
}

# Stop the stopwatch
$Stopwatch.Stop()

# Export the results to a CSV file
Write-Host "Exporting results to CSV..."
$AllResults | Export-Csv -Path $OutputFilePath -NoTypeInformation 

# Clear the progress bar when complete
Write-Progress -Activity "Calculating File Hashes and Info" -Status "Complete" -PercentComplete 100 -Completed -Id $ProgressId

Write-Host "Script completed."
Write-Host "Hash values and application info exported to $OutputFilePath"

# Calculate and print to display the total execution time
$TotalExecutionTime = $Stopwatch.Elapsed
Write-Host "Total execution time: $($TotalExecutionTime.ToString("hh\:mm\:ss"))"
