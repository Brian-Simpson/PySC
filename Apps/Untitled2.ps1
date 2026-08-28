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

# Ensure the output directory exists
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

# --- Script Logic ---
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

# Initialize an empty array to store results (using a generic list for better performance than `+=`)
$AllResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Initialize and start the stopwatch for the ticker
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Variable to track the last time a notification was displayed
$LastNotificationTime = $Stopwatch.Elapsed

# Get all files recursively, handling potential access errors, and then filter
Write-Host "Searching for executable files. This may take a while..."
$AllFiles = Get-ChildItem -Path $SearchPath -Recurse -Include "*.exe", "*.bat" -File -ErrorAction SilentlyContinue |
    Where-Object { 
        # Exclude specified directories from the search path
        $Exclude = $false
        foreach ($dir in $ExcludeDirectories) {
            # Use -like "$dir*" to match paths starting with the excluded directory
            if ($_.DirectoryName -like "$dir*" ) {
                $Exclude = $true
                break
            }
        }
        -not $Exclude # Only include files not in excluded directories
    } | Select-Object -Property FullName, Name, LastWriteTime, Length

# Get the total number of files to process for progress bar
$TotalFiles = $AllFiles.Count

Write-Host "Found $TotalFiles executable files to process."

# Process files in parallel
$ProcessedCount = 0
$NotificationIntervalSeconds = 15 # Set the notification interval to 15 seconds

$AllFiles | ForEach-Object -Parallel {
    param($file) # $file will be each object passed from the pipeline

    # Access parent scope variables safely for thread-safe increment
    # and to access configuration variables from the main script
    $global:ProcessedCount++
    $CurrentProcessedCount = $global:ProcessedCount
    $global:TotalFiles # Access $TotalFiles from the parent scope
    $global:Stopwatch # Access $Stopwatch from the parent scope
    $global:LastNotificationTime # Access $LastNotificationTime from parent scope for comparison
    $OutputDirectory # This variable is captured from the parent scope

    # Update progress bar every file (more granular progress)
    $PercentComplete = [int](($CurrentProcessedCount / $global:TotalFiles) * 100)
    $ElapsedTime = $global:Stopwatch.Elapsed.ToString("hh\:mm\:ss")
    $StatusMessage = "Processing file $CurrentProcessedCount of $($global:TotalFiles). Elapsed: $ElapsedTime"
    Write-Progress -Activity "Calculating File Hashes and Info" -Status $StatusMessage -PercentComplete $PercentComplete -CurrentOperation "Processing $($file.Name)" -Id 1

    # Check if 15 seconds have passed since the last notification
    if (($global:Stopwatch.Elapsed - $global:LastNotificationTime).TotalSeconds -ge $NotificationIntervalSeconds) {
        $notificationTime = Get-Date -Format "HH:mm:ss"
        Write-Host "[ $notificationTime ] Status Update: Processed $CurrentProcessedCount of $($global:TotalFiles) files. Elapsed: $ElapsedTime"
        # Update the last notification time in the parent scope for the next interval check
        $global:LastNotificationTime = $global:Stopwatch.Elapsed
    }

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
        # Output the object from the parallel block
        # This will be collected by the main pipeline into $AllResults.Add()
        $obj
    }
    catch {
        # Note: Write-Warning from within a parallel block might not display immediately or reliably.
        # You could log to a file instead. For now, we'll capture it in the object status.
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
        $failedObj
    }
} | ForEach-Object { $AllResults.Add($_) } # Collect results from parallel block into the list

# Stop the stopwatch
$Stopwatch.Stop()

# Export the results to a CSV file
Write-Host "Exporting results to CSV..."
$AllResults | Export-Csv -Path $OutputFilePath -NoTypeInformation 

# Clear the progress bar when complete
Write-Progress -Activity "Calculating File Hashes and Info" -Status "Complete" -PercentComplete 100 -Completed -Id 1

Write-Host "Script completed."
Write-Host "Hash values and application info exported to $OutputFilePath"

# Calculate and print to display the total execution time
$TotalExecutionTime = $Stopwatch.Elapsed
Write-Host "Total execution time: $($TotalExecutionTime.ToString("hh\:mm\:ss"))"