# Define file paths and directory (from previous steps)
$ApprovedListPath = "c:\PySC\approved_Applications_list.xlsx"
$OutputCsvDirectory = "C:\PySC\Apps"
$ComparisonResultsDirectory = "C:\PySC\Apps" # Directory to save comparison results

# Ensure the ImportExcel module is installed and imported (from previous steps)
try {
    Import-Module -Name ImportExcel -ErrorAction Stop
} catch {
    Write-Host "ImportExcel module not found. Attempting to install..."
    try {
        Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module -Name ImportExcel -ErrorAction Stop
        Write-Host "ImportExcel module installed and imported successfully."
    } catch {
        Write-Error "Failed to install and import ImportExcel module. Please install it manually: Install-Module -Name ImportExcel"
        exit 1
    }
}

# 1. Read Approved Applications from Excel $ApprovedListPath to a variable (from previous steps)
try {
    $ApprovedApplications = Import-Excel -Path $ApprovedListPath -ErrorAction Stop
    Write-Host "Successfully read approved applications from '$ApprovedListPath'."
    # Display count of approved applications
    Write-Host "Count of Approved Applications read from Excel: $($ApprovedApplications.Count)"
} catch {
    Write-Error "Failed to read approved applications from '$ApprovedListPath'. Please ensure the file exists and is accessible."
    exit 1
}

# Create a HashTable for quick lookup of approved application names (case-insensitive)
$ApprovedApplicationNames = $ApprovedApplications | Select-Object -ExpandProperty applicationName
$ApprovedApplicationLookup = @{}
foreach ($appName in $ApprovedApplicationNames) {
    # Using 'ToLower()' for case-insensitive comparison
    $ApprovedApplicationLookup[$appName.ToLower()] = $true
}

# 2. Find all executables and build into additional dataframe (from previous steps)
$ComputerName = $env:COMPUTERNAME
Write-Host "Current computer name: $ComputerName"

# Specify the path to recursively search for executable files
$SearchRootPath = "C:\"
# Specify the hash algorithm to use
$HashAlgorithm = "SHA256"

# Get the script start time
$ScriptStartTime = Get-Date

# Display the script start time and computername 'yyyyMMddHHmmss'
Write-Host "Script Start Time: $($ScriptStartTime.ToString('yyyyMMddHHmmss'))"
Write-Host "Computer Name: $ComputerName"

# Get the sortable date in yymmdd format 'yyyyMMddHHmmss'
$SortableDate = $ScriptStartTime.ToString('yyyyMMddHHmmss')

# Construct the output file name for the discovered applications (without comparison/hash yet)
$DiscoveredAppsFileName = "${ComputerName}_DiscoveredApplications_${SortableDate}.csv" # Renamed slightly for clarity
$FullDiscoveredAppsPath = Join-Path -Path $OutputCsvDirectory -ChildPath $DiscoveredAppsFileName

# Ensure the output directory exists
if (-not (Test-Path $OutputCsvDirectory)) {
    Write-Host "Creating output directory: $OutputCsvDirectory"
    New-Item -Path $OutputCsvDirectory -ItemType Directory | Out-Null
}

# Initialize and start the stopwatch for the ticker
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$LastStatusTime = $Stopwatch.Elapsed # Initialize the last time a status was reported

# Create an empty array to store results
$ApplicationsData = @()

# Counter for tracking progress
$Counter = 0

Write-Host "Starting recursive search for executables in '$SearchRootPath'..."

$ExecutableFiles = Get-ChildItem -Path $SearchRootPath -File -Recurse -Include "*.exe", "*.bat" -ErrorAction SilentlyContinue
$TotalFilesToProcess = $ExecutableFiles.Count

if ($TotalFilesToProcess -eq 0) {
    Write-Host "No executable files found in '$SearchRootPath'."
} else {
    Write-Host "Found $TotalFilesToProcess executable files. Processing..."

    foreach ($File in $ExecutableFiles) {
        $Counter++

        # Check if 15 seconds have passed since the last status report
        if ($Stopwatch.Elapsed.TotalSeconds -ge ($LastStatusTime.TotalSeconds + 15)) {
            Write-Host "Script running... Processing discovered files. Elapsed time: $($Stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
            $LastStatusTime = $Stopwatch.Elapsed
        }

        Write-Progress -Activity "Discovering Executable Files" `
                       -Status "File: $($File.Name)" `
                       -PercentComplete (($Counter / $TotalFilesToProcess) * 100) `
                       -CurrentOperation "Getting file info for $($File.FullName)"

        $FileVersionInfo = $null
        $ProductName = ""
        $FileDescription = ""
        $ApplicationName = ""
        $Publisher = ""

        try {
            $FileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
            $ProductName = $FileVersionInfo.ProductName
            $FileDescription = $FileVersionInfo.FileDescription

            if (-not [string]::IsNullOrEmpty($ProductName)) {
                $ApplicationName = $ProductName
            } elseif (-not [string]::IsNullOrEmpty($FileDescription)) {
                $ApplicationName = $FileDescription
            } elseif (-not [string]::IsNullOrEmpty($FileVersionInfo.FileName)) {
                $ApplicationName = $FileVersionInfo.FileName
            } else {
                $ApplicationName = $File.BaseName
            }

            $Publisher = $FileVersionInfo.CompanyName
        } catch {
            Write-Warning "Could not get file version info for $($File.FullName): $($_.Exception.Message)"
            if ([string]::IsNullOrEmpty($ApplicationName)) {
                $ApplicationName = $File.BaseName
            }
        }

        $AppData = [PSCustomObject]@{
            FileName        = $File.Name
            Path            = $File.FullName
            ApplicationName = $ApplicationName
            Publisher       = $Publisher
            Hash            = "" # Hash is now initialized as empty
            ProductName     = $ProductName
            FileDescription = $FileDescription
            Status          = "Processed" # Initial status
        }
        $ApplicationsData += $AppData
    }

    # Display count of discovered applications before comparison/hash
    Write-Host "Count of Discovered Applications for Comparison: $($ApplicationsData.Count)"

    # --- Display Application Names from Recursive Search ---
    Write-Host "--- Displaying unique Application Names from Recursive Search ---"
    $ApplicationsData | Select-Object -ExpandProperty ApplicationName | Sort-Object | Get-Unique | Format-Table -AutoSize
    Write-Host "---------------------------------------------------------"

    
    # Export the initial discovered applications data (optional, but good for debugging)
    # Write-Host "Exporting initial discovered application data to '$FullDiscoveredAppsPath'..."
    # try {
    #     $ApplicationsData | Export-Csv -Path $FullDiscoveredAppsPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    #     Write-Host "Successfully exported initial discovered application data to '$FullDiscoveredAppsPath'."
    # } catch {
    #     Write-Error "Failed to export initial discovered application data to '$FullDiscoveredAppsPath': $($_.Exception.Message)"
    # }

}

# --- Start of Comparison (Step 4) ---

Write-Host "Starting comparison of discovered applications against the approved list..."
$ComparisonCounter = 0
$TotalApplicationsToCompare = $ApplicationsData.Count # Use the initial discovered data

foreach ($App in $ApplicationsData) {
    $ComparisonCounter++

    # Check if 15 seconds have passed since the last status report
    if ($Stopwatch.Elapsed.TotalSeconds -ge ($LastStatusTime.TotalSeconds + 15)) {
        Write-Host "Script running... Performing comparison. Elapsed time: $($Stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
        $LastStatusTime = $Stopwatch.Elapsed
    }

    Write-Progress -Activity "Comparing Applications" `
                   -Status "Comparing: $($App.ApplicationName)" `
                   -PercentComplete (($ComparisonCounter / $TotalApplicationsToCompare) * 100) `
                   -CurrentOperation "Checking status for $($App.ApplicationName)"

    if ($ApprovedApplicationLookup.ContainsKey($App.ApplicationName.ToLower())) {
        $App | Add-Member -MemberType NoteProperty -Name Status -Value "Approved" -Force
    } else {
        $App | Add-Member -MemberType NoteProperty -Name Status -Value "Unapproved" -Force
    }
    # We are directly modifying $App, so no need for $ComparedApplications += $App if we're not creating a new collection
    # Instead, we are adding the status to the existing objects in $ApplicationsData.
}
Write-Host "Application comparison complete."

# Display count of applications after comparison (still using $ApplicationsData)
Write-Host "Count of Applications after Comparison: $($ApplicationsData.Count)"

# --- Start of Hash Calculation (Just before export) ---

Write-Host "Starting hash calculation for discovered applications..."
$HashingCounter = 0
$TotalApplicationsToHash = $ApplicationsData.Count

foreach ($App in $ApplicationsData) {
    $HashingCounter++

    # Check if 15 seconds have passed since the last status report
    if ($Stopwatch.Elapsed.TotalSeconds -ge ($LastStatusTime.TotalSeconds + 15)) {
        Write-Host "Script running... Calculating hashes. Elapsed time: $($Stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
        $LastStatusTime = $Stopwatch.Elapsed
    }

    Write-Progress -Activity "Calculating File Hashes" `
                   -Status "Hashing: $($App.FileName)" `
                   -PercentComplete (($HashingCounter / $TotalApplicationsToHash) * 100) `
                   -CurrentOperation "Calculating hash for $($App.Path)"

    $Hash = ""
    try {
        # Escape the file path for wildcard characters before passing to Get-FileHash
        $escapedPath = [WildcardPattern]::Escape($App.Path)
        $HashResult = Get-FileHash -Path $escapedPath -Algorithm $HashAlgorithm -ErrorAction Stop
        $Hash = $HashResult.Hash
    } catch {
        # Check if the error message indicates "Access to the path is denied"
        if ($_.Exception.Message -like "*Access to the path*is denied.*") {
            Write-Warning "Could not calculate hash for $($App.Path): Access Denied. Setting Hash to 'Denied'."
            $Hash = "Denied"
        } else {
            # For other errors, use the generic error message
            Write-Warning "Could not calculate hash for $($App.Path): $($_.Exception.Message)"
            $Hash = "Error Calculating Hash"
        }
    }

    # Add or update the Hash property
    $App | Add-Member -MemberType NoteProperty -Name Hash -Value $Hash -Force
}
Write-Host "Hash calculation complete."

# --- Save the updated data (with hash and status) to the final CSV file ---

$ComparisonResultsFileName = "${ComputerName}_ComparisonResults_${SortableDate}.csv"
$FullComparisonResultsPath = Join-Path -Path $ComparisonResultsDirectory -ChildPath $ComparisonResultsFileName

Write-Host "Exporting comparison results (including hashes) to '$FullComparisonResultsPath'..."
try {
    $ApplicationsData | Export-Csv -Path $FullComparisonResultsPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "Successfully exported comparison results to '$FullComparisonResultsPath'."
} catch {
    Write-Error "Failed to export comparison results to '$FullComparisonResultsPath': $($_.Exception.Message)"
}

# Stop the stopwatch
$Stopwatch.Stop()
Write-Host "Total script execution time: $($Stopwatch.Elapsed.TotalSeconds) seconds."
