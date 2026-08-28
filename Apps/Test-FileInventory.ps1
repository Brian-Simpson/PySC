# TEST VERSION: Script to inventory .exe and .bat files across Windows 11 endpoints
# This version includes testing features like limited file count and path options

# Parameters for testing
param(
    [string]$SearchPath = "C:\",        # Default to C:\ but can be changed for testing
    [int]$MaxFiles = 100,               # Limit number of files for testing
    [switch]$TestMode = $true,          # Enable test mode by default
    [string]$OutputPath = "$env:USERPROFILE\Desktop\FileInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Write-Host "TEST MODE ENABLED: Limited to $MaxFiles files from $SearchPath" -ForegroundColor Yellow

# Ensure output directory exists
$outputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

# Get computer information
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$deviceName = $computerSystem.Name
$fqdn = "$($computerSystem.Name).$((Get-WmiObject Win32_ComputerSystem).Domain)"

Write-Host "Device: $deviceName" -ForegroundColor Cyan
Write-Host "FQDN: $fqdn" -ForegroundColor Cyan

# Create an array to store results
$results = @()
$fileCount = 0

# Define a function to get file publisher information
function Get-FilePublisher {
    param (
        [string]$FilePath
    )
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($signature.Status -ne "NotSigned" -and $signature.SignerCertificate -ne $null) {
            $publisher = $signature.SignerCertificate.Subject
            # Extract CN from the subject
            if ($publisher -match "CN=([^,]+)") {
                return $Matches[1].Trim()
            }
            return $publisher
        }
        return "Unknown"
    }
    catch {
        return "Error retrieving publisher"
    }
}

# Define a function to get application name
function Get-ApplicationName {
    param (
        [string]$FilePath
    )
    
    try {
        $versionInfo = (Get-Item $FilePath -ErrorAction SilentlyContinue).VersionInfo
        if ($versionInfo.ProductName) {
            return $versionInfo.ProductName
        }
        else {
            # If ProductName is not available, use FileDescription or filename without extension
            if ($versionInfo.FileDescription) {
                return $versionInfo.FileDescription
            }
            else {
                return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
            }
        }
    }
    catch {
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
}

# Define a function to calculate SHA256 hash
function Get-FileHash256 {
    param (
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        return $hash.Hash
    }
    catch {
        return "Error calculating hash"
    }
}

Write-Host "Starting file inventory on $fqdn..." -ForegroundColor Cyan
Write-Host "Scanning $SearchPath..." -ForegroundColor Yellow

$startTime = Get-Date
$progressInterval = 10 # Show progress every 10 files

try {
    # Use Get-ChildItem with -File parameter for better performance
    # In test mode, limit the depth to avoid long scans
    $searchDepth = if ($TestMode) { 3 } else { 99 }
    
    Get-ChildItem -Path $SearchPath -Include "*.exe", "*.bat" -Recurse -File -Depth $searchDepth -ErrorAction SilentlyContinue -ErrorVariable errors | 
    ForEach-Object {
        if ($fileCount -ge $MaxFiles -and $TestMode) {
            return # Exit the loop if we've reached the max files in test mode
        }
        
        $file = $_
        try {
            $fileName = $file.Name
            $installPath = $file.DirectoryName
            $fullPath = $file.FullName
            
            # Show progress
            $fileCount++
            if ($fileCount % $progressInterval -eq 0) {
                Write-Host "Processing file $fileCount`: $fileName" -ForegroundColor Green
            }
            
            # Get additional file information
            $appName = Get-ApplicationName -FilePath $fullPath
            $publisher = Get-FilePublisher -FilePath $fullPath
            $hash = Get-FileHash256 -FilePath $fullPath
            
            # Create a custom object with the file information
            $fileInfo = [PSCustomObject]@{
                'DeviceName' = $deviceName
                'FQDN' = $fqdn
                'ApplicationName' = $appName
                'Publisher' = $publisher
                'FileName' = $fileName
                'InstallationPath' = $installPath
                'SHA256' = $hash
            }
            
            # Add to results array
            $results += $fileInfo
            
            # Display sample data for the first few files
            if ($fileCount -le 5) {
                Write-Host "Sample data for $fileName:" -ForegroundColor Cyan
                Write-Host "  Application: $appName" -ForegroundColor White
                Write-Host "  Publisher: $publisher" -ForegroundColor White
                Write-Host "  Path: $installPath" -ForegroundColor White
                Write-Host "  SHA256: $($hash.Substring(0, 16))..." -ForegroundColor White
                Write-Host ""
            }
        }
        catch {
            Write-Warning "Error processing file $($file.FullName): $_"
        }
    }
}
catch {
    Write-Warning "Error scanning $SearchPath`: $_"
}

# Report on any access errors (limit to first 10 in test mode)
$errorCount = 0
foreach ($error in $errors) {
    $errorCount++
    if ($TestMode -and $errorCount -gt 10) {
        Write-Warning "Additional errors omitted in test mode..."
        break
    }
    Write-Warning "Access error: $($error.CategoryInfo.TargetName)"
}

# Export results
$results | Export-Csv -Path $OutputPath -NoTypeInformation

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "Test inventory complete. Processed $fileCount files in $($duration.TotalSeconds.ToString("0.00")) seconds" -ForegroundColor Green
Write-Host "Results saved to $OutputPath" -ForegroundColor Green

# Display sample of the results
Write-Host "`nSample of inventory results:" -ForegroundColor Cyan
$results | Select-Object -First 5 | Format-Table -AutoSize

# Provide instructions for full deployment
if ($TestMode) {
    Write-Host "`nTEST COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "`nTo run a full inventory:" -ForegroundColor Yellow
    Write-Host "1. Remove the -TestMode switch" -ForegroundColor Yellow
    Write-Host "2. Set -MaxFiles to a higher number or remove the parameter" -ForegroundColor Yellow
    Write-Host "3. Ensure you have appropriate permissions for the target paths" -ForegroundColor Yellow
    Write-Host "`nExample: .\InventoryScript.ps1 -SearchPath 'C:\' -MaxFiles 10000 -TestMode:`$false" -ForegroundColor Yellow
}
