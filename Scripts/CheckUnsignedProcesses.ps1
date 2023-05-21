<#

.SYNOPSIS
This script checks if running processes are signed and prints information about unsigned processes including their name, full path, and hash.

.DESCRIPTION
The script retrieves a list of running processes and iterates through each process. It calculates the hash of the process file and checks if the process is signed using the Get-AuthenticodeSignature cmdlet. If the process is not signed, it prints the process name, full path, and hash.

.NOTES
- The script requires administrative privileges to access certain processes and their files.
- The digital signature check relies on the Get-AuthenticodeSignature cmdlet, which uses the digital signature information available in the system.
- Some processes may not have a valid path or their files may not be accessible due to permission restrictions. Such processes will be skipped.
- The script uses the SHA256 algorithm by default to calculate the hash of the process file. You can modify the $hashAlgorithm variable to use a different hash algorithm if needed.

.EXAMPLE
.\CheckUnsignedProcesses.ps1
Runs the script to check for unsigned processes and display information about unsigned processes.

.AUTHOR
Author: Idan-Beit-Yosef @ IBYf0r3ns1cs
#>

$runningProcesses = Get-Process

foreach ($process in $runningProcesses) {
    $processName = $process.ProcessName
    $processPath = $process.Path
    
    # Skip processes without a valid path
    if ([string]::IsNullOrWhiteSpace($processPath)) {
        continue
    }
    
    try {
        $hashAlgorithm = 'SHA256'  # You can change the hash algorithm if needed (e.g., MD5, SHA1)
        
        # Calculate the hash of the process file
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($hashAlgorithm)
        $fileStream = [System.IO.File]::OpenRead($processPath)
        $hashBytes = $hasher.ComputeHash($fileStream)
        $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')

        # Check if the process file is signed
        $signature = Get-AuthenticodeSignature -FilePath $processPath -ErrorAction Stop
        
        if ($signature.Status -eq 'Valid') {
            # Skip signed processes
            continue
        }
        
        # Print the process details if it's not signed
        Write-Host "Process Name: $processName"
        Write-Host "Full Path: $processPath"
        Write-Host "Hash: $hash"
        Write-Host "---------------------------"
        
        # Close the file stream
        $fileStream.Close()
    }
    catch {
        # Error occurred while accessing the process or calculating the hash
        Write-Host "Failed to retrieve information for process: $processName"
        Write-Host "Error: $_"
        Write-Host "---------------------------"
    }
}
