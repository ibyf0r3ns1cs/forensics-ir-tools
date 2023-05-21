<#

Author: Idan-Beit-Yosef @ IBYf0r3ns1cs

.SYNOPSIS
This script retrieves the hashes and command lines of running processes and prints the process name, command line, along with their corresponding hashes.

.DESCRIPTION
The script gets a list of running processes using the Get-Process cmdlet. It then calculates the hash of the process file for each running process using the specified hash algorithm (default is SHA256). The script also retrieves the command line of each process using a WMI query. It prints the process name, command line, and their corresponding hashes. If there is an error accessing the process or calculating the hash, the script displays an error message.

.NOTES
- This script requires administrative privileges to access certain processes and their files.
- You can modify the $hashAlgorithm variable to change the hash algorithm if needed.
- Some processes may not have a valid path or their files may not be accessible due to permission restrictions. Such processes will be skipped.
- The script includes the command line of each process to provide additional information about the running processes.

.EXAMPLE
.\GetProcessHashes.ps1
Runs the script to retrieve the hashes and command lines of running processes and displays the process names, command lines, along with their hashes.
#>

$runningProcesses = Get-Process

foreach ($process in $runningProcesses) {
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

        # Retrieve the command line of the process using WMI query
        $wmiQuery = "SELECT CommandLine FROM Win32_Process WHERE ProcessId = $($process.Id)"
        $commandLine = Get-WmiObject -Query $wmiQuery | Select-Object -ExpandProperty CommandLine

        # Print the process name, command line, and their corresponding hash
        Write-Host "Process Name: $($process.ProcessName)"
        Write-Host "Command Line: $commandLine"
        Write-Host "Hash: $hash"
        Write-Host "---------------------------"
        
        # Close the file stream
        $fileStream.Close()
    }
    catch {
        # Error occurred while accessing the process or calculating the hash
        Write-Host "Failed to retrieve hash for process: $($process.ProcessName)"
        Write-Host "Error: $_"
        Write-Host "---------------------------"
    }
}
