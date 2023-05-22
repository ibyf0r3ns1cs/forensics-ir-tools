## YaraRulesExtractor.py
YaraRulesExtractor.py splits a YARA rule file containing multiple rules into separate files, each containing a single rule. 
> **Note**  
> Sometimes when writing YARA rules, the "pe" Python library is used. Please note that the script does not add the "import pe" command, so you will need to add it manually if required.

## Get-RunningProcessInfo.ps1
Retrieves the hashes and command lines of running processes.

## CheckUnsignedProcesses.ps1
Checks if running processes are signed.

## GetAllTaskSchedules.ps1
Retrieves information about all task schedules in the system
