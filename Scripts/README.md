## YaraRulesExtractor.py
YaraRulesExtractor.py splits a YARA rule file containing multiple rules into separate files, each containing a single rule. 
> **Note**  
> Sometimes when writing YARA rules, the "pe" Python library is used. Please note that the script does not add the "import pe" command, so you will need to add it manually if required.

## GetProcessHashes.ps1
Retrieves the hashes and command lines of running processes.

## CheckUnsignedProcesses
Checks if running processes are signed.
