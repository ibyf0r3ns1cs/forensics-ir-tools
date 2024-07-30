## Volatility Commands

### 1. Identify the Memory Image Profile
Determine the profile of the memory image:
```
vol2
vol.py -f <Memory Image File> imageinfo

vol3
vol.py -f <Memory Image File> windows.info

```

### 2. Network Connections
List network connections:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 netscan

vol3
vol.py -f <memory_image> windows.netscan
```

### 3. List Processes
List all running processes:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 pslist

vol3
vol.py -f <memory_image> windows.pslist
```

### 4. List Processes - Includes terminated or hidden 
List all running processes:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 psscan

vol3
vol.py -f <memory_image> windows.psscan
```

### 5. Process Tree
Display the process tree:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 pstree

vol3
vol.py -f <memory_image> windows.pstree
```

### 6. DLL List
List DLLs loaded by a specific process:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_190410 dlllist --pid <process id>

vol3
vol.py -f <memory_image> windows.dlllist --pid <process id>
```

### 7. Handles
List the handles opened by a specific process:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 handles --pid <process id>

vol3
vol.py -f <memory_image> windows.handles --pid <process id>
```

### 8. Malfind
Scan for suspicious or hidden processes:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 malfind

vol3
vol.py -f <memory_image> windows.malfind
```

### 9. Process Dump
Dump the memory of a specific process:
```
vol2
vol.py -f <memory_image> --profile=Win10x64_19041 procdump --pid <process id> --dump-dir process_dump

vol3
vol.py -f <memory_image> -o <directory_output> windows.dumpfiles --pid <process id>
```


## Explanation of Commands

- **imageinfo**: Identifies the operating system profile to use with the memory image.
- **netscan**: Lists network connections, showing active connections and listening ports.
- **pslist**: Displays a list of all running processes in the memory image.
- **psscan**: Displays a list of all running and terminated processes in the memory image.
- **pstree**: Shows the hierarchical structure of processes, displaying parent-child relationships.
- **dlllist**: Lists the DLLs loaded by a specified process, which can help identify injected or malicious DLLs.
- **handles**: Lists the handles opened by a specified process, useful for identifying resources in use by a process.
- **malfind**: Scans for suspicious or hidden processes that may indicate malware presence.
- **procdump**: Dumps the memory of a specified process to a file for further analysis.

## Usage Tips

- Always start with `imageinfo` to determine the correct profile for the memory image.
- Use `netscan` to identify any suspicious network activity.
- Use `pslist` and `pstree` to get an overview of running processes and their relationships.
- For detailed analysis, use `dlllist` and `handles` on suspicious processes.
- Use `malfind` to detect potentially malicious activity.
- Dump suspicious processes with `procdump` for in-depth offline analysis.

By following this cheat sheet, you can systematically investigate memory evidence to uncover malicious activities.
