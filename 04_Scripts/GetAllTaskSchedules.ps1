<#
.SYNOPSIS
This script retrieves information about all task schedules in the system, including the task name, action, arguments, and trigger details.

.DESCRIPTION
The script connects to the local task scheduler and traverses through all task folders to retrieve information about each task schedule. It retrieves the task name, action, arguments, and trigger details for each task and displays them.

.NOTES
- This script requires administrative privileges to access the task scheduler.
- The script uses COM automation to interact with the task scheduler.
- Some tasks may not have an action or arguments. In such cases, those fields will not be displayed.

.EXAMPLE
.\GetAllTaskSchedules.ps1
Runs the script to retrieve information about all task schedules in the system.

.AUTHOR
Author: Idan-Beit-Yosef @ IBYf0r3ns1cs
#>

# Create a new instance of the Schedule.Service COM object
$scheduler = New-Object -ComObject Schedule.Service

# Connect to the local task scheduler
$scheduler.Connect()

# Get the root task folder
$rootFolder = $scheduler.GetFolder("\")
$allTasks = New-Object System.Collections.ArrayList

# Function to recursively traverse the task folders
function TraverseTaskFolders($folder) {
    $tasks = $folder.GetTasks(0)
    foreach ($task in $tasks) {
        [void]$allTasks.Add($task)
    }

    $subfolders = $folder.GetFolders(0)
    foreach ($subfolder in $subfolders) {
        TraverseTaskFolders $subfolder
    }
}

# Traverse through the task folders
TraverseTaskFolders $rootFolder

if ($allTasks.Count -gt 0) {
    # Tasks found
    Write-Host "All Tasks Found:"

    foreach ($task in $allTasks) {
        Write-Host "Task Name: $($task.Name)"

        $actionPath = $task.Definition.Actions.Item(1).Path
        if ($actionPath) {
            Write-Host "Action: $actionPath"
        }

        $arguments = $task.Definition.Actions.Item(1).Arguments
        if ($arguments) {
            Write-Host "Arguments: $arguments"
        }

        try {
            $trigger = $task.Definition.Triggers.Item(1).StartBoundary
            Write-Host "Trigger: $trigger"
        } catch {
            Write-Host "Trigger: Not available"
        }

        Write-Host "---------------------------"
    }
} else {
    # No tasks found
    Write-Host "No Tasks Found."
}

# Release the COM object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($scheduler) | Out-Null
