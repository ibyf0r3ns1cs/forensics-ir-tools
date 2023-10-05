# Define date
$targetDate = Get-Date "2023-09-18"  # yyyy-MM-dd

# Define path to the .evtx file
$evtxPath = "C:\Users\ibyf0r3ns1cs\Desktop\cases\aviv\dev-w7grisham2\kape_output\C\Windows\System32\winevt\logs\Security.evtx"

# Get all logon events for the defined date and time range from the .evtx file
$LogonEvents = Get-WinEvent -Path $evtxPath -FilterXPath "*[System[(EventID=1100) and TimeCreated[@SystemTime>='$($targetDate.ToUniversalTime().ToString('o'))' and @SystemTime<'$($targetDate.AddHours(34).ToUniversalTime().ToString('o'))']]]"

# Initialize a hashtable to store unique logon users
$UniqueLogons = @{}

# Output user information without duplication
foreach ($Event in $LogonEvents) {
    # Parse user and domain information
    $xml = [xml]$Event.ToXml()
    $User = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
    $Domain = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' } | Select-Object -ExpandProperty '#text'
    
    # Check if this user has already been recorded
    if (-not $UniqueLogons.ContainsKey($User)) {
        # If not recorded, add to hashtable and output information
        $UniqueLogons[$User] = $true
        Write-Output "User: $Domain\$User logged in on $($Event.TimeCreated)"
    }
}
