param(
    [int]$Days = 1,
    [int]$MaxEvents = 2000,
    [string]$OutputPath = "$PSScriptRoot\..\data\raw\windows-events.json"
)

$ErrorActionPreference = "Stop"
$Since = (Get-Date).AddDays(-$Days)
$Events = [System.Collections.Generic.List[object]]::new()

function Convert-WindowsEvent {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Record
    )

    [xml]$Xml = $Record.ToXml()
    $System = $Xml.Event.System
    $Fields = @{}

    if ($Xml.Event.EventData -and $Xml.Event.EventData.Data) {
        foreach ($Item in $Xml.Event.EventData.Data) {
            $Fields[[string]$Item.Name] = [string]$Item.InnerText
        }
    }

    # Extract TerminalServices UserData fields.
    $SessionFields = @{}
    $EventXmlNode = $Xml.SelectSingleNode(
        "//*[local-name()='UserData']/*[local-name()='EventXML']"
    )

    if ($null -ne $EventXmlNode) {
        foreach ($Child in $EventXmlNode.ChildNodes) {
            if ($Child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $SessionFields[$Child.LocalName] = [string]$Child.InnerText
            }
        }
    }

    $EventId = [string]$System.EventID
    $Channel = [string]$System.Channel
    $Provider = $null
    if ($null -ne $System.Provider) {
        $Provider = [string]$System.Provider.GetAttribute("Name")
    }
    $Timestamp = [DateTimeOffset]::Parse(
        [string]$System.TimeCreated.SystemTime
    ).ToString("o")

    $Username = $Fields["TargetUserName"]
    $SourceIP = $Fields["IpAddress"]
    $LogonType = $Fields["LogonType"]
    $EventType = "Windows Event $EventId"
    $SessionId = $null
    $SessionAddress = $null

    if ($EventId -eq "4624") {
        $EventType = "Successful login"
    }
    elseif ($EventId -eq "4625") {
        $EventType = "Failed login"
    }

    if ($Channel -like "*Sysmon*") {
        $Username = $Fields["User"]
        $EventType = "Process creation"
    }

    if ($Channel -like "*TerminalServices-LocalSessionManager*") {
        $Username = $SessionFields["User"]
        $SessionId = $SessionFields["SessionID"]
        $SessionAddress = $SessionFields["Address"]

        switch ($EventId) {
            "21" { $EventType = "RDP session logon succeeded" }
            "22" { $EventType = "RDP shell start" }
            "24" { $EventType = "RDP session disconnected" }
            "25" { $EventType = "RDP session reconnected" }
        }
    }

    if ($Username -in @("-", "")) { $Username = $null }
    if ($SourceIP -in @("-", "", "::1", "127.0.0.1")) { $SourceIP = $null }
    if ($LogonType -in @("-", "")) { $LogonType = $null }
    if ($SessionId -in @("-", "")) { $SessionId = $null }
    if ($SessionAddress -in @("-", "")) { $SessionAddress = $null }

    [PSCustomObject]@{
        timestamp       = $Timestamp
        event_id        = $EventId
        source          = $Channel
        provider        = $Provider
        host            = [string]$System.Computer
        event_type      = $EventType
        severity        = "informational"
        username        = $Username
        source_ip       = $SourceIP
        logon_type      = $LogonType
        session_id      = $SessionId
        session_address = $SessionAddress
        target_domain   = $Fields["TargetDomainName"]
        workstation_name = $Fields["WorkstationName"]
        source_port     = $Fields["IpPort"]
        authentication_package = $Fields["AuthenticationPackageName"]
        logon_process   = $Fields["LogonProcessName"]
        target_user_sid = $Fields["TargetUserSid"]
        subject_username = $Fields["SubjectUserName"]
        subject_domain  = $Fields["SubjectDomainName"]
        process_name    = $Fields["Image"]
        command_line    = $Fields["CommandLine"]
        record_id       = $Record.RecordId
        raw_xml         = $Record.ToXml()
    }
}

function Add-ChannelEvents {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [string]$Label
    )

    try {
        $Filter = @{
            LogName   = $LogName
            StartTime = $Since
        }

        if ($Ids -and $Ids.Count -gt 0) {
            $Filter.Id = $Ids
        }

        $Records = @(
            Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop
        )

        foreach ($Record in $Records) {
            $Events.Add((Convert-WindowsEvent -Record $Record))
        }

        Write-Host "[INFO] $Label events collected: $($Records.Count)"
    }
    catch {
        if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {
            Write-Host "[INFO] $Label events collected: 0"
        }
        else {
            Write-Warning "$Label collection unavailable: $($_.Exception.Message)"
        }
    }
}

Write-Host "[INFO] Collecting Windows Security events..."
Add-ChannelEvents -LogName "Security" -Ids @(4624, 4625) -Label "Security"

Write-Host "[INFO] Collecting Sysmon process events..."
Add-ChannelEvents -LogName "Microsoft-Windows-Sysmon/Operational" -Ids @(1) -Label "Sysmon"

Write-Host "[INFO] Collecting TerminalServices session events..."
Add-ChannelEvents -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -Ids @(21, 22, 24, 25) -Label "TerminalServices"

$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$OutputDirectory = Split-Path -Parent $OutputPath

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$Events |
    Sort-Object timestamp |
    ConvertTo-Json -Depth 8 |
    Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "[COMPLETE] Total events: $($Events.Count)"
Write-Host "[OUTPUT] $OutputPath"
