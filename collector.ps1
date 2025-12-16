param(
    [string]$OutputPath = ".\artifacts.json"
)

$ErrorActionPreference = "Continue"

Write-Host "[*] Starting basic triage collection..."

$systemInfo = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    TimestampUTC = (Get-Date).ToUniversalTime().ToString("o")
}

$processLookup = @{}
Process | ForEach-Object {
$processLookup[$_.Id] = @{
    Name = $_.ProcessName
    Path = $_.Path
 }
}

$networkConnections = Get-NetTCPConnection -State Established | ForEach-Object {
    $procInfo = $processLookup[$_.OwningProcess]
    [PSCustomObject]@{
    LocalAddress = $_.LocalAddress
    LocalPort = $_.LocalPort
    RemoteAddress = $_.RemoteAddress
    RemotePort = $_.RemotePort
    State = $_.State
    OwningProcess = $_.OwningProcess
    ProcessName = $procInfo_.Name
    ProcessPath = $procInfo_.Path
    }
}

$processes = Get-Process | ForEach-Object {
    $hash = $null
    if ($_.Path -and (Test-Path $_.Path)) {
        try {
            $hash = (Get-FileHash -Path $_.Path -Algorithm SHA256).Hash
        } catch {
            $hash = $null
        } 
    }
    [PSCustomObject]@{
    Id = $_.Id
    ProcessName = $_.ProcessName
    Path = $_.Path
    SHA256 = $hash
    }
}

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$persistence = @()

if (Test-Path $runKeyPath) {
    Get-ItemProperty $runKeyPath | ForEach-Object{
    $_.PSObject.Properties |
    Where-Object {$_.Name -notlike "PS*"} |
    ForEach-Object {
        $persistence += @{
            Name = $_.Name
            Command = $_.Value
        }
    }
} 

}

$powershellLogs = Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" -MaxEvents 100
Where-Object { $_.Message -match "EncodedCommand|DownloadString"} |
Select-Object TimeCreated, Id, Message

$artifacts = @{
    System = $systemInfo
    NetworkConnections = $networkConnections
    Processes = $processes
    Persistence = $persistence
    SuspiciousPowershellEvents = $powershellLogs
}

$artifacts | Convertto-Json -Depth 5 | Out-File -Encoding utf8 $OutputPath


Write-Host "[+] Collection.complete. Output saved to $OutputPath"
