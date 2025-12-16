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

$networkConnections = Get-NetTCPConnection -State Established | Select-Object `
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    State,
    OwningProcess

$processes = Get-Process | Select-Object `
    Id,
    ProcessName,
    Path

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