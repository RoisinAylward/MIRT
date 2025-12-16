param(
    [string]$OutputPath = ".\artifacts.json"
)

$ErrorActionPreference = "Continue"

Write-Host "[*] Starting basic triage collection..."

$run = [PSCustomObject]@{
    host = $env:COMPUTERNAME
    username = $env:USERNAME
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
}

$processes = Get-Process | Select-Object `
    Id,
    ProcessName,
    Path

$procIndex = @{}
foreach ($p in $processes) {
    $procIndex[$p.Id] = $p
}

$connections = Get-NetTCPConnection -State Established |
Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" } |
ForEach-Object {
    $procId = $_.OwningProcess
    $p = $procIndex[$procId]

    $exePath = $null
    $procName = $null
    if ($p) {
        $exePath = $p.Path
        $procName = $p.ProcessName
    }
    
    $sha256 = $null 
    if ($exePath -and (Test-Path -LiteralPath $exePath)) {
        try { 
            $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exePath -ErrorAction SilentlyContinue).Hash 
        } catch { 
            $sha256 = $null 
        }
    }

    [PSCustomObject]@{
        local_ip = $_.LocalAddress
        local_port = $_.LocalPort
        remote_ip = $_.RemoteAddress
        remote_port = $_.RemotePort
        state = $_.State
        process_id = $procId
        process_name = $procName
        exe_path = $exePath
        sha256 = $sha256
    }
}

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$persistence = @()

if (Test-Path $runKeyPath) {
    Get-ItemProperty $runKeyPath | ForEach-Object{
        $_.PSObject.Properties |
        Where-Object {$_.Name -notlike "PS*"} |
        ForEach-Object {
            $cmd = [string]$_.Value

            $target = $null 
            if ($cmd -match '^\s*"(.*?)"') { $target = $Matches[1] } 
            else { $target = ($cmd -split '\s+')[0] } 
            
            $targetHash = $null 
            if ($target -and (Test-Path -LiteralPath $target)) { 
                try { 
                    $targetHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target -ErrorAction SilentlyContinue).Hash 
                } catch { 
                    $targetHash = $null 
                } 
            }

            $persistence += [PSCustomObject]@{
                type = "RunKey"
                location = $runKeyPath
                name = $_.Name
                command = $cmd
                target_path = $target
                sha256 = $targetHash
            }
        }
    }
}

$powershell_events = @()
try {
    $powershell_events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
    Where-Object { $_.Message -match "EncodedCommand|DownloadString" } |
    Select-Object `
        @{n="time_created";e={$_.TimeCreated.ToUniversalTime().ToString("o")}}, `
        @{n="event_id";e={$_.Id}}, `
        @{n="message";e={$_.Message}}
} catch {
    $powershell_events = @()
}

$artefacts = [PSCustomObject]@{
    run = $run
    connections = $connections
    persistence = $persistence
    powershell_events = $powershell_events
    processes = $processes
}

$artefacts | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $OutputPath

Write-Host "[+] Collection complete. Output saved to $OutputPath"
