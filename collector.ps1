param(
    [string]$OutputPath = ".\artefacts.json"
)

#This shows errors but keeps collecting data.
$ErrorActionPreference = "Continue"

#This displays text straight to console:
Write-Host "[*] Starting basic triage collection..."

#This colects basic system info:
$run = [PSCustomObject]@{
    host = $env:COMPUTERNAME
    username = $env:USERNAME
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
}

#This collects run processes like Id.
$processes = Get-Process | Select-Object `
    Id,
    ProcessName,
    Path

#This makes the lookup table:
$procIndex = @{}
foreach ($p in $processes) {
    $procIndex[$p.Id] = $p
}

#These commands collect the active TCP connections, and is improved with the process info.
$connections = Get-NetTCPConnection -State Established |
Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" } |
ForEach-Object {
    $procId = $_.OwningProcess
    $p = $procIndex[$procId]

#These are the default values if process is not found:
    $exePath = $null
    $procName = $null
    if ($p) {
        $exePath = $p.Path
        $procName = $p.ProcessName
    }

#This would try to hash the files, and can fail if the file is locked.
    $sha256 = $null 
    if ($exePath -and (Test-Path -LiteralPath $exePath)) {
        try { 
            $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exePath -ErrorAction SilentlyContinue).Hash 
        } catch { 
            $sha256 = $null 
        }
    }

#This creates the connection object with proccess details:
    [PSCustomObject]@{
        local_ip = $_.LocalAddress
        local_port = $_.LocalPort
        remote_ip = $_.RemoteAddress
        remote_port = $_.RemotePort
        state = $_.State.ToString()
        process_id = $procId
        process_name = $procName
        exe_path = $exePath
        sha256 = $sha256
    }
}

#This would look at Run key entries:
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$persistence = @()

if (Test-Path $runKeyPath) {
    Get-ItemProperty $runKeyPath | ForEach-Object{
        $_.PSObject.Properties |
        Where-Object {$_.Name -notlike "PS*"} |
        ForEach-Object {
            $cmd = [string]$_.Value

#This extracts the target executable path from the command string
            $target = $null 
            if ($cmd -match '^\s*"(.*?)"') { $target = $Matches[1] } 
            else { $target = ($cmd -split '\s+')[0] } 

            #Tries to hash the target binary:
            $targetHash = $null 
            if ($target -and (Test-Path -LiteralPath $target)) { 
                try { 
                    $targetHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target -ErrorAction SilentlyContinue).Hash 
                } catch { 
                    $targetHash = $null 
                } 
            }

#This builds persistence entry object:
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

#This collects the suspicious Powershell events:
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

#This combines all the artefacts into one object:
$artefacts = [PSCustomObject]@{
    run = $run
    connections = $connections
    persistence = $persistence
    powershell_events = $powershell_events
    processes = $processes
}

#This would export the artifacts to the JSON file:
$artefacts | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $OutputPath

Write-Host "[+] Collection complete. Output saved to $OutputPath"



