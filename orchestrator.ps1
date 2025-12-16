param(
    [string]$OutputDir = ".\output"
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Starting Incident Response Workflow"

#This is to check if the required files exist before running.
if (-not (Test-Path ".\collector.ps1")) { throw "Missing .\collector.ps1" }
if (-not (Test-Path ".\mirt.py"))      { throw "Missing .\mirt.py" }
if (-not (Test-Path ".\config.json"))  { throw "Missing .\config.json" }

#This checks that 'python' is available on PATH:
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is not available. Install Python or add it to PATH (so 'python' works in terminal)."
}
#This makes sure the output directory exists:
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

#This is the command we use to create a run folder with timestamps:
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputDir "run_$timestamp"
New-Item -ItemType Directory -Path $runDir | Out-Null

try {
#Runs Powershells collector to gather artifacts:
    Write-Host "[*] Running Powershell collector..."
    .\collector.ps1 -OutputPath "$runDir\artifacts.json"
    
#In order to verify we created artifacts.json:
    if (-not (Test-Path "$runDir\artifacts.json")) {
        throw "Artifacts file was not created"
    }

#This command runs the python analysis orchestrator with config.json:
    Write-Host "[*] Running Python analysis..."
    python .\mirt.py --config .\config.json --out $runDir

    Write-Host "[+] Workflow complete. Results saved in $OutputDir"
}
#To catch errors so we can print them earlier we input the comand:
catch{ 
    Write-Error "[!] Workflow failed: $_"
}


