param(
    [string]$OutputDir = ".\output"
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Starting Incident Response Workflow"

if (-not (Test-Path ".\collector.ps1")) { throw "Missing .\collector.ps1" }
if (-not (Test-Path ".\mirt.py"))      { throw "Missing .\mirt.py" }
if (-not (Test-Path ".\config.json"))  { throw "Missing .\config.json" }

# Check that 'python' is available on PATH
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is not available. Install Python or add it to PATH (so 'python' works in terminal)."
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputDir "run_$timestamp"
New-Item -ItemType Directory -Path $runDir | Out-Null

try {
    Write-Host "[*] Running Powershell collector..."
    .\collector.ps1 -OutputPath "$runDir\artifacts.json"

    if (-not (Test-Path "$runDir\artifacts.json")) {
        throw "Artifacts file was not created"
    }

    Write-Host "[*] Running Python analysis..."
    python .\mirt.py --config .\config.json --out $runDir

    Write-Host "[+] Workflow complete. Results saved in $OutputDir"
}
catch{ 
    Write-Error "[!] Workflow failed: $_"
}

