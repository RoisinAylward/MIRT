param(
    [string]$OutputDir = ".\output"
)

Write-Host "[*] Starting Incident Response Workflow"

.\collector.ps1 -OutputPath "$OutputDir\artifacts.json"

python .\mirt.py --config .\config.json --output $OutputDir

Write-Host "[+] Workflow complete. Results saved in $OutputDir"