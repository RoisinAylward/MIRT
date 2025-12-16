#Modular Indient Response Triage Tool

##Project Overview:
This Project is a modular cybersecurity automation tool designed to perform basic incident response triage on a Windows system.
The tool collects system, network, persistence, and Powershell artifacts using PowerShell, and then performs automated analysis, and enrichment using Python.
The project demonstrates automation, scripting, and security analysis techniques covered throughout the module.

##Contents:
- `collector.ps1` -> This is a powershell script for collecting artifacts.
- `orchestrator.ps1` -> Wrapper script that runs the collector, and the Python analysis in one workflow. 
- `artifacts.json`-> This defines the collected artifacts.
- `plugins/` -> Python plugins for analysis (for example, the encoded Powershell hunt, hash reputation).
- `samples/` -> These are sample scripts, and outputs.
- `mirt.py` -> The python orchestrator for plugin execution.
- `config.json` -> Used for plugin configuration, and severity mapping.
- `requirements.txt` -> The python dependencies.

##Setup Instructions

###Required Packages / Modules
**Python**
**JSON**
**PowerShell**
-Windows Powershell 
-Ensure script execution policy allows running local scripts:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

##Usage Instructions

###How to run the PowerShell Collector
```powershell
.\collector.ps1 -OutputPath .\output\artifacts.json

###How to run the Orchestrator (Collector, and the Python Analysis)
.\orchestrator.ps1 -OutputDir .\output

###How to run the Python Core directly:
python mirt.py --config config.json --out output/

###Outputs are saved in a timestamped folder like so:
output/run_YYYYMMDD_HHMMSS/
    ├── artifacts.json
    ├── findings.json
    └── report.csv

