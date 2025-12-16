#Modular Indient Response Triage Tool

##Project Overview:

This Project is a modular cybersecurity automation tool designed to perform basic incident response triage on a Windows system.
The tool collects system, network, persistence, and PowerShell artifacts using PowerShell, and then performs automated analysis, and enrichment using Python.
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
-Python 3.9 or later.
-Required Python packages (which is installed via pip):
pip install -r requirements.txt. 
-The python libraries used are:
requests - HTTP requests to security APIS
json - Parsing structured artifact data.
datetime - Timestamp handling
time - Rate limiting API requests
csv - Report generation
os/sys - Covers file handling, and execution.

**API Keys**
-VirusTotal API key
-AbuseIPDB API key

**PowerShell**
-Windows Powershell 5.1 or later.
-Administrator privileges recommended.
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

### 🔌 Plugins
- `encoded_pshunt.py` → Detects suspicious PowerShell commands (EncodedCommand, DownloadString).
- `hash_reputation.py` → Checks SHA256 hashes against VirusTotal.
- `ip_reputation.py` → Enriches remote IPs using AbuseIPDB.
- `persistence_check.py` → Flags suspicious Run key entries.

###Snippet of Json File (config.json):
{
    "output_dir": "output",
    "enabled_plugins": [
        "plugins.encoded_powershell_hunt",
        "plugins.hash_reputation",
        "plugins.ip_reputation"
    ],
    "thresholds": {
        "abuseipdb_score_high": 70,
        "abuseipdb_score_medium_min": 30,
        "abuseipdb_max_age_days": 90,
        "abuseipdb_request_delay_seconds": 0.6,
        
        "vt_malicious_min": 1,
        "vt_suspicious_min": 1,
        "vt_request_delay_seconds": 0.6
    }
}

##Limitations:
-Some executables cannot be hashed (locked/protected files).
-Only Run key persistence is checked (no scheduled tasks/services yet).
-PowerShell event filtering limited to EncodedCommand/DowloadString.
