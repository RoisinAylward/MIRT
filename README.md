# Modular IR Triage (MIRT) Toolkit: A Plugin-Based Mini DFIR Framework

## Project Overview

This project is a modular cybersecurity automation tool designed to perform basic incident response triage on a Windows system.
The tool collects system, network, persistence, and PowerShell artefacts using PowerShell, and then performs automated analysis and enrichment using Python.
The project demonstrates automation, scripting, and security analysis techniques covered throughout the module.

Built as a pair project by Roisin Aylward and Livia Mathew for Scripting for Cybersecurity (COMP H2702) at TU Dublin, and submitted in December 2025 with a [technical report (PDF)](documentation/Technical%20Report.pdf).

---

## Who Built What

The work was split by language: Livia led the PowerShell side and Roisin led the Python side. The technical report has a section from each of us explaining our own files.

| Part | What it does | Built by |
|------|--------------|----------|
| `collector.ps1` | Collects running processes, TCP connections (with a SHA-256 hash of each owning executable), HKCU Run-key persistence entries and PowerShell Operational log events into `artefacts.json` | Livia |
| `orchestrator.ps1` | Creates a timestamped run folder, runs the collector, then runs the Python analysis | Livia |
| `mirt.py` | The Python core: loads the plugins listed in `config.json`, collects their findings into `findings.json` and writes `report.md` grouped by severity | Roisin |
| `plugins/ip_reputation.py` | Looks up public IP addresses on AbuseIPDB, with caching and a delay between requests | Roisin |
| `plugins/hash_reputation.py` | Checks unique SHA-256 hashes against VirusTotal, with caching and a delay between requests | Roisin |
| `plugins/encoded_powershell_hunt.py` | Searches PowerShell events for encoded commands and other suspicious switches and keywords | Roisin |
| `plugins/persistence_analyser.py` | Flags Run-key entries that point to user-writable paths or whose executable couldn't be hashed | Designed together |
| `config.json` | Enables the plugins and sets the severity thresholds and API request delays | Written together |
| `README.md` | Setup, usage, plugin overview and limitations | Livia (formatting tidied by Roisin in November 2026) |

Roisin also reviewed Livia's PowerShell files and made changes so they worked with the Python side and the output files.

---

## Outcome

The toolkit was tested end to end on a Windows laptop in December 2025. The full output of that run is in [`samples/run_20251216_233939/`](samples/run_20251216_233939), with the laptop's public IPv6 address anonymised.

In that run:

- The collector gathered 402 processes, 63 network connections, 6 Run-key persistence entries and 10 PowerShell events.
- `hash_reputation.py` checked 5 unique executable hashes against VirusTotal, with no detections.
- `persistence_analyser.py` flagged 2 Run-key entries as medium severity, because their executables were in a user-writable `AppData` folder (and one couldn't be hashed).
- `encoded_powershell_hunt.py` found no encoded or suspicious PowerShell commands.
- No AbuseIPDB key was set for this run, so `ip_reputation.py` reported the missing key as a finding instead of stopping the run.

Everything ended up in one [`report.md`](samples/run_20251216_233939/report.md), grouped by severity, plus a machine-readable [`findings.json`](samples/run_20251216_233939/findings.json).

As a triage tool, MIRT errs on the side of caution, so some findings (like the two persistence entries above) are expected to be legitimate software that an analyst then confirms.

---

## Project Contents

- `collector.ps1`: a PowerShell script for collecting artefacts.
- `orchestrator.ps1`: a wrapper script that runs the collector and the Python analysis in one workflow.
- `plugins/`: Python plugins for analysis (for example, the encoded PowerShell hunt and hash reputation).
- `samples/`: sample outputs from a real run (public IPv6 address anonymised).
- `mirt.py`: the Python orchestrator for plugin execution.
- `config.json`: plugin configuration and severity thresholds.
- `requirements.txt`: the Python dependencies.
- `documentation/Technical Report.pdf`: the technical report submitted for the module.

> `artefacts.json` is generated at runtime and is not committed to the repository (apart from the samples). It holds the collected artefacts.

---

## Setup Instructions

### Required Packages / Modules

**Python**

- Python 3.9 or later.
- Required Python packages (installed via pip):

  ```
  pip install -r requirements.txt
  ```

- The Python libraries used are:
  - `requests`: HTTP requests to security APIs
  - `json`: parsing structured artefact data
  - `datetime`: timestamp handling
  - `time`: rate limiting API requests
  - `os` / `sys`: file handling and execution

**API Keys**

- VirusTotal API key
- AbuseIPDB API key

**PowerShell**

- Windows PowerShell 5.1 or later.
- Administrator privileges recommended.
- Ensure the script execution policy allows running local scripts:

  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  ```

---

## Usage Instructions

### How to Set Environment Variables Temporarily

```powershell
$env:ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
$env:VT_API_KEY = "your_virustotal_key_here"

# To verify:
echo $env:ABUSEIPDB_API_KEY
echo $env:VT_API_KEY
```

### How to Set Environment Variables Permanently

```powershell
[System.Environment]::SetEnvironmentVariable("ABUSEIPDB_API_KEY", "your_key_here", "User")
[System.Environment]::SetEnvironmentVariable("VT_API_KEY", "your_key_here", "User")
```

### How to Run the PowerShell Collector

```powershell
.\collector.ps1
```

### How to Run the Orchestrator (Collector and the Python Analysis)

```powershell
.\orchestrator.ps1
```

### Outputs

Outputs are saved in a timestamped folder like so:

```
output/run_YYYYMMDD_HHMMSS/
    ├── artefacts.json
    ├── findings.json
    └── report.md
```

---

## 🔌 Plugins

- `encoded_powershell_hunt.py`: detects suspicious PowerShell commands (EncodedCommand, DownloadString).
- `hash_reputation.py`: checks SHA-256 hashes against VirusTotal.
- `ip_reputation.py`: enriches remote IPs using AbuseIPDB.
- `persistence_analyser.py`: flags suspicious Run key entries.

### Snippet of the JSON File (config.json)

```json
{
    "output_dir": "output",
    "enabled_plugins": [
        "plugins.encoded_powershell_hunt",
        "plugins.hash_reputation",
        "plugins.ip_reputation",
        "plugins.persistence_analyser"
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
```

---

## Limitations

- Some executables cannot be hashed (locked/protected files).
- Only Run key persistence is checked (no scheduled tasks/services yet).
- PowerShell event filtering is limited to EncodedCommand/DownloadString.
