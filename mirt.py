#CONNECT TO COLLECTOR.PS1**********
import importlib
import os
import json
from pathlib import Path
from datetime import datetime, timezone

def load_json(path):
    with open(path, "r", encoding="utf-8-sig") as json_file: #utf-8-sig prevents errors as powershell uses utf-8 BOM
        return json.load(json_file)

def load_plugins(plugin_paths):
    plugins = []
    for plugin_path in plugin_paths:
        module = importlib.import_module(plugin_path)
        plugins.append(module)
    return plugins

def severity_key(finding):
    severity_order = {"high": 0, "medium": 1, "low": 2}
    severity = (finding.get("severity") or "low").lower()
    return severity_order.get(severity, 99) #99 puts nonanswers at end of report instead of crashing
  
def main():
    config_path = Path(os.environ.get("MIRT_CONFIG", "config.json"))
    artefacts_path = Path(os.environ.get("MIRT_ARTEFACTS"))
    run_dir = Path(os.environ.get("MIRT_RUN_DIR", "output"))
    
    config = load_json(config_path) 
    artefacts = load_json(artefacts_path)

    #output_dir = Path(config.get("output_dir", "output")) #WIP
    run_dir.mkdir(parents=True, exist_ok=True) #creates parent folder if missing; doesn't raise FileExistsError if folder already exists 
    run_id = (artefacts.get("run", {}) or {}).get("run_id")
    if not run_id:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    run_meta = {
        "run_id": run_id,
        "host": (artefacts.get("run", {}) or {}).get("host"),
        "timestamp_utc": (artefacts.get("run", {}) or {}).get("timestamp_utc")
    }

    findings = []
    for plugin in load_plugins(config.get("enabled_plugins", [])):
        try:
            findings.extend(plugin.run(artefacts, config))
        except Exception as e:
            plugin_name = getattr(plugin, "PLUGIN_META", {}).get("name", getattr(plugin, "__name__", "unknown_plugin"))
            findings.append({
                "plugin": plugin_name,
                "severity": "medium",
                "title": "Plugin execution failed",
                "evidence": {"error": str(e)},
                "recommendation": "Fix the plugin error and re-run."
            })
    for finding in findings:
        finding["run"] = run_meta

    findings_path = run_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as findings_file:
        findings_file.write(json.dumps(findings, indent=2))

    findings_sorted = sorted(findings, key=severity_key)

    host = run_meta.get("host") or "UNKNOWN_HOST"
    report_lines = [f"# MIRT Report ({run_id}) - {host}", ""]
    
    current_severity = None
    for finding in findings_sorted:
        severity = (finding.get("severity") or "low").lower()
        if severity != current_severity:
            report_lines.append(f"## {severity.upper()}")
            report_lines.append("")
            current_severity = severity
        title = finding.get("title") or "Untitled finding"
        plugin_name = finding.get("plugin") or "unknown_plugin"
        report_lines.append(f"- **{severity.upper()}**: {title} ({plugin_name})")
    
    report_path = run_dir / "report.md"
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines))

    print(f"Created: {run_dir}")

if __name__ == "__main__":
    main()
