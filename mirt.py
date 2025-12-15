import importlib
import json
from pathlib import Path
from datetime import datetime, timezone

def load_json(path):
    with open(path, "r", encoding="utf-8") as json_file:
        return json.load(json_file)

def load_plugins(plugin_paths):
    plugins = []
    for plugin_path in plugin_paths:
        module = importlib.import_module(plugin_path)
        plugins.append(module)
    return plugins

def main():
    config = load_json(Path("config.json"))
    artefacts = load_json(Path("samples/artefacts.json"))

    output_dir = Path(config.get("output_dir", "output")) #WIP
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{run_id}" #NEED TO TEST IF OUTPUT FOLDER CAN BE CREATED FROM THIS PROGRAM
    run_dir.mkdir(parents=True, exist_ok=True) #creates parent folder if missing; doesn't raise FileExistsError if folder already exists 

    findings = []
    for plugin in load_plugins(config.get("enabled_plugins", [])):
        findings.extend(plugin.run(artefacts, config))
    findings_path = run_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as findings_file:
        findings_file.write(json.dumps(findings, indent=2))

    # WIP
    report_lines = [f"# MIRT Report ({run_id})", ""]
    for finding in findings:
        report_lines.append(f"- **{finding['severity'].upper()}**: {finding['title']} ({finding['plugin']})")
    report_path = run_dir / "report.md"
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines))

    print(f"Created: {run_dir}")

if __name__ == "__main__":
    main()
