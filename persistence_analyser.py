def analyse(artifacts, config):
    findings = []

    persistence_items = artifacts.get("persistence", [])

    suspicious_paths = [
        "\\AppData\\",
        "\\Temp\\",
        "\\Downloads",
        "\\Users\\Public\\"
    ]

    for entry in persistence_items:
        reasons = []

        target = entry.get("target_path")
        sha256 = entry.get("sha256")

        if not target:
            reasons.append("No executable path extracted")

        if target: 
            for path in suspicious_paths:
                if path.lower() in target.lower():
                    reasons.append(f"Executable located in user-writable path: {path}")
                    break

            if not sha256:
                reasons.append("Executable hash missing or could not be calculated")

            if reasons:
                findings.append({
                    "category": "persistence",
                    "type": entry.get("type"),
                    "name": entry.get("name"),
                    "location": entry.get("location"),
                    "command": entry.get("command"),
                    "target_path": target,
                    "sha256": sha256,
                    "severity": "medium",
                    "reasons": reasons
                })

    return findings
