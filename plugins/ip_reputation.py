#ALL WIP
PLUGIN_META = {
    "name": "example_local_plugin",
    "version": "0.1",
    "requires_env": []
}

def run(artefacts, config):
    findings = []
    events = artefacts.get("powershell_events", [])
    for event in events:
        msg = (event.get("message") or "").lower()
        if "-encodedcommand" in msg:
            findings.append({
                "plugin": PLUGIN_META["name"],
                "severity": "medium",
                "title": "Possible encoded PowerShell usage",
                "evidence": {"event_id": event.get("event_id"), "message": event.get("message")},
                "recommendation": "Review script block content; extract and decode payload if appropriate."
            })
    return findings
