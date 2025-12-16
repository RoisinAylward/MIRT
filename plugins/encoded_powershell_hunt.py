# plugins/encoded_powershell_hunt.py

import re

PLUGIN_META = {
    "name": "encoded_powershell_hunt",
    "version": "0.1",
    "requires_env": []
}

ENC_RE = re.compile(r"(?i)\-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]{10,})")

SUSPICIOUS_SWITCHES = [
    "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden",
    "-noninteractive",
    "-executionpolicy bypass", "-ep bypass",
]

SUSPICIOUS_KEYWORDS = [
    "iex", "invoke-expression",
    "downloadstring", "webclient",
    "frombase64string",
    "invoke-webrequest", "iwr",
    "invoke-restmethod", "irm",
    "http://", "https://"
]


def run(artefacts, config):
    events = artefacts.get("powershell_events", [])
    if not events:
        return []

    hits = []

    for event in events:
        msg = event.get("message") or ""
        msg_lower = msg.lower()

        match = ENC_RE.search(msg)
        if not match:
            continue

        token = match.group(1)

        switch_hits = []
        for switch in SUSPICIOUS_SWITCHES:
            if switch in msg_lower:
                switch_hits.append(switch)

        keyword_hits = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in msg_lower:
                keyword_hits.append(keyword)


        hits.append({
            "event_id": event.get("event_id"),
            "time_created": event.get("time_created"),
            "switch_indicators": switch_hits,
            "message_indicators": keyword_hits,
            "encoded_token_len": len(token),
            "encoded_token_preview": token[:30] + ("..." if len(token) > 30 else "")
        })

    if not hits:
        return []

    score = 0
    for hit in hits:
        if hit["switch_indicators"]:
            score += 1
        if hit["message_indicators"]:
            score += 1

    if score >= 4:
        severity = "high"
    elif score >= 2:
        severity = "medium"
    else:
        severity = "medium"

    return [{
        "plugin": PLUGIN_META["name"],
        "severity": severity,
        "title": f"Encoded PowerShell usage detected ({len(hits)} event(s))",
        "evidence": {
            "count": len(hits),
            "events_preview": hits[:5],
            "note": "Preview shows first 5 matches. Expand if you want full list."
        },
        "recommendation": (
            "Review command context and script block content. "
            "EncodedCommand is commonly used for obfuscation; confirm if it is expected admin activity."
        )
    }]
