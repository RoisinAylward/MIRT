# plugins/hash_reputation.py

import os
import time
import re
import requests

PLUGIN_META = {
    "name": "hash_reputation_virustotal",
    "version": "0.1",
    "requires_env": ["VT_API_KEY"],
}

VT_API_URL = "https://www.virustotal.com/api/v3/files/"

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def is_sha256(hash_str):
    return bool(hash_str) and bool(SHA256_RE.match(str(hash_str).strip()))


def extract_hashes_with_context(artefacts):
    results = []

    for connection in artefacts.get("connections", []):
        conn_hash = connection.get("sha256")
        if is_sha256(conn_hash):
            results.append((conn_hash, {
                "source": "connections",
                "remote_ip": connection.get("remote_ip"),
                "process_id": connection.get("process_id"),
                "process_name": connection.get("process_name"),
                "exe_path": connection.get("exe_path")
            }))

    for persistence in artefacts.get("persistence", []):
        persistence_hash = persistence.get("sha256")
        if is_sha256(persistence_hash):
            results.append((persistence_hash, {
                "source": "persistence",
                "type": persistence.get("type"),
                "location": persistence.get("location"),
                "name": persistence.get("name"),
                "command": persistence.get("command"),
                "target_path": persistence.get("target_path")
            }))

    return results


def run(artefacts, config):
    findings = []

    API_KEY = os.environ.get("VT_API_KEY")
    if not API_KEY:
        findings.append({
            "plugin": PLUGIN_META["name"],
            "severity": "low",
            "title": "VirusTotal API key missing",
            "evidence": {"required_env": "VT_API_KEY"},
            "recommendation": "Set VT_API_KEY as an environment variable and re-run."
        })
        return findings

    thresholds = config.get("thresholds", {})
    malicious_min = int(thresholds.get("vt_malicious_min", 1))
    suspicious_min = int(thresholds.get("vt_suspicious_min", 1))
    request_delay = float(thresholds.get("vt_request_delay_seconds", 0.6))

    hash_context_pairs = extract_hashes_with_context(artefacts)

    if not hash_context_pairs:
        findings.append({
            "plugin": PLUGIN_META["name"],
            "severity": "low",
            "title": "No SHA-256 hashes found in artefacts",
            "evidence": {"hint": "Collector should include sha256 for processes/persistence targets."},
            "recommendation": "Update collector.ps1 to add sha256 fields, then re-run."
        })
        return findings

    contexts_by_hash = {}
    for hash, context in hash_context_pairs:
        if hash not in contexts_by_hash:
            contexts_by_hash[hash] = []
        contexts_by_hash[hash].append(context)

    headers = {"x-apikey": API_KEY, "Accept": "application/json"}

    cache = {}

    for hash, contexts in contexts_by_hash.items():
        if hash in cache:
            attributes = cache[hash]
        else:
            url = VT_API_URL + hash

            try:
                response = requests.get(url, headers=headers, timeout=15)
            except requests.RequestException as e:
                findings.append({
                    "plugin": PLUGIN_META["name"],
                    "severity": "medium",
                    "title": "VirusTotal request failed",
                    "evidence": {"sha256": hash, "error": str(e)},
                    "recommendation": "Check connectivity / API key / rate limits and retry."
                })
                continue

            if response.status_code == 404:
                findings.append({
                    "plugin": PLUGIN_META["name"],
                    "severity": "low",
                    "title": "Hash not found in VirusTotal",
                    "evidence": {"sha256": hash, "contexts": contexts},
                    "recommendation": "Treat as unknown; validate file origin and use other signals (path, signer, behaviour)."
                })
                continue

            if response.status_code != 200:
                findings.append({
                    "plugin": PLUGIN_META["name"],
                    "severity": "medium",
                    "title": "VirusTotal returned non-200 response",
                    "evidence": {"sha256": hash, "status_code": response.status_code, "body_snippet": response.text[:200]},
                    "recommendation": "Verify API key and handle rate limiting (429) with backoff."
                })
                continue

            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            cache[hash] = attributes

            time.sleep(request_delay) #program pauses for set amount of time before continuing

        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        if malicious >= malicious_min:
            severity = "high"
            title = f"Malicious file hash detected (VT): {hash}"
            recommendation = "Isolate host if needed; locate file on disk; investigate persistence/execution; collect additional artefacts."
        elif suspicious >= suspicious_min:
            severity = "medium"
            title = f"Suspicious file hash detected (VT): {hash}"
            recommendation = "Review file context (path/signer); investigate related processes and network activity; consider sandboxing."
        else:
            severity = "low"
            title = f"File hash checked (VT, no detections): {hash}"
            recommendation = "No detections reported, but continue triage using context (path, behaviour, provenance)."

        evidence = {
            "sha256": hash,
            "vt_type_description": attributes.get("type_description"),
            "meaningful_name": attributes.get("meaningful_name"),
            "last_analysis_stats": stats,
            "contexts": contexts,
        }

        findings.append({
            "plugin": PLUGIN_META["name"],
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation
        })

    return findings
