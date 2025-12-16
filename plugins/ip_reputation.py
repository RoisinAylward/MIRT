# plugins/ip_reputation.py
import os
import time
import ipaddress
import requests

PLUGIN_META = {
    "name": "ip_reputation_abuseipdb",
    "version": "0.2", #with error handeling now
    "requires_env": ["ABUSEIPDB_API_KEY"]
}

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check" #the endpoint


def is_global_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str) #converts the string to an ip object if valid and global
        return ip.is_global #returns True
    except ValueError:
        return False


def extract_ip_to_connections(artefacts): #artefacts=samples/artefacts.json
    ip_to_conns = {}
    for connection in artefacts.get("connections", []):
        ip = connection.get("remote_ip")
        if not ip: #if null
            continue #next iteration
        if ip not in ip_to_conns:
            ip_to_conns[ip] = [] #creates key
        ip_to_conns[ip].append(connection) #appends value
    return ip_to_conns


def run(artefacts, config):
    findings = []

    API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
    if not API_KEY:
        findings.append({ 
            "plugin": PLUGIN_META["name"],
            "severity": "low",
            "title": "AbuseIPDB API key missing",
            "evidence": {"required_env": "ABUSEIPDB_API_KEY"},
            "recommendation": "Set ABUSEIPDB_API_KEY as an environment variable and re-run."
        })
        return findings

    thresholds = config.get("thresholds", {})
    high_score = int(thresholds.get("abuseipdb_score_high", 70))
    medium_min = int(thresholds.get("abuseipdb_score_medium_min", 30))
    max_age_days = int(thresholds.get("abuseipdb_max_age_days", 90))
    request_delay = float(thresholds.get("abuseipdb_request_delay_seconds", 0.6))

    ip_to_conns = extract_ip_to_connections(artefacts)

    #removes private ips:
    candidate_ips = []
    for ip in ip_to_conns.keys():
        if is_global_ip(ip):
            candidate_ips.append(ip)
    candidate_ips.sort()

    headers = {"Key": API_KEY, "Accept": "application/json"}

    cache = {}

    for ip in candidate_ips:
        if ip in cache: #checks if the ip was already looked up in this run
            data = cache[ip]
        else:
            params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}

            try:
                response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
            except requests.RequestException as e: #specific error to prevent unrelated bugs being hidden
                findings.append({
                    "plugin": PLUGIN_META["name"],
                    "severity": "medium",
                    "title": "AbuseIPDB request failed",
                    "evidence": {"ip": ip, "error": str(e)},
                    "recommendation": "Check connectivity / API key / rate limits and retry."
                })
                continue #next iteration if error

            if response.status_code != 200: #not sucessfull
                findings.append({
                    "plugin": PLUGIN_META["name"],
                    "severity": "medium",
                    "title": "AbuseIPDB returned non-200 response",
                    "evidence": {"ip": ip, "status_code": response.status_code, "body_snippet": response.text[:200]},
                    "recommendation": "Verify API key and rate limits."
                })
                continue #next iteration if response not successfull

            payload = response.json() #parsing response as json
            data = payload.get("data", {})
            cache[ip] = data

            time.sleep(request_delay)#program pauses for set amount of time before continuing

        score = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        
        conns = ip_to_conns.get(ip, [])
        evidence_conns = []
        for conn in conns:
            evidence_conns.append({
                "process_id": conn.get("process_id"),
                "process_name": conn.get("process_name")
            })

        if score >= high_score: #if ip has many reports of abusing activity
            findings.append({
                "plugin": PLUGIN_META["name"],
                "severity": "high",
                "title": f"High-risk remote IP detected: {ip}",
                "evidence": {
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "total_reports": total_reports,
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "connections": evidence_conns
                },
                "recommendation": "Investigate owning process; validate binary hash; consider blocking the IP and hunting related IOCs."
            })
        
        elif medium_min <= score < high_score: #if ip has some reports of abusing activity
            findings.append({
                "plugin": PLUGIN_META["name"],
                "severity": "medium",
                "title": f"Moderate-risk remote IP detected: {ip}",
                "evidence": {
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "total_reports": total_reports,
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "connections": evidence_conns
                },
                "recommendation": "Review the owning process and connection context; monitor for repeat activity; consider additional enrichment (VT hash lookup, event log review)."
            })

    return findings
