def analyse(artifacts, config):
    findings = [] #This creates a list to store any suspicious persistence findings.

    #This gets persistence-related items from the artifacts dictionary (default to empty list if missing)
    persistence_items = artifacts.get("persistence", [])
   
    #This defines the paths that are considered suspicious because they are user-writable:
    suspicious_paths = [
        "\\AppData\\",
        "\\Temp\\",
        "\\Downloads",
        "\\Users\\Public\\"
    ]

    #To loop through each persistence entry we input:
    for entry in persistence_items:
        reasons = []

        #This extracts key fields from the entry.
        target = entry.get("target_path")
        sha256 = entry.get("sha256")

        #When no target is found, this flags the issue:
        if not target:
            reasons.append("No executable path extracted")

        #If the target path is found, you check further using:
        if target: 
            #Checks the target path is found in a suspicious user-writable directory
            for path in suspicious_paths:
                if path.lower() in target.lower():
                    reasons.append(f"Executable located in user-writable path: {path}")
                    break #This causes the loop to stop after the first match.

            #If the hash is not found, this will flag it:
            if not sha256:
                reasons.append("Executable hash missing or could not be calculated")

            #When suspicious reasons are found, this will record this entry in findings:
            if reasons:
                findings.append({
                    #This consists of the categories:
                    "category": "persistence",
                    "type": entry.get("type"),
                    "name": entry.get("name"),
                    "location": entry.get("location"),
                    "command": entry.get("command"),
                    "target_path": target,
                    "sha256": sha256,
                    "severity": "medium",
                    "reasons": reasons 
                    
#Which represent the types of finding, the persistence type, the name of the entry,
#where it was found, the commands used, the path, and hash to, and of the executable.
#And also the severity level assigned, and the list of reasons why it was flagged.
                })

    return findings #This input returns all suspicious persistence findings.


