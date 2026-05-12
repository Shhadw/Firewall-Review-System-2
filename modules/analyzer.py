INSECURE_PORTS = {
    21: "FTP (Transmits passwords in plain text)",
    23: "Telnet (Unencrypted communication)",
    80: "HTTP (Unencrypted web traffic)",
    445: "SMB (Highly vulnerable to ransomware attacks)"
}

def analyze_rules(rules_list):
    findings = []
    findings += check_open_ports(rules_list)
    findings += check_overly_permissive(rules_list)
    return findings

def check_open_ports(rules):
    port_findings = []
    for rule in rules:
        action = rule.get("action", "")
        # FIX: Changed 'port' to 'dst_port' to match reader.py
        port = rule.get("dst_port")
        protocol = rule.get("protocol", "")
        rule_id = rule.get("order") or "Unknown"

        # ISO/NIST Standard: Only flag TCP protocols for these unencrypted services
        if action in ["ALLOW", "ACCEPT"] and port is not None:
            if protocol == "tcp" and port in INSECURE_PORTS:
                port_findings.append({
                    "rule_id": rule_id,
                    "severity": "High",
                    "issue": "Insecure Port Allowed",
                    "message": f"Port {port} ({INSECURE_PORTS[port]}) is permitted over TCP."
                })
    return port_findings

def check_overly_permissive(rules):
    permissive_findings = []
    for rule in rules:
        action = rule.get("action", "")
        src = rule.get("src_ip", "").lower()
        dst = rule.get("dst_ip", "").lower()
        rule_id = rule.get("order") or "Unknown"

        if action in ["ALLOW", "ACCEPT"]:
            # NIST Principle: Principle of Least Privilege violations
            if src == "any" and dst == "any":
                permissive_findings.append({
                    "rule_id": rule_id,
                    "severity": "High",
                    "issue": "Overly Permissive Rule",
                    "message": "Critical: Any-to-Any traffic provides no perimeter defense."
                })
            elif src == "any":
                permissive_findings.append({
                    "rule_id": rule_id,
                    "severity": "Medium",
                    "issue": "Wide Source Exposure",
                    "message": "Public access allowed; violates Least Privilege."
                })
    return permissive_findings