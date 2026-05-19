def catch_dangerous_ports_and_crypto(rule):
    """
    FRAMEWORK: NIST SP 800-41 Rev. 1 & ISO 27001 (A.10.1.1 / A.13.2.1)
    TARGET: The most exhaustive list of insecure, unencrypted, and highly targeted remote management ports.
    """
    dst_port = str(rule.get('dst_port', '')).strip()
    action = str(rule.get('action', '')).strip().lower()

    if action not in ['allow', 'accept', 'permit']:
        return None

    findings = []

    if dst_port in ['20', '21']:
        findings.append({"severity": "Medium", "tag": "NIST 800-41", "desc": "FTP transmits in cleartext. Use SFTP."})
        findings.append({"severity": "Medium", "tag": "ISO 27001: A.10.1.1", "desc": "Lack of cryptographic controls for data transit."})
    elif dst_port == '23':
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "Telnet transmits passwords in cleartext. Strictly prohibited."})
        findings.append({"severity": "High", "tag": "ISO 27001: A.10.1.1", "desc": "Violation of cryptographic policy for administrative access."})
        findings.append({"severity": "High", "tag": "PCI-DSS v4.0", "desc": "Req 4.2.1: Strong cryptography required for transmission."})
        findings.append({"severity": "High", "tag": "HIPAA", "desc": "§ 164.312(e)(1): Transmission Security violation."})
        findings.append({"severity": "High", "tag": "CIS Control 3", "desc": "Data Protection: Encrypt sensitive data in transit."})
    elif dst_port == '80':
        findings.append({"severity": "Low", "tag": "NIST 800-41", "desc": "HTTP is unencrypted. Enforce HTTPS (443)."})
    elif dst_port in ['110', '143']:
        findings.append({"severity": "Medium", "tag": "NIST 800-41", "desc": "POP3/IMAP email transmits in cleartext. Use secure IMAPS/POP3S."})
    elif dst_port in ['161', '162']:
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "SNMPv1/v2c uses cleartext community strings. Upgrade to SNMPv3."})
    elif dst_port == '389':
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "LDAP transmits directory credentials in cleartext. Use LDAPS (636)."})
    elif dst_port in ['512', '513', '514']:
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "Legacy rsh/rlogin/rexec protocols are fundamentally insecure."})

    # 2. Remote Access / Desktop Protocols (Ransomware Targets)
    elif dst_port == '3389':
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "RDP is highly targeted by ransomware. Place behind a VPN with MFA."})
    elif dst_port in ['5900', '5901']:
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "VNC remote access is highly vulnerable if exposed to untrusted networks."})
    elif dst_port in ['6000', '6001']:
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "X11 window system lacks encryption and is vulnerable to session hijacking."})

    elif dst_port in ['135', '137', '138', '139', '445']:
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "NetBIOS/SMB should NEVER cross a firewall boundary. High risk of worm propagation."})
    elif dst_port == '111':
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "RPC portmapper is frequently exploited for DDoS amplification or enumeration."})
    elif dst_port == '69':
        findings.append({"severity": "Medium", "tag": "NIST 800-41", "desc": "TFTP has no authentication. Unsafe for cross-zone transfers."})

    elif dst_port == '2375':
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "Unencrypted Docker API exposed. Allows full container takeover."})
    elif dst_port == '6379':
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "Redis lacks default authentication. High risk of data wipe/crypto-mining."})
    elif dst_port == '9200':
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": "Elasticsearch API exposed. High risk of massive data exfiltration."})
    elif dst_port == '11211':
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "Memcached exposed. Highly vulnerable to UDP DDoS amplification attacks."})

    elif dst_port in ['1433', '1434', '3306', '5432', '1521', '27017']:
        findings.append({"severity": "Critical", "tag": "NIST 800-41", "desc": f"Database port {dst_port} should never be reachable directly via the firewall."})
        findings.append({"severity": "Critical", "tag": "ISO 27001: A.13.2.1", "desc": "Information transfer policy violation. Databases must reside in secure isolated zones."})

        findings.append({"severity": "Critical", "tag": "PCI-DSS v4.0", "desc": "Req 1.3.1: Restrict inbound traffic to the cardholder data environment."})
        findings.append({"severity": "Critical", "tag": "SOC 2", "desc": "CC6.6: Logical access security boundary failure."})
    elif dst_port == '53' and str(rule.get('protocol', '')).strip().upper() == 'TCP':
        findings.append({"severity": "Low", "tag": "NIST 800-41", "desc": "DNS over TCP allows zone transfers. Restrict to authorized secondary servers."})
    elif dst_port == '5060':
        findings.append({"severity": "Medium", "tag": "NIST 800-41", "desc": "SIP (VoIP) is unencrypted. Vulnerable to toll fraud and eavesdropping."})
    elif dst_port in ['6667', '6668', '6669']:
        findings.append({"severity": "High", "tag": "NIST 800-41", "desc": "IRC ports are frequently used for Botnet Command & Control (C2) traffic."})

    return findings if findings else None


def catch_iso_shadow_rules(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.12.1.1 (Documented Operating Procedures)
    TARGET: Identifies orphaned rules causing router bloat.
    """
    # 🟢 THE FIX: Check for None and catch TypeError
    raw_hits = rule.get('hit_count', 1)
    try:
        hits = int(raw_hits) if raw_hits is not None else 1
    except (ValueError, TypeError):
        hits = 1

    if hits == 0:
        return [{"severity": "Low", "tag": "ISO 27001: A.12.1.1", "desc": "0 hits detected. Demonstrates lack of rule lifecycle maintenance."}]
    return None


def catch_iso_lazy_access(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.9.1.2 (Access to Networks)
    TARGET: Flags 'Any-to-Any' rules that violate explicit access control policies.
    """
    src_ip = str(rule.get('src_ip', '')).strip().lower()
    dst_ip = str(rule.get('dst_ip', '')).strip().lower()
    action = str(rule.get('action', '')).strip().lower()

    if src_ip in ['any', '0.0.0.0/0'] and dst_ip in ['any', '0.0.0.0/0'] and action in ['allow', 'accept', 'permit']:
        return [{"severity": "High", "tag": "ISO 27001: A.9.1.2", "desc": "Permissive 'Any-to-Any' access detected. Access must be explicitly granted based on business need."}]
    return None


def catch_iso_missing_logs(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.12.4.1 (Event Logging)
    TARGET: Ensures that critical traffic is being actively audited/logged.
    """
    action = str(rule.get('action', '')).strip().lower()

    if 'log' not in action and action in ['allow', 'accept', 'permit']:
        return [{"severity": "Low", "tag": "ISO 27001: A.12.4.1", "desc": "Allowed traffic lacks explicit logging command. Audit trails are required for security events."}]
    return None


def catch_iso_any_source_admin(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.13.1.1 (Network Controls)
    TARGET: Flags rules allowing the entire internet to hit management ports.
    """
    dst_port = str(rule.get('dst_port', '')).strip()
    src_ip = str(rule.get('src_ip', '')).strip().lower()
    action = str(rule.get('action', '')).strip().lower()

    if action in ['allow', 'accept', 'permit'] and src_ip in ['any', '0.0.0.0/0']:
        if dst_port in ['22', '3389', '443']:
            return [{"severity": "Critical", "tag": "ISO 27001: A.13.1.1", "desc": f"Management port {dst_port} is exposed to 'Any' source. Requires strict IP whitelisting or VPN."}]
    return None

SECURITY_CHECKS = [
    catch_dangerous_ports_and_crypto,
    catch_iso_shadow_rules,
    catch_iso_lazy_access,
    catch_iso_missing_logs,
    catch_iso_any_source_admin
]

def analyze_rule(rule):
    findings = []
    highest_severity = "OK"

    for check_function in SECURITY_CHECKS:
        result_list = check_function(rule)

        if result_list:
            for result in result_list:
                findings.append(result)

                sev = result["severity"]
                if sev == "Critical":
                    highest_severity = "CRITICAL"
                elif sev == "High" and highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
                elif sev == "Medium" and highest_severity not in ["CRITICAL", "HIGH"]:
                    highest_severity = "MEDIUM"
                elif sev == "Low" and highest_severity == "OK":
                    highest_severity = "LOW"

    rule['findings'] = findings
    rule['status'] = highest_severity

    return rule