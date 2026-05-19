# Detailed mapping containing unencrypted and dangerous ports with full framework justification descriptions
INSECURE_PORTS_METADATA = {
    '20': {"name": "FTP (Data)", "alt": "SFTP", "nist_rationale": "Transmits data across network perimeters in unencrypted plaintext, allowing unauthorized actors to perform network sniffing and packet capture attacks.", "iso_rationale": "Direct breach of cryptographic protection mandates. Explicit transit encryption is required to protect information exchange segments."},
    '21': {"name": "FTP (Control)", "alt": "SFTP", "nist_rationale": "Exposes cleartext administrative credentials over control streams, facilitating lateral interception and credential harvesting vectors.", "iso_rationale": "Fails secure system architecture guidelines due to missing cryptographic controls for authenticated control traffic."},
    '23': {"name": "Telnet", "alt": "SSH", "nist_rationale": "Transmits command execution streams and administrative passwords entirely in cleartext, rendering perimeter nodes fully vulnerable to intercept-and-replay attacks.", "iso_rationale": "Direct violation of cryptographic policies governing privileged remote management access utilities."},
    '80': {"name": "HTTP", "alt": "HTTPS", "nist_rationale": "Lacks logical transit-layer encryption, enabling malicious data manipulation and eavesdropping via Man-in-the-Middle (MitM) positioning.", "iso_rationale": "Bypasses default network communication privacy baselines by failing to enforce web segment authentication mechanisms."},
    '110': {"name": "POP3", "alt": "POP3S", "nist_rationale": "Broadcasts mail retrieval authentication hashes in plaintext across routing perimeters, exposing executive mail domains to local session stealing.", "iso_rationale": "Breaches secure information transfer baselines by exposing operational messaging assets to plaintext interception."},
    '143': {"name": "IMAP", "alt": "IMAPS", "nist_rationale": "Transmits message collection transactions over unencrypted cleartext sockets, endangering authentication tokens at network demarcations.", "iso_rationale": "Violates corporate data access privacy rules by failing to utilize encrypted mail synchronization tunnels."},
    '161': {"name": "SNMPv1/v2c", "alt": "SNMPv3", "vuln": "Uses unencrypted cleartext 'community strings' for management signaling, allowing network context discovery or unauthorized infrastructure alterations."},
    '162': {"name": "SNMPv1/v2c Trap", "alt": "SNMPv3", "vuln": "Uses unencrypted cleartext 'community strings' for management signaling, allowing network context discovery or unauthorized infrastructure alterations."},
    '389': {"name": "LDAP", "alt": "LDAPS", "nist_rationale": "Passes directory queries and active directory credentials in raw readable strings, raising cross-zone compromise opportunities.", "iso_rationale": "Directly endangers identity infrastructure security by ignoring encryption requirements for directory services traffic."},
    '512': {"name": "rsh", "alt": "SSH", "nist_rationale": "Relies on legacy, easily spoofed IP address verification tables rather than authenticated cryptographic handshakes.", "iso_rationale": "Fails to meet identification and authentication controls by using completely unauthenticated legacy protocols."},
    '513': {"name": "rlogin", "alt": "SSH", "nist_rationale": "Relies on legacy, easily spoofed IP address verification tables rather than authenticated cryptographic handshakes.", "iso_rationale": "Fails to meet identification and authentication controls by using completely unauthenticated legacy protocols."},
    '514': {"name": "rexec", "alt": "SSH", "nist_rationale": "Relies on legacy, easily spoofed IP address verification tables rather than authenticated cryptographic handshakes.", "iso_rationale": "Fails to meet identification and authentication controls by using completely unauthenticated legacy protocols."}
}

def catch_dangerous_ports_and_crypto(rule):
    """
    FRAMEWORK: NIST SP 800-41 Rev. 1 & ISO 27001 (A.10.1.1 / A.13.2.1)
    TARGET: Flags unencrypted legacy protocols that leak information across boundaries.
    """
    dst_port = str(rule.get('dst_port', '')).strip()
    action = str(rule.get('action', '')).strip().lower()

    if action not in ['allow', 'accept', 'permit']:
        return None

    findings = []

    # 1. Standard Protocol Auditing with Compliance Narratives
    if dst_port in INSECURE_PORTS_METADATA:
        meta = INSECURE_PORTS_METADATA[dst_port]
        
        # TASK ACCOMPLISHED: Injecting NIST Framework Tag and explaining the exact violation mechanism
        findings.append({
            "severity": "High" if dst_port in ['23', '161', '162', '389'] else ("Critical" if dst_port in ['512', '513', '514'] else "Medium"),
            "tag": "NIST SP 800-41",
            "issue": "Insecure Protocol Permitted",
            "desc": f"Violation: Permitting unencrypted {meta['name']} traffic. Framework Conflict: This breaks standard control rules because it {meta['nist_rationale']} Remediation: Migrate perimeter services exclusively to secure {meta['alt']} configurations."
        })
        
        # TASK ACCOMPLISHED: Injecting ISO Framework Tag and explaining the explicit violation reason
        findings.append({
            "severity": "High" if dst_port in ['23', '161', '162', '389'] else ("Critical" if dst_port in ['512', '513', '514'] else "Medium"),
            "tag": "ISO 27001: A.14.1.2",
            "issue": "Cryptographic Control Defect",
            "desc": f"Violation: Transit encryption missing on port {dst_port}. Framework Conflict: This breaches secure engineering requirements because it demonstrates a {meta['iso_rationale']} Encryption blocks must protect sensitive exchange pathways."
        })

    # 2. Remote Desktop Targets
    elif dst_port == '3389':
        findings.append({
            "severity": "Critical",
            "tag": "NIST SP 800-41",
            "issue": "Exposed Remote Desktop (RDP)",
            "desc": "Violation: Direct RDP exposure. Framework Conflict: Exposing port 3389 breaks boundary protection principles since it is heavily targeted for credential brute-forcing and ransomware orchestration. Place behind a secure VPN gateway with Multi-Factor Authentication (MFA)."
        })
    elif dst_port in ['5900', '5901']:
        findings.append({
            "severity": "Critical",
            "tag": "NIST SP 800-41",
            "issue": "Exposed VNC Service",
            "desc": "Violation: Exposed unencrypted virtual network computing. Framework Conflict: Allows raw desktop viewing across unvetted networks, presenting an extreme risk of session takeover."
        })

    # 3. Perimeter Worm Targets
    elif dst_port in ['135', '137', '138', '139', '445']:
        findings.append({
            "severity": "Critical",
            "tag": "NIST SP 800-41",
            "issue": "Exposed NetBIOS/SMB Fabric",
            "desc": "Violation: Active file sharing protocol visible to public boundaries. Framework Conflict: Directly exposes network internal namespaces and file systems, creating a high risk of automated malware and lateral worm propagation across zones."
        })

    # 4. Database Isolation Targets
    elif dst_port in ['1433', '1434', '3306', '5432', '1521', '27017']:
        findings.append({
            "severity": "Critical",
            "tag": "NIST SP 800-41",
            "issue": "Direct External Database Exposure",
            "desc": f"Violation: Firewall rule exposes internal relational/NoSQL storage engine on port {dst_port}. Framework Conflict: Directly violates network defense-in-depth segmentation models. Core repositories should remain isolated from internet segments."
        })
        findings.append({
            "severity": "Critical",
            "tag": "ISO 27001: A.13.2.1",
            "issue": "Information Transfer Policy Breach",
            "desc": f"Violation: Database endpoints accessible across outer firewalls. Framework Conflict: Fails data control segregation baselines by failing to isolate persistent data tables within standalone secure zones."
        })

    return findings if findings else None


def catch_iso_shadow_rules(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.12.1.1 (Documented Operating Procedures)
    TARGET: Identifies dead, inactive rules causing rule-base bloat.
    """
    # TASK ACCOMPLISHED: Safely read attributes and ignore analysis completely if src_port is 'any'
    src_port = str(rule.get('src_port', '')).strip().lower()
    if src_port == 'any':
        return None

    # Handle numeric type extraction safely based on reader.py specifications
    hit_count = rule.get('hit_count')

    # TASK ACCOMPLISHED: Write logic to check if hit count == 0 and generate a robust compliance violation description
    if hit_count == 0:
        return [{
            "severity": "Low",
            "tag": "ISO 27001: A.12.1.1",
            "issue": "Inactive Shadow Rule Detected",
            "desc": "Violation: Redundant firewall policy entry registering 0 operational packet hits. Framework Conflict: Retaining unutilized rules creates policy base 'bloat', slows configuration processing times, and obscures active rules during incident responses. This indicates a failure to maintain standard system operations lifecycle reviews."
        }]
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
        return [{
            "severity": "High",
            "tag": "ISO 27001: A.9.1.2",
            "issue": "Overly Permissive Access Rule",
            "desc": "Violation: Full 'Any-to-Any' traffic permission. Framework Conflict: Bypasses network access segregation matrices and violates the Principle of Least Privilege. Access must be granted based on specific, justified business needs."
        }]
    return None


def catch_iso_missing_logs(rule):
    """
    FRAMEWORK: ISO 27001 Annex A.12.4.1 (Event Logging)
    TARGET: Ensures that critical traffic is being actively audited/logged.
    """
    action = str(rule.get('action', '')).strip().lower()

    if 'log' not in action and action in ['allow', 'accept', 'permit']:
        return [{
            "severity": "Low",
            "tag": "ISO 27001: A.12.4.1",
            "issue": "Missing Audit Trails",
            "desc": "Violation: Active allowance rule operates without an explicit log trace keyword. Framework Conflict: Breaks event logging principles. Independent audit logs must exist to track perimeter connection events for forensic analysis."
        }]
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
            return [{
                "severity": "Critical",
                "tag": "ISO 27001: A.13.1.1",
                "issue": "Exposed Management Access Control",
                "desc": f"Violation: Gateway management port {dst_port} open to generic source domains. Framework Conflict: Exposes device control planes to arbitrary internet scans, bypassing structural access segmentation controls. Enforce specialized source white-lists or an internal VPN access path."
            }]
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