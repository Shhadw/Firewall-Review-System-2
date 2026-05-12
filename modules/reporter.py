def generate_summary(findings_list):
    total_risks = len(findings_list)
    # FIX: Corrected spelling from 'critial' to 'critical'
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    issue_count = {}
    action_items = []
    
    for finding in findings_list:
        severity = finding.get("severity", "").lower()
        issue = finding.get("issue", "Unknown Issue")
        rule_id = finding.get("rule_id", "Unknown")
        
        if severity in severity_count:
            severity_count[severity] += 1

        issue_count[issue] = issue_count.get(issue, 0) + 1

        if severity in ["high", "critical"]:
            if rule_id not in action_items:
                action_items.append(rule_id)
            
    # FIX: Corrected spelling here as well
    high_critical_total = severity_count["high"] + severity_count["critical"]

    if high_critical_total > 0:
        system_status = "DANGER"
    elif severity_count["medium"] > 0:
        system_status = "WARNING"
    else:
        system_status = "SECURE"

    return {
        'total_risks': total_risks,
        'status': system_status,
        'severity_count': severity_count,
        'common_issues': issue_count,
        'rule_needing_action': action_items
    }