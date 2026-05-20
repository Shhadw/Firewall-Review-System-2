# for cvss
severity_scores = {
    "low":      3.9,
    "medium":   6.9,
    "high":     8.9,
    "critical": 10.0,
}

# for determining system status
severity_rank = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

def generate_summary(findings_list):
    total_risks = len(findings_list)
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    issue_count = {}
    action_items = []

    worst_rank = 0
    total_score = 0.0

    for finding in findings_list:
        severity = finding.get("severity", "").lower()
        issue = finding.get("issue", "Unknown Issue")
        rule_id = finding.get("rule_id", "Unknown")

        if severity in severity_count:
            severity_count[severity] += 1

        total_score += severity_scores.get(severity, 0.0)

        issue_count[issue] = issue_count.get(issue, 0) + 1

        if severity in ["high", "critical"]:
            if rule_id not in action_items:
                action_items.append(rule_id)

        rank = severity_rank.get(severity, 0)
        if rank > worst_rank:
            worst_rank = rank

    # Determine system status using a hybrid model:
    # 1. High Water Mark (NIST 800-30 Task 2-6) - worst-case-wins
    # 2. Risk Aggregation / Vulnerability Chaining thresholds
    
    if worst_rank >= severity_rank["critical"]:
        # 1 or more Critical instantly triggers DANGER
        system_status = "DANGER"
        
    elif worst_rank >= severity_rank["high"] or severity_count["medium"] > 5:
        # 1 High OR an aggregation of 3+ Mediums triggers WARNING
        system_status = "WARNING"
        
    elif worst_rank >= severity_rank["medium"] or severity_count["low"] > 5:
        # 1 Medium OR an aggregation of 3+ Lows triggers CAUTION
        system_status = "CAUTION"
        
    else:
        # If no severe risks and fewer than 3 lows are found
        system_status = "SECURE"

    # CVSS-based scoring
    if total_risks > 0:
        average_score = round(total_score / total_risks, 2)
    else:
        average_score = 0.0

    return {
        'total_risks': total_risks,
        'status': system_status,
        'average_severity_score': average_score, # new return value
        'severity_count': severity_count,
        'common_issues': issue_count,
        'rule_needing_action': action_items
    }