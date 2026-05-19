// static/js/reports.js

document.addEventListener('DOMContentLoaded', () => {
    const selectEl = document.getElementById('ui-report-select');
    const loadBtn = document.getElementById('ui-load-btn');

    if (!RAW_HISTORY_DATA || RAW_HISTORY_DATA.length === 0) {
        selectEl.innerHTML = '<option value="">No past reports available</option>';
        selectEl.disabled = true;
        loadBtn.style.opacity = '0.5';
        loadBtn.style.pointerEvents = 'none';

        document.getElementById('ui-action-rules-list').innerHTML =
            '<div style="padding: 10px; color: var(--muted);">Run a New Scan to generate reports.</div>';
        return;
    }

    selectEl.innerHTML = '';
    RAW_HISTORY_DATA.forEach((report, index) => {
        const option = document.createElement('option');
        option.value = index;
        option.innerText = report.filename;
        selectEl.appendChild(option);
    });

    // Load first report automatically
    loadReportIntoUI(0);

    selectEl.addEventListener('change', (event) => {
        loadReportIntoUI(event.target.value);
    });

    // Wire up the "Load to Dashboard" button
    loadBtn.addEventListener('click', async () => {
        const selectedIndex = selectEl.value;
        const filenameToLoad = RAW_HISTORY_DATA[selectedIndex].filename;

        try {
            const response = await fetch('/api/load_report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filenameToLoad })
            });

            if (response.ok) {
                window.location.href = '/dashboard';
            } else {
                console.error("Failed to load report");
            }
        } catch (error) {
            console.error("API Connection Error", error);
        }
    });
});


function loadReportIntoUI(index) {
    const reportData = RAW_HISTORY_DATA[index];
    if (!reportData) return;

    document.getElementById('ui-report-filename').innerText = reportData.filename;

    const summary = reportData.summary || {};
    const critical = summary.critical || 0;
    const high     = summary.high     || 0;
    const medium   = summary.medium   || 0;
    const low      = summary.low      || 0;
    const totalRisks = critical + high + medium + low;

    document.getElementById('ui-total-risks').innerText   = `Total Risks: ${totalRisks}`;
    document.getElementById('ui-risk-critical').innerText = critical;
    document.getElementById('ui-risk-high').innerText     = high;
    document.getElementById('ui-risk-medium').innerText   = medium;
    document.getElementById('ui-risk-low').innerText      = low;

    // Avg severity score from generate_summary
    const avgEl = document.getElementById('ui-avg-score');
    if (avgEl) {
        const rs = reportData.report_summary || {};
        const avg = rs.average_severity_score != null ? rs.average_severity_score : null;
        if (avg !== null) {
            avgEl.innerText = avg.toFixed(2);
            avgEl.style.color = avg >= 9 ? 'var(--critical)' : avg >= 7 ? 'var(--high)' : avg >= 4 ? 'var(--medium)' : 'var(--low)';
        } else {
            avgEl.innerText = 'N/A';
        }
    }

    const rulesListEl = document.getElementById('ui-action-rules-list');
    rulesListEl.innerHTML = '';

    const allRules = reportData.rules || [];

    // Decisions are namespaced by filename: { filename: { rule_id: decision } }
    // Pull only the decisions that belong to this specific file.
    const fileDecisions = GLOBAL_DECISIONS[reportData.filename] || {};

    // Count decisions across every rule for this file only
    let keptCount    = 0;
    let removedCount = 0;
    let pendingCount = 0;

    allRules.forEach(rule => {
        const decision = fileDecisions[rule.rule_id];
        if (decision === "Keep")        keptCount++;
        else if (decision === "Remove") removedCount++;
        else                            pendingCount++;
    });

    // For the visible list: show rules that have a decision OR are high-severity
    const displayRules = allRules.filter(rule => {
        const decision = fileDecisions[rule.rule_id];
        const isActioned     = decision === "Keep" || decision === "Remove";
        const isHighSeverity = rule.status === 'CRITICAL' || rule.status === 'HIGH';
        return isActioned || isHighSeverity;
    });

    if (displayRules.length === 0) {
        rulesListEl.innerHTML =
            '<div style="padding: 10px; color: var(--muted);">No immediate actions required for this file.</div>';
    } else {
        displayRules.forEach(rule => {
            const decision = fileDecisions[rule.rule_id];

            let badgeClass = "rcb-pending";
            let badgeText  = "Pending";

            if (decision === "Keep") {
                badgeClass = "rcb-kept";
                badgeText  = "Kept";
            } else if (decision === "Remove") {
                badgeClass = "rcb-removed";
                badgeText  = "Removed";
            }

            const row = document.createElement('div');
            row.className = 'rc-rule-row';
            row.innerHTML = `
                <span class="rc-rule-id">${rule.rule_id}</span>
                <span class="rc-status-badge ${badgeClass}">${badgeText}</span>
            `;
            rulesListEl.appendChild(row);
        });
    }

    // Push the accurate counts into the summary bar
    document.getElementById('ui-rules-kept').innerText    = keptCount;
    document.getElementById('ui-rules-removed').innerText = removedCount;
    document.getElementById('ui-rules-pending').innerText = pendingCount;
}