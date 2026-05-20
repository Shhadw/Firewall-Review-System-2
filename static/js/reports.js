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

    // --- DYNAMIC BADGE & CARD BORDER LOGIC ---
    const rs = reportData.report_summary || {};
    const pyStatus = (rs.status || '').toUpperCase();
    const badgeEl = document.getElementById('ui-report-status-badge');
    const badgeTextEl = document.getElementById('ui-report-status-text');
    const cardEl = document.querySelector('.report-card');

    if (badgeEl && badgeTextEl && cardEl) {
        if (pyStatus === 'DANGER' || critical > 0) {
            badgeEl.style.background = 'rgba(232, 64, 74, 0.15)';
            badgeEl.style.borderColor = 'rgba(232, 64, 74, 0.40)';
            badgeEl.style.color = 'var(--critical)';
            badgeTextEl.innerText = 'DANGER';

            // Set card border to red
            cardEl.style.borderColor = 'var(--critical)';

        } else if (pyStatus === 'WARNING' || high > 0 || medium > 0) {
            badgeEl.style.background = 'rgba(240, 168, 50, 0.12)';
            badgeEl.style.borderColor = 'rgba(240, 168, 50, 0.40)';
            badgeEl.style.color = 'var(--high)';
            badgeTextEl.innerText = 'WARNING';

            // Set card border to yellow/orange
            cardEl.style.borderColor = 'var(--high)';

        } else if (pyStatus === 'CAUTION') {
            badgeEl.style.background = 'rgba(184, 134, 11, 0.12)';
            badgeEl.style.borderColor = 'rgba(184, 134, 11, 0.40)';
            badgeEl.style.color = '#b8860b';
            badgeTextEl.innerText = 'CAUTION';

            // Set card border to caution color
            cardEl.style.borderColor = '#b8860b';

        } else {
            badgeEl.style.background = 'rgba(76, 175, 136, 0.12)';
            badgeEl.style.borderColor = 'rgba(76, 175, 136, 0.40)';
            badgeEl.style.color = 'var(--low)';
            badgeTextEl.innerText = 'SECURE';

            // Set card border to green
            cardEl.style.borderColor = 'var(--low)';
        }
    }

    // Avg severity score from generate_summary
    const avgEl = document.getElementById('ui-avg-score');
    if (avgEl) {
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