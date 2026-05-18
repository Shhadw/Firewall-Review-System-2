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

    const rulesListEl = document.getElementById('ui-action-rules-list');
    rulesListEl.innerHTML = '';

    // ── FIX 1 ────────────────────────────────────────────────────────
    // Use ALL rules — not just CRITICAL/HIGH — so every Keep/Remove
    // decision made on the dashboard is counted in the summary bar.
    // Rules with status MEDIUM/LOW that were acted on were previously
    // silently excluded, making Kept always show 0.
    // ─────────────────────────────────────────────────────────────────
    const allRules = reportData.rules || [];

    // ── FIX 2 ────────────────────────────────────────────────────────
    // Count decisions across EVERY rule, not just the displayed subset.
    // This ensures Rules Kept + Rules Removed + Pending = total rules,
    // matching the dashboard progress card exactly.
    // ─────────────────────────────────────────────────────────────────
    let keptCount    = 0;
    let removedCount = 0;
    let pendingCount = 0;

    allRules.forEach(rule => {
        const decision = GLOBAL_DECISIONS[rule.rule_id];
        if (decision === "Keep")        keptCount++;
        else if (decision === "Remove") removedCount++;
        else                            pendingCount++;
    });

    // For the visible list: show rules that have a decision OR are high-severity
    const displayRules = allRules.filter(rule => {
        const decision = GLOBAL_DECISIONS[rule.rule_id];
        const isActioned     = decision === "Keep" || decision === "Remove";
        const isHighSeverity = rule.status === 'CRITICAL' || rule.status === 'HIGH';
        return isActioned || isHighSeverity;
    });

    if (displayRules.length === 0) {
        rulesListEl.innerHTML =
            '<div style="padding: 10px; color: var(--muted);">No immediate actions required for this file.</div>';
    } else {
        displayRules.forEach(rule => {
            const decision = GLOBAL_DECISIONS[rule.rule_id];

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