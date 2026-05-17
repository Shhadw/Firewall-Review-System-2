document.addEventListener('DOMContentLoaded', () => {
    const selectEl = document.getElementById('ui-report-select');

    if (!RAW_HISTORY_DATA || RAW_HISTORY_DATA.length === 0) {
        selectEl.innerHTML = '<option value="">No past reports available</option>';
        selectEl.disabled = true; // Lock the dropdown

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

    loadReportIntoUI(0);

    selectEl.addEventListener('change', (event) => {
        const selectedIndex = event.target.value;
        loadReportIntoUI(selectedIndex);
    });
});


function loadReportIntoUI(index) {
    const reportData = RAW_HISTORY_DATA[index];
    if (!reportData) return;

    document.getElementById('ui-report-filename').innerText = reportData.filename;

    const summary = reportData.summary || {};
    const critical = summary.critical || 0;
    const high = summary.high || 0;
    const medium = summary.medium || 0;
    const low = summary.low || 0;
    const totalRisks = critical + high + medium + low;

    document.getElementById('ui-total-risks').innerText = `Total Risks: ${totalRisks}`;
    document.getElementById('ui-risk-critical').innerText = critical;
    document.getElementById('ui-risk-high').innerText = high;
    document.getElementById('ui-risk-medium').innerText = medium;
    document.getElementById('ui-risk-low').innerText = low;

    document.getElementById('ui-rules-kept').innerText = "0";
    document.getElementById('ui-rules-removed').innerText = "0";
    document.getElementById('ui-rules-pending').innerText = summary.total_rules || 0;

    const rulesListEl = document.getElementById('ui-action-rules-list');
    rulesListEl.innerHTML = ''; // Clear old rows

    const actionRules = (reportData.rules || []).filter(r => r.status === 'CRITICAL' || r.status === 'HIGH');

    if (actionRules.length === 0) {
        rulesListEl.innerHTML = '<div style="padding: 10px; color: var(--muted);">No immediate actions required for this file.</div>';
    } else {
        actionRules.forEach(rule => {
            const row = document.createElement('div');
            row.className = 'rc-rule-row';
            row.innerHTML = `
                <span class="rc-rule-id">${rule.rule_id}</span>
                <span class="rc-status-badge rcb-pending">Pending</span>
            `;
            rulesListEl.appendChild(row);
        });
    }
}