// static/js/dashboard.js
document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();
});

async function fetchDashboardData() {
    try {
        const response = await fetch('/api/get_analysis_results');
        if (!response.ok) return; // Stop if no scan yet

        const data = await response.json();

        // Inject the summary numbers
        document.getElementById('ui-total-rules').innerText = data.summary.total_rules;
        document.getElementById('ui-critical-risk').innerText = data.summary.critical;
        document.getElementById('ui-high-risk').innerText = data.summary.high;
        document.getElementById('ui-medium-risk').innerText = data.summary.medium;
        document.getElementById('ui-low-risk').innerText = data.summary.low;

        // Show the Danger Card and file name
        document.getElementById('ui-danger-card').style.display = 'block';
        document.getElementById('ui-filename').innerText = data.filename || "Uploaded_CSV";

        populateRuleTable(data.rules);

    } catch (error) {
        console.error("Error fetching dashboard data:", error);
    }
}

function populateRuleTable(rulesArray) {
    const tableBody = document.getElementById('ui-rule-table-body');
    tableBody.innerHTML = '';

    if (!rulesArray || rulesArray.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 20px; color: var(--muted);">No rules found in scan.</td></tr>';
        return;
    }

    rulesArray.forEach(rule => {
        const row = document.createElement('tr');

        let hitsDisplay = `<span class="hits-val">${rule.hit_count}</span>`;
        if (rule.hit_count === 0) {
            hitsDisplay = `<div class="hits-zero"><span>0</span><div class="warn-icon">⚠</div></div>`;
        }

        row.innerHTML = `
            <td><a class="rule-id-link" href="#">${rule.rule_id}</a></td>
            <td><span class="${rule.src_ip === 'any' ? 'ip-any' : 'ip-val'}">${rule.src_ip}</span></td>
            <td><span class="ip-val">${rule.dst_ip}</span></td>
            <td><span class="port-val">${rule.dst_port}</span></td>
            <td><span class="proto-val">${rule.protocol}</span></td>
            <td>${hitsDisplay}</td>
            <td><span class="status-badge status-${rule.status.toLowerCase()}">${rule.status}</span></td>
            <td><button class="comp-tag-btn">VIEW TAG <span class="arrow-dn">↓</span></button></td>
            <td>
                <div class="decision-cell">
                    <button class="btn-keep">Keep</button>
                    <button class="btn-remove">Remove</button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);
    });
}