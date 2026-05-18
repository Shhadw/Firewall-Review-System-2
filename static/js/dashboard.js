// static/js/dashboard.js

// --- Global State Variables ---
let globalRules = [];
let globalDecisions = {};
let globalScanFilename = 'scan';
let filterUnreviewed = false;
let sortSeverity = false;

document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();

    // --- Filter & Sort Button Listeners ---
    const filterBtn = document.querySelector('.filter-pill');
    const sortBtn = document.querySelector('.sort-pill');

    if (filterBtn) {
        filterBtn.addEventListener('click', () => {
            filterUnreviewed = !filterUnreviewed; // Toggle state
            // Make it blue when active
            filterBtn.style.borderColor = filterUnreviewed ? 'var(--accent)' : '';
            filterBtn.style.color = filterUnreviewed ? 'var(--accent)' : '';
            populateRuleTable(); // Redraw the table
        });
    }

    if (sortBtn) {
        sortBtn.addEventListener('click', () => {
            sortSeverity = !sortSeverity; // Toggle state
            // Make it blue when active
            sortBtn.style.borderColor = sortSeverity ? 'var(--accent)' : '';
            sortBtn.style.color = sortSeverity ? 'var(--accent)' : '';
            populateRuleTable(); // Redraw the table
        });
    }

    const exportBtn = document.querySelector('.export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportAuditLogs);
    }
});

async function fetchDashboardData() {
    const emptyState = document.getElementById('ui-empty-state');
    const dashboardContent = document.getElementById('ui-dashboard-content');

    try {
        const response = await fetch('/api/get_analysis_results');

        // 1. If no scan exists (404) or API fails, show the Empty State and stop.
        if (!response.ok) {
            if(emptyState) emptyState.style.display = 'flex';
            if(dashboardContent) dashboardContent.style.display = 'none';
            return;
        }

        const data = await response.json();

        // 2. If data is completely empty, also show Empty State.
        if (!data.rules || data.rules.length === 0) {
            if(emptyState) emptyState.style.display = 'flex';
            if(dashboardContent) dashboardContent.style.display = 'none';
            return;
        }

        // 3. We have data! Hide the Empty State and show the Dashboard content.
        if(emptyState) emptyState.style.display = 'none';
        if(dashboardContent) dashboardContent.style.display = 'flex';

        globalRules = data.rules || [];
        globalDecisions = data.decisions || {};

        // Update Top Stats
        document.getElementById('ui-total-rules').innerText = data.summary.total_rules || 0;
        document.getElementById('ui-critical-risk').innerText = data.summary.critical || 0;
        document.getElementById('ui-high-risk').innerText = data.summary.high || 0;
        document.getElementById('ui-medium-risk').innerText = data.summary.medium || 0;
        document.getElementById('ui-low-risk').innerText = data.summary.low || 0;

        // Update Danger Card (Now Dynamic)
        const statusCard = document.getElementById('ui-danger-card');
        const statusBadge = document.getElementById('ui-status-badge');

        if (statusCard && statusBadge) {
            statusCard.style.display = 'block';
            const filenameEl = document.getElementById('ui-filename');
            globalScanFilename = data.filename || 'scan';
            if (filenameEl) filenameEl.innerText = data.filename || "Uploaded_CSV";

            // Determine Status based on risks
            if (data.summary.critical > 0) {
                statusCard.style.background = 'var(--danger-bg)';
                statusCard.style.borderColor = 'var(--danger-bd)';
                statusBadge.style.background = 'var(--critical)';
                statusBadge.innerText = 'DANGER';
            } else if (data.summary.high > 0 || data.summary.medium > 0) {
                statusCard.style.background = '#2b2210'; // Dark Warning Orange
                statusCard.style.borderColor = '#8a651a';
                statusBadge.style.background = 'var(--medium)';
                statusBadge.innerText = 'WARNING';
            } else {
                statusCard.style.background = '#121c18'; // Dark Secure Green
                statusCard.style.borderColor = '#235c45';
                statusBadge.style.background = 'var(--low)';
                statusBadge.innerText = 'SECURE';
            }
        }

        // Extract unique tags and issues from Python findings
        const uniqueTags = new Set();
        const commonIssues = new Set();
        globalRules.forEach(rule => {
            if(rule.findings) {
                rule.findings.forEach(f => {
                    uniqueTags.add(f.tag);
                    commonIssues.add(f.desc);
                });
            }
        });

        // Inject Tags with Enterprise Framework Routing
        const tagsContainer = document.getElementById('ui-violation-tags');
        if (tagsContainer) {
            tagsContainer.innerHTML = Array.from(uniqueTags).map(tag => {
                let tagClass = "vtag-nist"; // Default

                if (tag.includes("ISO")) tagClass = "vtag-iso";
                else if (tag.includes("PCI")) tagClass = "vtag-pci";
                else if (tag.includes("CIS")) tagClass = "vtag-cis";
                else if (tag.includes("SOC")) tagClass = "vtag-soc2";
                else if (tag.includes("HIPAA")) tagClass = "vtag-hipaa";
                else if (tag.includes("COBIT")) tagClass = "vtag-cobit";
                else if (tag.includes("CSF")) tagClass = "vtag-nistcsf";

                return `<span class="vtag ${tagClass}">${tag}</span>`;
            }).join('');
        }

        // Inject Issues (limit to top 3 so it doesn't break UI)
        const issuesContainer = document.getElementById('ui-common-issues');
        if (issuesContainer) {
            if (commonIssues.size > 0) {
                issuesContainer.innerHTML = Array.from(commonIssues).slice(0, 3).map(issue => `<li>${issue}</li>`).join('');
            } else {
                // If completely secure, show a success message
                issuesContainer.innerHTML = `<li style="color: var(--low);">No significant vulnerabilities detected. Network posture is secure.</li>`;
            }
        }

        // Build Table and Update Progress
        populateRuleTable();
        updateReviewProgress();

    } catch (error) {
        console.error("Error fetching dashboard data:", error);
    }
}

// Handles the Button Clicks
async function makeDecision(ruleId, decisionAction) {
    try {
        await fetch('/decide', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId, decision: decisionAction })
        });

        // Save locally and update UI instantly without reloading the whole page
        globalDecisions[ruleId] = decisionAction;
        populateRuleTable();
        updateReviewProgress();

    } catch (error) {
        console.error("Failed to save decision", error);
    }
}

function updateReviewProgress() {
    let kept = 0;
    let removed = 0;
    const total = globalRules.length;

    Object.values(globalDecisions).forEach(dec => {
        if (dec === "Keep") kept++;
        if (dec === "Remove") removed++;
    });

    const pending = total - (kept + removed);
    const progressPercent = total === 0 ? 0 : ((kept + removed) / total) * 100;

    const elReviewedCount = document.getElementById('ui-reviewed-count');
    const elTotalProgress = document.getElementById('ui-total-progress');
    const elKeptCount = document.getElementById('ui-kept-count');
    const elRemovedCount = document.getElementById('ui-removed-count');
    const elPendingCount = document.getElementById('ui-pending-count');
    const elProgressFill = document.getElementById('ui-progress-fill');

    if (elReviewedCount) elReviewedCount.innerText = (kept + removed);
    if (elTotalProgress) elTotalProgress.innerText = total;
    if (elKeptCount) elKeptCount.innerText = kept;
    if (elRemovedCount) elRemovedCount.innerText = removed;
    if (elPendingCount) elPendingCount.innerText = pending;
    if (elProgressFill) elProgressFill.style.width = `${progressPercent}%`;
}

// Projects the finding to the bottom panel instead of expanding a row
function showFindings(ruleId) {
    const panelContainer = document.getElementById('ui-global-findings-panel');
    const rule = globalRules.find(r => r.rule_id === ruleId);

    // If the rule has no findings, hide the panel
    if (!rule || !rule.findings || rule.findings.length === 0) {
        panelContainer.style.display = "none";
        return;
    }

    const complianceText = getComplianceText(rule);
    const findingsHtml = rule.findings.map(finding => {
        const tagName = String(finding.tag || 'Compliance Finding');
        let tagClass = "vtag-nist";
        if (tagName.includes("ISO")) tagClass = "vtag-iso";
        else if (tagName.includes("PCI")) tagClass = "vtag-pci";
        else if (tagName.includes("CIS")) tagClass = "vtag-cis";
        else if (tagName.includes("SOC")) tagClass = "vtag-soc2";
        else if (tagName.includes("HIPAA")) tagClass = "vtag-hipaa";
        else if (tagName.includes("COBIT")) tagClass = "vtag-cobit";
        else if (tagName.includes("CSF")) tagClass = "vtag-nistcsf";

        return `
            <div class="finding-row">
                <span class="ftag ${tagClass}">${tagName}</span>
                <div class="finding-meta">
                    <div class="finding-desc">${finding.desc || 'No description available.'}</div>
                    <div class="finding-severity">Severity: ${finding.severity || 'UNKNOWN'}</div>
                </div>
            </div>
        `;
    }).join('');

    // Inject the HTML into our dedicated box at the bottom
    panelContainer.innerHTML = `
        <div class="findings-panel" style="border-top: 1px solid var(--border2); border-radius: 8px;">
            <div class="findings-title" style="display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 1L1 14h14L8 1z"/><path d="M8 6v4M8 12v.5"/></svg>
                    Compliance Findings – Rule ${rule.rule_id}
                </div>
                <button onclick="document.getElementById('ui-global-findings-panel').style.display='none'" style="background: none; border: none; color: var(--muted); cursor: pointer; font-size: 20px; line-height: 1;">&times;</button>
            </div>
            <div class="findings-body">
                <div class="findings-left">
                    <div class="findings-summary">
                        <div class="summary-label">Compliance:</div>
                        <div class="summary-text">${complianceText}</div>
                    </div>
                    ${findingsHtml}
                </div>
                <div class="findings-right">
                    <div class="rec-label">
                        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="8" cy="8" r="6"/><path d="M8 5v3l2 2"/></svg>
                        Recommendation
                    </div>
                    <p class="rec-text">Review and modify this rule to ensure compliance with the listed controls and tags. Consider implementing strict IP whitelisting and rule refinement.</p>
                </div>
            </div>
        </div>
    `;

    // Reveal the modal overlay
    panelContainer.style.display = "grid";
    panelContainer.style.placeItems = "center";
    panelContainer.style.padding = "32px";

    // Close when clicking outside the modal content
    panelContainer.onclick = (event) => {
        if (event.target === panelContainer) {
            panelContainer.style.display = 'none';
        }
    };
}

function getDisplayedRules() {
    let rulesToDisplay = [...globalRules];

    if (filterUnreviewed) {
        rulesToDisplay = rulesToDisplay.filter(rule => !globalDecisions[rule.rule_id]);
    }

    if (sortSeverity) {
        const severityWeights = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "OK": 0 };
        rulesToDisplay.sort((a, b) => {
            const weightA = severityWeights[a.status] || 0;
            const weightB = severityWeights[b.status] || 0;
            return weightB - weightA;
        });
    }

    return rulesToDisplay;
}

function csvEscape(value) {
    if (value === null || value === undefined) return '';
    const text = String(value);
    if (/[",\r\n]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
}

function getComplianceText(rule) {
    if (!rule.findings || rule.findings.length === 0) {
        return 'None';
    }
    return rule.findings.map(f => f.tag || f.desc || 'Compliance Finding').join('; ');
}

function exportAuditLogs() {
    const exportRows = getDisplayedRules();
    if (!exportRows.length) {
        alert('No rules available to export.');
        return;
    }

    const headers = ['Rule ID', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Hits', 'Status', 'Compliance', 'Decision'];
    const csvLines = [headers.map(csvEscape).join(',')];

    exportRows.forEach(rule => {
        const row = [
            rule.rule_id,
            rule.src_ip,
            rule.dst_ip,
            rule.dst_port,
            rule.protocol,
            rule.hit_count,
            rule.status,
            getComplianceText(rule),
            globalDecisions[rule.rule_id] || 'Pending'
        ];
        csvLines.push(row.map(csvEscape).join(','));
    });

    const scanBase = String(globalScanFilename).replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `${scanBase}_${new Date().toISOString().slice(0,10)}.csv`;
    const csvContent = csvLines.join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');

    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Builds the table dynamically
function populateRuleTable() {
    const tableBody = document.getElementById('ui-rule-table-body');
    if (!tableBody) return;
    tableBody.innerHTML = '';

    if (globalRules.length === 0) return;

    // --- Filter & Sort Logic ---
    let rulesToDisplay = [...globalRules]; // Clone array to avoid mutating original

    // Filter: Show ONLY rules that don't have a decision yet
    if (filterUnreviewed) {
        rulesToDisplay = rulesToDisplay.filter(rule => !globalDecisions[rule.rule_id]);
    }

    // Sort: Highest severity first
    if (sortSeverity) {
        const severityWeights = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "OK": 0 };
        rulesToDisplay.sort((a, b) => {
            const weightA = severityWeights[a.status] || 0;
            const weightB = severityWeights[b.status] || 0;
            return weightB - weightA;
        });
    }

    // --- Render the Filtered/Sorted Rules ---
    rulesToDisplay.forEach(rule => {
        const row = document.createElement('tr');
        const activeDecision = globalDecisions[rule.rule_id];

        const keepText = activeDecision === "Keep" ? "Kept" : "Keep";
        const remText = activeDecision === "Remove" ? "Removed" : "Remove";

        const keepOpacity = activeDecision === "Keep" ? "1" : (activeDecision === "Remove" ? "0.2" : "0.8");
        const remOpacity = activeDecision === "Remove" ? "1" : (activeDecision === "Keep" ? "0.2" : "0.8");
        const keepBorder = activeDecision === "Keep" ? "border: 1px solid var(--low);" : "";
        const remBorder = activeDecision === "Remove" ? "border: 1px solid var(--critical);" : "";

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

            <td><button class="comp-tag-btn" onclick="showFindings('${rule.rule_id}')">VIEW TAG <span class="arrow-dn">↓</span></button></td>

            <td>
                <div class="decision-cell">
                    <button class="btn-keep" style="opacity: ${keepOpacity}; ${keepBorder}" onclick="makeDecision('${rule.rule_id}', 'Keep')">${keepText}</button>
                    <button class="btn-remove" style="opacity: ${remOpacity}; ${remBorder}" onclick="makeDecision('${rule.rule_id}', 'Remove')">${remText}</button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);
    });
}