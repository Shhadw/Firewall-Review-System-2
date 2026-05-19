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
        globalScanFilename = data.filename || 'scan';
        // data.decisions is already pre-filtered to this file by the server
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
        const rs = data.report_summary || {};

        if (statusCard && statusBadge) {
            statusCard.style.display = 'block';
            const filenameEl = document.getElementById('ui-filename');
            if (filenameEl) filenameEl.innerText = globalScanFilename;

            // Use Python-computed status (NIST 800-30 worst-case-wins)
            const pyStatus = (rs.status || '').toUpperCase();
            if (pyStatus === 'DANGER' || data.summary.critical > 0) {
                statusCard.style.background = 'var(--danger-bg)';
                statusCard.style.borderColor = 'var(--danger-bd)';
                statusBadge.style.background = 'var(--critical)';
                statusBadge.innerText = 'DANGER';
            } else if (pyStatus === 'WARNING' || data.summary.high > 0 || data.summary.medium > 0) {
                statusCard.style.background = '#2b2210';
                statusCard.style.borderColor = '#8a651a';
                statusBadge.style.background = 'var(--medium)';
                statusBadge.innerText = 'WARNING';
            } else if (pyStatus === 'CAUTION') {
                statusCard.style.background = '#241f0a';
                statusCard.style.borderColor = '#6b5c1a';
                statusBadge.style.background = '#b8860b';
                statusBadge.innerText = 'CAUTION';
            } else {
                statusCard.style.background = '#121c18';
                statusCard.style.borderColor = '#235c45';
                statusBadge.style.background = 'var(--low)';
                statusBadge.innerText = 'SECURE';
            }

            // Avg severity score — colour by value
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

            // Rules needing action count
            const actionEl = document.getElementById('ui-action-count');
            if (actionEl) {
                const actionRules = rs.rule_needing_action || [];
                actionEl.innerText = actionRules.length;
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
            body: JSON.stringify({
                rule_id: ruleId,
                decision: decisionAction,
                filename: globalScanFilename   // ← scope the save to this file
            })
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

function showFindings(ruleId) {
    const panelContainer = document.getElementById('ui-global-findings-panel');
    const rule = globalRules.find(r => r.rule_id === ruleId);

    // 1. Safety check
    if (!rule || !rule.findings || rule.findings.length === 0) {
        if (panelContainer) panelContainer.style.display = "none";
        return;
    }

    const complianceText = getComplianceText ? getComplianceText(rule) : "N/A";

    // 2. Generate the rows and identify the primary finding for the sidebar
    const firstFinding = rule.findings[0];
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
            <div class="finding-row" style="margin-bottom: 12px; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 4px;">
                <span class="ftag ${tagClass}">${tagName}</span>
                <div class="finding-meta">
                    <div class="finding-desc" style="font-size: 0.9em; margin-top: 5px;">${finding.desc || 'No description available.'}</div>
                    <div class="finding-severity" style="font-size: 0.8em; color: var(--muted);">Severity: ${finding.severity || 'UNKNOWN'}</div>
                </div>
            </div>
        `;
    }).join('');

    // 3. Set the HTML (Replaced undefined 'f' with 'firstFinding')
    panelContainer.innerHTML = `
    <div class="findings-panel" style="
        background-color: #0d1117; /* Solid Dark Background */
        border: 1px solid #30363d; 
        border-radius: 12px; 
        max-width: 900px; 
        width: 95%; 
        color: #c9d1d9;
        box-shadow: 0 10px 40px rgba(0,0,0,0.5); /* Adds depth */
        overflow: hidden;
    ">
        <!-- Header -->
        <div class="findings-header" style="padding: 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d;">
            <div style="display: flex; align-items: center; gap: 10px; font-weight: 600; color: #58a6ff;">
                <span style="color: #f85149;">⚠</span> 
                Compliance Findings – Rule ${rule.rule_id}
            </div>
            <button onclick="document.getElementById('ui-global-findings-panel').style.display='none'" style="background: none; border: none; color: #8b949e; cursor: pointer; font-size: 24px;">&times;</button>
        </div>

        <div class="findings-body" style="display: flex; padding: 24px; gap: 24px; background: #0d1117;">
            <!-- Left Side: Findings -->
            <div class="findings-left" style="flex: 1.5;">
                <div style="margin-bottom: 20px;">
                    <div style="color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Overall Compliance:</div>
                    <div style="font-weight: 700; color: #f0f6fc; font-size: 1.1em;">${complianceText}</div>
                </div>
                
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    ${findingsHtml}
                </div>
            </div>

            <!-- Right Side: Recommendation -->
            <div class="findings-right" style="flex: 1; padding: 24px; background: rgba(56, 139, 253, 0.05); border-radius: 8px; border: 1px solid rgba(56, 139, 253, 0.15); height: fit-content;">
                <div style="display: flex; align-items: center; gap: 8px; color: #3fb950; font-weight: 600; margin-bottom: 12px;">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="7"/><path d="M8 4v4l2 2"/></svg>
                    RECOMMENDATION
                </div>
                <p style="font-size: 0.9em; line-height: 1.6; color: #8b949e;">
                    Review and modify this rule to ensure compliance with <strong>${rule.findings[0].tag}</strong> protocols. Consider implementing strict IP whitelisting and rule refinement.
                </p>
            </div>
        </div>
    </div>
`;

    // 4. Reveal the modal
    panelContainer.style.display = "grid";
    panelContainer.style.position = "fixed";
    panelContainer.style.top = "0";
    panelContainer.style.left = "0";
    panelContainer.style.width = "100%";
    panelContainer.style.height = "100%";
    panelContainer.style.zIndex = "1000";
    panelContainer.style.backgroundColor = "rgba(0,0,0,0.8)";
    panelContainer.style.placeItems = "center";

    // Close when clicking background
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