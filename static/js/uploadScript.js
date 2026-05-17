// 1. Global Window Fix: Prevent browser from opening files dropped outside the zone
['dragover', 'drop'].forEach(ev => window.addEventListener(ev, e => e.preventDefault()));

const elements = {
    form: document.getElementById("uploadForm"),
    zone: document.getElementById("dropZone"),
    input: document.getElementById("csvFile"),
    display: document.getElementById("fileName"),
    status: document.getElementById("status"),
    msg: document.getElementById("statusMessage")
};

// 2. Helper: Unified UI Update
const updateUI = (name) => {
    if (elements.display && elements.zone) {
        elements.display.innerHTML = `Selected: <strong>${name}</strong>`;
        elements.zone.classList.add('file-selected');
    }
};

// ==========================================
// TASK 1: UPLOAD CSV LOGIC (Page-Safe Wrapper)
// ==========================================
// This 'if' block ensures this code ONLY runs if we are on the upload page (index.html)
if (elements.form) {

    // 3. Drag & Drop Logic: Combined listeners using event.type
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(name => {
        if (elements.zone) {
            elements.zone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();

                // Toggle highlight class
                const isHover = ['dragenter', 'dragover'].includes(name);
                elements.zone.classList.toggle('dragover', isHover);

                // Handle file drop
                if (name === 'drop' && e.dataTransfer.files.length && elements.input) {
                    elements.input.files = e.dataTransfer.files;
                    updateUI(e.dataTransfer.files[0].name);
                }
            });
        }
    });

    // 4. Manual Selection
    if (elements.input) {
        elements.input.onchange = () => elements.input.files[0] && updateUI(elements.input.files[0].name);
    }

    // 5. Submit Logic
    elements.form.onsubmit = async (e) => {
        e.preventDefault();
        const file = elements.input ? elements.input.files[0] : null;
        if (!file) return;

        // Reset Status UI
        if (elements.status && elements.msg) {
            elements.status.className = "status-box";
            elements.msg.innerText = "Analyzing firewall rules...";
        }

        try {
            const formData = new FormData();
            formData.append("file", file);

            const response = await fetch("/upload", { method: "POST", body: formData });
            if (!response.ok) throw new Error();

            if (elements.status && elements.msg) {
                elements.status.classList.add("success");
                elements.msg.innerText = "Analysis Complete! Redirecting...";
            }
            setTimeout(() => window.location.href = "/", 1500);

        } catch (err) {
            if (elements.status && elements.msg) {
                elements.status.classList.add("error");
                elements.msg.innerText = "Could not connect to the backend server.";
            }
        }
    };
}

// ==========================================
// TASK 5: LIVE RESULTS INTERACTIONS LOGIC
// ==========================================
// This sits completely outside the 'if' block so it's globally available to results.html
let keptCount = 0;
let removedCount = 0;

async function handleAction(buttonElement, action) {
    // Locate row metadata
    const row = buttonElement.closest('tr');
    const ruleId = row.getAttribute('data-rule-id');
    const buttonGroup = buttonElement.closest('.action-buttons');

    // UI Updates Execution
    if (action === 'keep') {
        keptCount++;
        document.getElementById('keptCount').innerText = keptCount;
        buttonGroup.innerHTML = `<span class="btn-status-active kept-state">✓ Kept</span>`;
    } else if (action === 'remove') {
        removedCount++;
        document.getElementById('removedCount').innerText = removedCount;
        buttonGroup.innerHTML = `<span class="btn-status-active removed-state">✗ Removed</span>`;
    }

    // Trigger row visual fading
    row.classList.add('row-faded');

    // Network Sync (Dar & Nate's backend endpoint)
    try {
        const response = await fetch('http://127.0.0.1:5000/api/rule-action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId, action: action })
        });
        if (!response.ok) console.warn("Session tracking sync failed on backend.");
    } catch (error) {
        console.error("Network error communicating action metadata:", error);
    }
}
