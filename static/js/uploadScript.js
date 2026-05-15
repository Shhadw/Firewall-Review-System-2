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
    elements.display.innerHTML = `Selected: <strong>${name}</strong>`;
    elements.zone.classList.add('file-selected');
};

// 3. Drag & Drop Logic: Combined listeners using event.type
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(name => {
    elements.zone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();

        // Toggle highlight class
        const isHover = ['dragenter', 'dragover'].includes(name);
        elements.zone.classList.toggle('dragover', isHover);

        // Handle file drop
        if (name === 'drop' && e.dataTransfer.files.length) {
            elements.input.files = e.dataTransfer.files;
            updateUI(e.dataTransfer.files[0].name);
        }
    });
});

// 4. Manual Selection
elements.input.onchange = () => elements.input.files[0] && updateUI(elements.input.files[0].name);

// 5. Submit Logic
elements.form.onsubmit = async (e) => {
    e.preventDefault();
    const file = elements.input.files[0];
    if (!file) return;

    // Reset Status UI
    elements.status.className = "status-box";
    elements.msg.innerText = "Analyzing firewall rules...";

    try {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("/upload", { method: "POST", body: formData });
        if (!response.ok) throw new Error();

        elements.status.classList.add("success");
        elements.msg.innerText = "Analysis Complete! Redirecting...";
        setTimeout(() => window.location.href = "/", 1500);

    } catch (err) {
        elements.status.classList.add("error");
        elements.msg.innerText = "Could not connect to the backend server.";
    }
};