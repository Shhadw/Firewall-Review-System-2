// static/js/uploadScript.js
const uploadForm = document.getElementById("uploadForm");
const statusBox = document.getElementById("status");
const statusMsg = document.getElementById("statusMessage");
const analyzeBtn = document.getElementById("analyzeBtn");
const rulesFileInput = document.getElementById("rulesFile");
const logsFileInput = document.getElementById("logsFile");

function updateAnalyzeButtonState() {
  const rulesSelected = rulesFileInput.files.length > 0;
  const logsSelected = logsFileInput.files.length > 0;
  analyzeBtn.disabled = !(rulesSelected && logsSelected);
}

rulesFileInput.addEventListener("change", () => {
  document.getElementById("rulesFileName").innerText = rulesFileInput.files[0]?.name || "Drop firewall rules CSV here or click to browse";
  updateAnalyzeButtonState();
});

logsFileInput.addEventListener("change", () => {
  document.getElementById("logsFileName").innerText = logsFileInput.files[0]?.name || "Drop firewall logs CSV here or click to browse (optional)";
  updateAnalyzeButtonState();
});

updateAnalyzeButtonState();

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const rulesFile = rulesFileInput.files[0];
  const logsFile = logsFileInput.files[0];

  if (!rulesFile) {
    statusBox.className = "status-box error";
    statusMsg.innerText = "Please select a firewall rules (.csv) before analyzing.";
    statusBox.classList.remove("hidden");
    return;
  }

 if (!logsFile) {
    statusBox.className = "status-box error";
    statusMsg.innerText = "Please select a firewall logs (.log) file before analyzing.";
    statusBox.classList.remove("hidden");
    return;
  }

  const formData = new FormData();
  formData.append("rules_file", rulesFile);
  formData.append("logs_file", logsFile);


  // 1. Show the loading state
  statusBox.className = "status-box";
  statusMsg.innerText = "Analyzing your firewall rules against ISO/NIST standards...";
  statusBox.classList.remove("hidden");
  analyzeBtn.disabled = true;

  try {
    // 2. Send the file to app.py
    const response = await fetch("/upload", {
      method: "POST",
      body: formData,
    });

    // 3. Handle Success
    if (response.ok) {
      statusBox.classList.add("success");
      statusMsg.innerText = "Analysis Complete! Redirecting to Dashboard...";

      // Redirect to the dynamic dashboard after a short delay
      setTimeout(() => {
        window.location.href = "/dashboard";
      }, 1500);

    // 4. Handle Backend Rejections (e.g., missing columns in reader.py)
    } else {
      const errorData = await response.json();
      throw new Error(errorData.error || "Internal Server Error");
    }

  // 5. Catch and Display the exact error on the UI
  } catch (error) {
    statusBox.className = "status-box error";
    statusMsg.innerText = `Scan Failed: ${error.message}`;
    console.error("Connection/Server Error:", error);
    updateAnalyzeButtonState();
  }
});