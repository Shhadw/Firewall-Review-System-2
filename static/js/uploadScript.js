const uploadForm = document.getElementById("uploadForm");
const statusBox = document.getElementById("status");
const statusMsg = document.getElementById("statusMessage");

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById("csvFile");
  const file = fileInput.files[0];

  if (!file) return;

  const formData = new FormData();
  formData.append("file", file); // Handshake: Key must match Python's request.files.get('file') [cite: 1030]

  statusBox.className = "status-box";
  statusMsg.innerText =
    "Analyzing your firewall rules against ISO/NIST standards...";
  statusBox.classList.remove("hidden");

  try {
    const response = await fetch("/upload", {
      // Relative path is safer for deployment
      method: "POST",
      body: formData,
    });

    if (response.ok) {
      const data = await response.json();
      statusBox.classList.add("success");
      statusMsg.innerText = "Analysis Complete! Redirecting to Dashboard...";

      // --- 🚀 THE PROGRESSIVE DISCLOSURE REDIRECT ---
      // Automatically takes the auditor to the results summary [cite: 1172, 1184]
      setTimeout(() => {
        window.location.href = "/";
      }, 1500); // 1.5 second delay so the user can see the success message
    } else {
      throw new Error("Backend server error");
    }
  } catch (error) {
    statusBox.classList.add("error");
    statusMsg.innerText = "Could not connect to the backend server.";
    console.error("Connection Error:", error);
  }
});
