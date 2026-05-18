// static/js/uploadScript.js
const uploadForm = document.getElementById("uploadForm");
const statusBox = document.getElementById("status");
const statusMsg = document.getElementById("statusMessage");

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById("csvFile");
  const file = fileInput.files[0];

  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  // 1. Show the loading state
  statusBox.className = "status-box";
  statusMsg.innerText = "Analyzing your firewall rules against ISO/NIST standards...";
  statusBox.classList.remove("hidden");

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
    statusBox.classList.add("error");
    statusMsg.innerText = `Scan Failed: ${error.message}`;
    console.error("Connection/Server Error:", error);
  }
});