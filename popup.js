
const statusText = document.getElementById("statusText");
const statusDescription = document.getElementById("statusDescription");
const statusDot = document.getElementById("statusDot");
const checkButton = document.getElementById("checkButton");

function updateStatus(type, title, description) {
  statusText.textContent = title;
  statusDescription.textContent = description;
  statusDot.className = "status-dot";

  if (type === "connected") {
    statusDot.classList.add("connected");
  } else if (type === "error") {
    statusDot.classList.add("error");
  }
}

function checkConnection() {
  checkButton.disabled = true;
  checkButton.textContent = "Checking...";

  chrome.tabs.query(
    { active: true, currentWindow: true },
    tabs => {
      const tab = tabs[0];

      if (chrome.runtime.lastError || !tab?.id) {
        updateStatus(
          "error",
          "Connection unavailable",
          "Could not identify the current browser tab."
        );
        finishCheck();
        return;
      }

      chrome.tabs.sendMessage(
        tab.id,
        { type: "PHISHGUARD_PING" },
        response => {
          if (chrome.runtime.lastError || !response?.active) {
            updateStatus(
              "error",
              "Detector not connected",
              "Open or refresh WhatsApp Web, then check again."
            );
          } else {
            updateStatus(
              "connected",
              "Detector connected",
              "The content script is responding on this page."
            );
          }

          finishCheck();
        }
      );
    }
  );
}

function finishCheck() {
  checkButton.disabled = false;
  checkButton.textContent = "Check Connection";
}

checkButton.addEventListener("click", checkConnection);

checkConnection();
