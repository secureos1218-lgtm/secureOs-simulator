"use strict";

const startButton = document.getElementById("startButton");
const stopButton = document.getElementById("stopButton");
const clearButton = document.getElementById("clearButton");
const progressBar = document.getElementById("progressBar");
const progressValue = document.getElementById("progressValue");
const terminal = document.getElementById("terminal");
const resultsBody = document.getElementById("resultsBody");
const resultCount = document.getElementById("resultCount");
const profile = document.getElementById("profile");
const ports = document.getElementById("ports");
const targetInput = document.getElementById("target");
const menuButton = document.getElementById("menuButton");
const sidebar = document.getElementById("sidebar");

// Establish the persistent, bidirectional WebSocket connection tunnel
const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/nmap`);

function setStatus(label, percent) {
  progressBar.style.width = `${percent}%`;
  progressValue.textContent = label;
}

function addCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value ?? "";
  row.appendChild(cell);
}

function renderResults(result) {
  resultsBody.replaceChildren();
  const discoveredPorts = Array.isArray(result.ports) ? result.ports : [];

  discoveredPorts.forEach((item) => {
    const row = document.createElement("tr");
    addCell(row, item.dest_ip || result.target);
    addCell(row, item.port);

    const stateCell = document.createElement("td");
    const badge = document.createElement("span");
    const stateUpper = String(item.state).toUpperCase();

    badge.className = `badge ${stateUpper === "OPEN" ? "" : "closed"}`;
    badge.textContent = stateUpper.toLowerCase();
    stateCell.appendChild(badge);
    row.appendChild(stateCell);

    addCell(row, item.service);
    
    // Update 3 Highlight: Identify vulnerabilities cleanly with specific warning text
    const versionCell = document.createElement("td");
    versionCell.textContent = item.version;
    if (String(item.version).includes("⚠️ VULNERABLE")) {
      versionCell.style.color = "#ff6b7a";
      versionCell.style.fontWeight = "bold";
      versionCell.style.whiteSpace = "normal";
    }
    row.appendChild(versionCell);
    
    resultsBody.appendChild(row);
  });

  resultCount.textContent = discoveredPorts.length
    ? `Showing ${discoveredPorts.length} discovered port${discoveredPorts.length === 1 ? "" : "s"}`
    : "No ports discovered";
}

function setScanning(scanning) {
  startButton.disabled = scanning;
  stopButton.disabled = !scanning;
  profile.disabled = scanning;
  ports.disabled = scanning || profile.value !== "CUSTOM";
}

// Intercept streaming packet frames sent from the Flask websocket server routing loop
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);

  // Update 1: Stream live Nmap stdout telemetry line-by-line right into the console wrapper
  if (data.type === "TERMINAL_LINE") {
    if (terminal.textContent === "Ready. Configure an authorized target and start a scan." || terminal.textContent.startsWith("Starting")) {
      terminal.textContent = "";
    }
    terminal.textContent += data.text;
    terminal.scrollTop = terminal.scrollHeight; // Automatically anchor scroll positions down
  }

  // Update 2: Drive real-time execution progress sliders dynamically via regex percentage matches
  if (data.type === "PROGRESS_UPDATE") {
    setStatus(data.label, data.percent);
  }

  // Handle final synchronization payload logic
  if (data.type === "SCAN_COMPLETE") {
    setScanning(false);
    if (data.payload.status === "success") {
      renderResults(data.payload);
      terminal.textContent += `\n[+] ${data.payload.summary}\n`;
      setStatus("Complete", 100);
    } else {
      terminal.textContent += `\n[!] Scan transaction error encountered: ${data.payload.summary}\n`;
      setStatus("Error", 0);
      resultCount.textContent = "Scan failed.";
    }
    terminal.scrollTop = terminal.scrollHeight;
  }
};

profile.addEventListener("change", () => {
  ports.disabled = profile.value !== "CUSTOM";
});

startButton.addEventListener("click", () => {
  const target = targetInput.value.trim();

  if (!target) {
    terminal.textContent = "Input Validation Error: Enter an IP address, hostname, range, or CIDR target.";
    return;
  }

  setScanning(true);
  setStatus("Starting", 10);
  terminal.textContent = `Starting ${profile.options[profile.selectedIndex].text} on ${target}...`;
  resultsBody.replaceChildren();
  resultCount.textContent = "Scanning active. Streaming live results...";

  // Emit your execution payload parameters up the open WebSocket channel pipe
  ws.send(JSON.stringify({
    "action": "RUN_NMAP",
    "target": target,
    "profile": profile.value,
    "custom_ports": profile.value === "CUSTOM" ? ports.value.trim() : null
  }));
});

stopButton.addEventListener("click", () => {
  terminal.textContent += "\n[*] Terminate command registered. Closing background threads safely...\n";
  setScanning(false);
  setStatus("Cancelled", 0);
});

clearButton.addEventListener("click", () => {
  setStatus("Ready", 0);
  terminal.textContent = "Ready. Configure a target and start a scan.";
  resultsBody.replaceChildren();
  resultCount.textContent = "No scan results";
});

menuButton.addEventListener("click", () => {
  sidebar.classList.toggle("open");
});

ws.onclose = function() {
  console.warn("SecurOS UI Matrix Warning: WebSocket channel connection closed dropped.");
  terminal.textContent += "\n[!] Connection lost. Check your Python flask app environment logs.";
  setStatus("Offline", 0);
};
