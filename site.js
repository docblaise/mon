const demoData = {
  updated: "2026-05-03 17:46:33",
  trustedBindings: [
    { ip: "192.168.1.254", mac: "50:95:51:93:A2:C8" },
    { ip: "192.168.1.119", mac: "A8:A1:59:60:49:23" }
  ],
  devices: [
    { name: "Router", ip: "192.168.1.254", mac: "50:95:51:93:A2:C8", type: "Router", status: "trusted", firstSeen: "17:10:02", lastSeen: "17:46:31" },
    { name: "Raspberry Pi", ip: "192.168.1.119", mac: "A8:A1:59:60:49:23", type: "Host", status: "trusted", firstSeen: "17:12:41", lastSeen: "17:46:33" },
    { name: "", ip: "192.168.1.172", mac: "E8:68:E7:48:E9:74", type: "AP", status: "known", firstSeen: "17:18:07", lastSeen: "17:46:20" },
    { name: "", ip: "192.168.1.217", mac: "78:83:9F:6A:40:49", type: "Laptop", status: "known", firstSeen: "17:20:13", lastSeen: "17:46:18" },
    { name: "", ip: "192.168.1.58", mac: "4C:F3:E0:F1:98:64", type: "ESP32", status: "new", firstSeen: "17:34:48", lastSeen: "17:45:59" },
    { name: "", ip: "192.168.1.42", mac: "84:C0:EF:1E:A8:4E", type: "IoT Device", status: "new", firstSeen: "17:31:02", lastSeen: "17:46:03" },
    { name: "", ip: "192.168.1.37", mac: "CC:50:E3:E5:68:70", type: "ESP32", status: "alert", firstSeen: "17:37:19", lastSeen: "17:45:49" },
    { name: "", ip: "192.168.1.31", mac: "4A:83:FE:36:46:1B", type: "Host", status: "known", firstSeen: "17:41:38", lastSeen: "17:42:29" }
  ],
  devicesBackup: [
    { name: "Router", ip: "192.168.1.254", mac: "50:95:51:93:A2:C8", type: "Router", status: "trusted", firstSeen: "17:10:02", lastSeen: "17:46:31" },
    { name: "Raspberry Pi", ip: "192.168.1.119", mac: "A8:A1:59:60:49:23", type: "Host", status: "trusted", firstSeen: "17:12:41", lastSeen: "17:46:33" },
    { name: "", ip: "192.168.1.172", mac: "E8:68:E7:48:E9:74", type: "AP", status: "known", firstSeen: "17:18:07", lastSeen: "17:46:20" },
    { name: "", ip: "192.168.1.217", mac: "78:83:9F:6A:40:49", type: "Laptop", status: "known", firstSeen: "17:20:13", lastSeen: "17:46:18" },
    { name: "", ip: "192.168.1.58", mac: "4C:F3:E0:F1:98:64", type: "ESP32", status: "new", firstSeen: "17:34:48", lastSeen: "17:45:59" },
    { name: "", ip: "192.168.1.42", mac: "84:C0:EF:1E:A8:4E", type: "IoT Device", status: "new", firstSeen: "17:31:02", lastSeen: "17:46:03" },
    { name: "", ip: "192.168.1.37", mac: "CC:50:E3:E5:68:70", type: "ESP32", status: "alert", firstSeen: "17:37:19", lastSeen: "17:45:49" },
    { name: "", ip: "192.168.1.31", mac: "4A:83:FE:36:46:1B", type: "Host", status: "known", firstSeen: "17:41:38", lastSeen: "17:42:29" }
  ],
  alerts: [
    { time: "17:46:25", type: "new_device", ip: "192.168.1.192", mac: "E0:62:34:F9:C8:BD", message: "New device connected" },
    { time: "17:46:26", type: "new_device", ip: "192.168.1.172", mac: "E8:68:E7:48:E9:74", message: "New device connected" },
    { time: "17:46:30", type: "new_device", ip: "192.168.1.217", mac: "78:83:9F:6A:40:49", message: "New device connected" },
    { time: "17:46:33", type: "new_device", ip: "192.168.1.119", mac: "A8:A1:59:60:49:23", message: "New device connected" }
  ],
  events: [
    { time: "17:41:30", port: "LIVE", senderIp: "192.168.86.38", senderMac: "84:F3:EB:F1:98:E4", reason: "Subnet mismatch" },
    { time: "17:41:30", port: "LIVE", senderIp: "192.168.86.42", senderMac: "84:C0:EF:1E:A8:4E", reason: "Subnet mismatch" },
    { time: "17:41:33", port: "LIVE", senderIp: "192.168.86.37", senderMac: "CC:50:E3:E5:68:70", reason: "Subnet mismatch" },
    { time: "17:41:35", port: "LIVE", senderIp: "192.168.86.41", senderMac: "84:F3:EB:F1:39:24", reason: "Subnet mismatch" }
  ],
  syslog: [
    { time: "17:44:10", source: "sw-core", message: "%SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs (Req) on Vlan 1, from 84:C0:EF:1E:A8:4E/192.168.1.42 to ff:ff:ff:ff:ff:ff/192.168.1.1" },
    { time: "17:44:10", source: "sw-core", message: "Ethernet src 84:C0:EF:1E:A8:4E dst ff:ff:ff:ff:ff:ff" },
    { time: "17:44:10", source: "sw-core", message: "ARP request from 192.168.1.42 for 192.168.1.1 vlan 1" },
    { time: "17:45:03", source: "sw-edge", message: "%LINK-3-UPDOWN: Interface Gi0/1, changed state to up" }
  ],
  scanResults: [
    {
      label: "Network Scan",
      status: "done",
      started: "2026-05-03 17:46:00",
      cmd: "nmap -O --osscan-limit -PR 192.168.1.0/24",
      output:
`Nmap scan report for 192.168.1.254
Host is up (0.0010s latency).
MAC Address: 50:95:51:93:A2:C8 (Router)
Device type: broadband router

Nmap scan report for 192.168.1.119
Host is up (0.00080s latency).
MAC Address: A8:A1:59:60:49:23 (Raspberry Pi)
OS details: Linux 5.X`
    }
  ]
};

const state = {
  view: "overview",
  filter: "all"
};

const el = id => document.getElementById(id);
const esc = value => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");

function rowHtml(cells) {
  return `<tr>${cells.map(cell => `<td>${cell}</td>`).join("")}</tr>`;
}

function emptyRow(message, cols) {
  return `<tr><td colspan="${cols}" class="wrap">${esc(message)}</td></tr>`;
}

function wrapTable(headers, rows, scroll = false) {
  return `<div class="table-panel"><div class="table-wrap${scroll ? " scroll" : ""}"><table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.join("") : emptyRow("No data available", headers.length)}</tbody></table></div></div>`;
}

function setView(view) {
  state.view = view;
  document.querySelectorAll("[data-demo-view]").forEach(button => {
    button.classList.toggle("active", button.dataset.demoView === view);
  });
  document.querySelectorAll(".demo-view").forEach(section => {
    section.classList.toggle("active", section.id === `demo-${view}`);
  });
}

function setFilter(filter) {
  state.filter = filter;
  document.querySelectorAll("[data-filter]").forEach(button => {
    button.classList.toggle("active", button.dataset.filter === filter);
  });
  renderDevices();
}

function renderOverview() {
  const overview = el("demo-overview");
  const latestAlerts = demoData.alerts.map(a => rowHtml([esc(a.time), esc(a.type), esc(a.ip), `<span class="wrap">${esc(a.message)}</span>`]));
  const latestEvents = demoData.events.map(e => rowHtml([esc(e.time), esc(e.port), esc(e.senderIp), `<span class="wrap">${esc(e.reason)}</span>`]));
  const latestDevices = demoData.devices.slice(0, 6).map(d => rowHtml([
    d.name ? esc(d.name) : '<span class="wrap">unnamed</span>',
    esc(d.ip),
    `<span class="status-${esc(d.status)}">${esc(d.status)}</span>`,
    esc(d.lastSeen)
  ]));

  overview.innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Overview</h2>
        <div class="section-subtitle">Live summary of trusted bindings, devices, alerts, and suspicious activity.</div>
      </div>
      <div class="section-tools">
        <button id="resetOverviewBtn" class="btn btn-ghost">Reset</button>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Trusted Bindings</div><div class="stat-value">${demoData.trustedBindings.length}</div></div>
      <div class="stat-card"><div class="stat-label">Known Devices</div><div class="stat-value">${demoData.devices.length}</div></div>
      <div class="stat-card"><div class="stat-label">Alerts</div><div class="stat-value">${demoData.alerts.length}</div></div>
      <div class="stat-card"><div class="stat-label">Events</div><div class="stat-value">${demoData.events.length}</div></div>
    </div>

    <div class="overview-grid">
      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Trusted Bindings</div>
            <div class="panel-note">Updated: ${esc(demoData.updated)}</div>
          </div>
          ${wrapTable(["IP", "MAC"], demoData.trustedBindings.map(b => rowHtml([esc(b.ip), esc(b.mac)])))}
        </div>
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Latest Alerts</div>
          </div>
          ${wrapTable(["Time", "Type", "IP", "Message"], latestAlerts)}
        </div>
      </div>

      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Recent Events</div>
          </div>
          ${wrapTable(["Time", "Port", "Sender IP", "Reason"], latestEvents, true)}
        </div>
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Known Devices Snapshot</div>
          </div>
          ${wrapTable(["Name", "IP", "Status", "Last Seen"], latestDevices)}
        </div>
      </div>
    </div>
  `;

  setTimeout(() => {
    const resetBtn = el("resetOverviewBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.devices = demoData.devicesBackup.map(d => ({ ...d, name: "" }));
        demoData.alerts = [];
        demoData.events = [];
        demoData.syslog = [];
        renderAll();
      });
    }
  }, 0);
}

function renderDevices() {
  const section = el("demo-devices");
  const search = (el("deviceSearchInput")?.value || "").trim().toLowerCase();
  const filtered = demoData.devices.filter(device => {
    if (state.filter !== "all" && device.status !== state.filter) return false;
    if (!search) return true;
    return [device.name, device.ip, device.mac, device.type, device.status].join(" ").toLowerCase().includes(search);
  });

  const counts = {
    trusted: demoData.devices.filter(d => d.status === "trusted").length,
    known: demoData.devices.filter(d => d.status === "known").length,
    new: demoData.devices.filter(d => d.status === "new").length,
    alert: demoData.devices.filter(d => d.status === "alert").length
  };

  section.innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Devices on Network</h2>
        <div class="summary-line">
          <span><strong>${demoData.devices.length}</strong> total</span>
          <span><strong>${counts.trusted}</strong> trusted</span>
          <span><strong>${counts.known}</strong> known</span>
          <span><strong>${counts.new}</strong> new</span>
          <span><strong>${counts.alert}</strong> alert</span>
        </div>
      </div>
      <div class="section-tools">
        <button id="scanNowBtn" class="btn btn-ghost">Scan Now</button>
        <button id="resetDevicesBtn" class="btn btn-ghost">Reset</button>
      </div>
    </div>

    <div class="filters">
      <input id="deviceSearchInput" class="search-input" type="text" placeholder="Search IP, MAC, name, or type">
      <div class="pill-row">
        <button class="pill ${state.filter === "all" ? "active" : ""}" data-filter="all">all</button>
        <button class="pill ${state.filter === "trusted" ? "active" : ""}" data-filter="trusted">trusted</button>
        <button class="pill ${state.filter === "known" ? "active" : ""}" data-filter="known">known</button>
        <button class="pill ${state.filter === "new" ? "active" : ""}" data-filter="new">new</button>
        <button class="pill ${state.filter === "alert" ? "active" : ""}" data-filter="alert">alert</button>
      </div>
    </div>

    ${wrapTable(
      ["Status", "Name", "IP", "MAC", "Type", "First Seen", "Last Seen"],
      filtered.map(d => rowHtml([
        `<span class="dot dot-${esc(d.status)}"></span><span class="status-${esc(d.status)}">${esc(d.status)}</span>`,
        d.name ? esc(d.name) : '<span class="wrap">unnamed</span>',
        esc(d.ip),
        esc(d.mac),
        esc(d.type),
        esc(d.firstSeen),
        esc(d.lastSeen)
      ]))
    )}
  `;

  setTimeout(() => {
    el("deviceSearchInput").value = search;
    el("deviceSearchInput").addEventListener("input", renderDevices);
    document.querySelectorAll("[data-filter]").forEach(button => {
      button.addEventListener("click", () => setFilter(button.dataset.filter));
    });

    const resetBtn = el("resetDevicesBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.devices = demoData.devicesBackup.map(d => ({ ...d, name: "" }));
        renderDevices();
      });
    }

    const scanBtn = el("scanNowBtn");
    if (scanBtn) {
      scanBtn.addEventListener("click", () => {
        setView("scan");
      });
    }
  }, 0);
}

function renderAlerts() {
  el("demo-alerts").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Alerts</h2>
        <div class="section-subtitle">Recent new-device alerts and network notices.</div>
      </div>
      <div class="section-tools">
        <button id="resetAlertsBtn" class="btn btn-ghost">Reset</button>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Type", "IP", "MAC", "Message"],
      demoData.alerts.map(a => rowHtml([esc(a.time), esc(a.type), esc(a.ip), esc(a.mac), `<span class="wrap">${esc(a.message)}</span>`])),
      true
    )}
  `;

  setTimeout(() => {
    const resetBtn = el("resetAlertsBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.alerts = [];
        renderAlerts();
      });
    }
  }, 0);
}

function renderEvents() {
  el("demo-events").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Events</h2>
        <div class="section-subtitle">Sample suspicious and DAI-related event data.</div>
      </div>
      <div class="section-tools">
        <button id="resetEventsBtn" class="btn btn-ghost">Reset</button>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Port", "Sender IP", "Sender MAC", "Reason"],
      demoData.events.map(e => rowHtml([esc(e.time), esc(e.port), esc(e.senderIp), esc(e.senderMac), `<span class="wrap">${esc(e.reason)}</span>`])),
      true
    )}
  `;

  setTimeout(() => {
    const resetBtn = el("resetEventsBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.events = [];
        renderEvents();
      });
    }
  }, 0);
}

function renderSyslog() {
  el("demo-syslog").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Syslog Feed</h2>
        <div class="section-subtitle">Example switch syslog entries captured by Net-PY.</div>
      </div>
      <div class="section-tools">
        <button id="resetSyslogBtn" class="btn btn-ghost">Reset</button>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Source", "Message"],
      demoData.syslog.map(s => rowHtml([esc(s.time), esc(s.source), `<span class="wrap">${esc(s.message)}</span>`])),
      true
    )}
  `;

  setTimeout(() => {
    const resetBtn = el("resetSyslogBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.syslog = [];
        renderSyslog();
      });
    }
  }, 0);
}

function renderScan() {
  const scan = demoData.scanResults[0];
  el("demo-scan").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Network Scan</h2>
        <div class="section-subtitle">Combined host discovery, MAC/vendor lookup, and OS detection preview.</div>
      </div>
    </div>

    <div class="panel">
      <div class="scan-grid">
        <div class="scan-card selected">
          <div class="scan-label">Network Scan</div>
          <div class="scan-desc">Combined host discovery, MAC/vendor lookup, and OS detection across the subnet.</div>
          <div class="scan-cmd">nmap -O --osscan-limit -PR 192.168.1.0/24</div>
        </div>
      </div>

      <div class="scan-controls">
        <input id="scanInput" class="search-input" type="text" value="192.168.1.0/24" readonly>
        <button id="runScanBtn" class="btn btn-accent">Run Network Scan</button>
        <button id="clearScanBtn" class="btn btn-ghost">Clear Results</button>
        <button id="resetDataBtn" class="btn btn-ghost">Reset All Data</button>
      </div>

      <div id="scanResults" class="scan-results">
        <div class="scan-result">
          <div class="scan-head">
            <div class="scan-meta">
              <span class="scan-status done">${esc(scan.status)}</span>
              <span>${esc(scan.label)}</span>
              <span>${esc(scan.cmd)}</span>
            </div>
            <span class="top-timestamp">${esc(scan.started)}</span>
          </div>
          <div class="scan-output">
            <pre>${esc(scan.output)}</pre>
          </div>
        </div>
      </div>
    </div>
  `;

  setTimeout(() => {
    const runBtn = el("runScanBtn");
    if (runBtn) {
      runBtn.addEventListener("click", () => {
        const scanResultsDiv = el("scanResults");
        const newScan = {
          label: "Network Scan",
          status: "done",
          started: new Date().toLocaleString(),
          cmd: "nmap -O --osscan-limit -PR 192.168.1.0/24",
          output: `Nmap scan report for 192.168.1.254
Host is up (0.0010s latency).
MAC Address: 50:95:51:93:A2:C8 (Router)
Device type: broadband router

Nmap scan report for 192.168.1.119
Host is up (0.00080s latency).
MAC Address: A8:A1:59:60:49:23 (Raspberry Pi)
OS details: Linux 5.X

Scan completed at ${new Date().toLocaleTimeString()}`
        };
        
        scanResultsDiv.innerHTML += `
          <div class="scan-result">
            <div class="scan-head">
              <div class="scan-meta">
                <span class="scan-status done">${esc(newScan.status)}</span>
                <span>${esc(newScan.label)}</span>
                <span>${esc(newScan.cmd)}</span>
              </div>
              <span class="top-timestamp">${esc(newScan.started)}</span>
            </div>
            <div class="scan-output">
              <pre>${esc(newScan.output)}</pre>
            </div>
          </div>
        `;
      });
    }

    const clearBtn = el("clearScanBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        el("scanResults").innerHTML = '';
      });
    }

    const resetBtn = el("resetDataBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        demoData.devices = demoData.devicesBackup.map(d => ({ ...d, name: "" }));
        demoData.syslog = [];
        demoData.alerts = [];
        demoData.events = [];
        el("scanResults").innerHTML = '';
        renderAll();
      });
    }
  }, 0);
}

function renderSettings() {
  el("demo-settings").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Settings</h2>
        <div class="section-subtitle">Static configuration preview for the GitHub demo site.</div>
      </div>
    </div>
    <div class="settings-grid">
      <div class="setting-card"><div class="setting-label">Active Interface</div><div class="setting-value">${esc(el("demoNic").value)}</div></div>
      <div class="setting-card"><div class="setting-label">Auto Refresh</div><div class="setting-value">10 second dashboard refresh</div></div>
      <div class="setting-card"><div class="setting-label">Syslog Port</div><div class="setting-value">UDP 514</div></div>
      <div class="setting-card"><div class="setting-label">Dashboard Port</div><div class="setting-value">5000</div></div>
    </div>
  `;
}

function renderAll() {
  el("demoUpdated").textContent = `Updated: ${demoData.updated}`;
  renderOverview();
  renderDevices();
  renderAlerts();
  renderEvents();
  renderSyslog();
  renderScan();
  renderSettings();
}

document.querySelectorAll("[data-demo-view]").forEach(button => {
  button.addEventListener("click", () => setView(button.dataset.demoView));
});

el("demoNic").addEventListener("change", renderSettings);

renderAll();
setView("overview");
