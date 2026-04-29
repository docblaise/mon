const demoData = {
  updated: "2026-04-28 17:46:33",
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
      started: "2026-04-28 17:46:00",
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
  ],
  adminUsers: [
    { user: "admin", role: "Administrator", status: "active", lastLogin: "2026-04-28 17:45:58" },
    { user: "observer", role: "Read Only", status: "active", lastLogin: "2026-04-28 16:18:11" },
    { user: "lab-ops", role: "Operator", status: "pending", lastLogin: "2026-04-27 10:42:05" }
  ],
  adminAudit: [
    { time: "17:45:58", action: "login", actor: "admin", detail: "Authenticated to dashboard" },
    { time: "17:44:12", action: "switch_nic", actor: "admin", detail: "Changed capture interface to Ethernet" },
    { time: "17:42:03", action: "clear_events", actor: "admin", detail: "Cleared dropped event history" }
  ]
};

const state = {
  view: "login",
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
  return `<div class="table-panel"><div class="table-wrap${scroll ? " scroll" : ""}"><table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.join("") : emptyRow("No data", headers.length)}</tbody></table></div></div>`;
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

function renderLogin() {
  el("demo-login").innerHTML = `
    <div class="login-demo">
      <div class="login-hero">
        <div class="eyebrow">Access Screen</div>
        <h2 class="section-title">Login</h2>
        <p class="section-subtitle">Simple operator sign-in screen for the Net-PY dashboard.</p>
        <div class="login-note-card">
          <strong>Default Demo User</strong>
          <span>Username: admin</span>
          <span>Password: netpy2024</span>
        </div>
      </div>
      <div class="login-card-demo">
        <div class="login-brand-demo">net-py</div>
        <div class="login-subtitle-demo">authenticate to continue</div>
        <div class="login-form-demo">
          <label>Username</label>
          <input class="search-input" type="text" value="admin" readonly>
          <label>Password</label>
          <input class="search-input" type="password" value="netpy2024" readonly>
          <button class="btn btn-accent demo-button-full" onclick="setView('overview')">Open Dashboard</button>
        </div>
      </div>
    </div>
  `;
}

function renderAdmin() {
  const users = demoData.adminUsers.map(user => rowHtml([
    esc(user.user),
    esc(user.role),
    `<span class="status-${user.status === "active" ? "trusted" : user.status === "pending" ? "new" : "alert"}">${esc(user.status)}</span>`,
    esc(user.lastLogin)
  ]));
  const audit = demoData.adminAudit.map(item => rowHtml([
    esc(item.time),
    esc(item.action),
    esc(item.actor),
    `<span class="wrap">${esc(item.detail)}</span>`
  ]));

  el("demo-admin").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Admin</h2>
        <div class="section-subtitle">Manage access, review audit activity, and monitor platform state.</div>
      </div>
      <div class="section-tools">
        <span class="btn btn-ghost">Add User</span>
        <span class="btn btn-accent">Export Audit</span>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Users</div><div class="stat-value">3</div></div>
      <div class="stat-card"><div class="stat-label">Active Sessions</div><div class="stat-value">2</div></div>
      <div class="stat-card"><div class="stat-label">Pending Access</div><div class="stat-value">1</div></div>
      <div class="stat-card"><div class="stat-label">Audit Entries</div><div class="stat-value">${demoData.adminAudit.length}</div></div>
    </div>

    <div class="overview-grid">
      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">User Access</div>
            <div class="panel-note">role and session overview</div>
          </div>
          ${wrapTable(["User", "Role", "Status", "Last Login"], users)}
        </div>
      </div>
      <div class="stack">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Audit Log</div>
            <div class="panel-note">latest admin actions</div>
          </div>
          ${wrapTable(["Time", "Action", "Actor", "Detail"], audit, true)}
        </div>
      </div>
    </div>
  `;
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
        <span class="btn btn-ghost">Scan Now</span>
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

  el("deviceSearchInput").value = search;
  el("deviceSearchInput").addEventListener("input", renderDevices);
  document.querySelectorAll("[data-filter]").forEach(button => {
    button.addEventListener("click", () => setFilter(button.dataset.filter));
  });
}

function renderAlerts() {
  el("demo-alerts").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Alerts</h2>
        <div class="section-subtitle">Recent new-device alerts and network notices.</div>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Type", "IP", "MAC", "Message"],
      demoData.alerts.map(a => rowHtml([esc(a.time), esc(a.type), esc(a.ip), esc(a.mac), `<span class="wrap">${esc(a.message)}</span>`])),
      true
    )}
  `;
}

function renderEvents() {
  el("demo-events").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Events</h2>
        <div class="section-subtitle">Sample suspicious and DAI-related event data.</div>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Port", "Sender IP", "Sender MAC", "Reason"],
      demoData.events.map(e => rowHtml([esc(e.time), esc(e.port), esc(e.senderIp), esc(e.senderMac), `<span class="wrap">${esc(e.reason)}</span>`])),
      true
    )}
  `;
}

function renderSyslog() {
  el("demo-syslog").innerHTML = `
    <div class="section-header">
      <div>
        <h2 class="section-title">Syslog Feed</h2>
        <div class="section-subtitle">Example switch syslog entries captured by Net-PY.</div>
      </div>
    </div>
    ${wrapTable(
      ["Time", "Source", "Message"],
      demoData.syslog.map(s => rowHtml([esc(s.time), esc(s.source), `<span class="wrap">${esc(s.message)}</span>`])),
      true
    )}
  `;
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
        <input class="search-input" type="text" value="192.168.1.0/24" readonly>
        <span class="btn btn-accent">Run Network Scan</span>
      </div>

      <div class="scan-results">
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
  renderLogin();
  renderAdmin();
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
setView("login");
