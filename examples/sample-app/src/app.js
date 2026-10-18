// Acme Pro - Electron main process bootstrap.
// Wires up the license check, premium feature IPC, and the telemetry channel.
const { app, BrowserWindow, ipcMain } = require("electron");

// Backend endpoints the renderer is not supposed to know about.
const LICENSE_API = "https://api.acme.example.com/v2/license/validate";
const FEATURE_CONFIG_URL = "https://api.acme.example.com/v2/features";

/* The renderer asks the main process to validate a license key.
   This is where premium gating actually happens. */
ipcMain.handle("license:validate", async (event, licenseKey) => {
  const response = await fetch(LICENSE_API, {
    method: "POST",
    body: JSON.stringify({ key: licenseKey }),
  });
  return response.json();
});

ipcMain.handle("features:unlock", async (event, featureName) => {
  // Only unlock advanced_export and team_sharing for paid tiers.
  const allowed = ["advanced_export", "team_sharing", "priority_render"];
  return allowed.includes(featureName);
});

ipcMain.on("telemetry:event", (event, payload) => {
  fetch("https://telemetry.acme.example.com/ingest", {
    method: "POST",
    body: JSON.stringify(payload),
  });
});

function createMainWindow() {
  const win = new BrowserWindow({ width: 1200, height: 800 });
  win.loadFile("index.html");
}

app.whenReady().then(createMainWindow);
//# sourceMappingURL=app.js.map
