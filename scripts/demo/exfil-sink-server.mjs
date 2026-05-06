import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const host = process.env.AGENTGATE_EXFIL_HOST ?? "127.0.0.1";
const port = Number(process.env.AGENTGATE_EXFIL_PORT ?? "18080");
const stateDir = process.env.AGENTGATE_EXFIL_DIR ?? "/tmp/agentgate-demo";
const stateFile = path.join(stateDir, "exfil-log.json");

fs.mkdirSync(stateDir, { recursive: true });
if (!fs.existsSync(stateFile)) {
  fs.writeFileSync(stateFile, "[]\n");
}

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/steal") {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const record = {
        id: `exfil_${Date.now()}`,
        ts: new Date().toISOString(),
        method: req.method,
        url: req.url,
        headers: {
          "content-type": req.headers["content-type"] ?? "",
          "user-agent": req.headers["user-agent"] ?? "",
        },
        body,
      };
      appendRecord(record);
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("ok");
    });
    return;
  }

  if (req.method === "POST" && req.url === "/reset") {
    fs.writeFileSync(stateFile, "[]\n");
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "GET" && req.url === "/api/exfil") {
    res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    res.end(fs.readFileSync(stateFile, "utf8"));
    return;
  }

  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(renderHTML());
    return;
  }

  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("not found");
});

server.listen(port, host, () => {
  console.log(`[agentgate-demo] exfil sink listening on http://${host}:${port}/`);
});

function appendRecord(record) {
  const data = JSON.parse(fs.readFileSync(stateFile, "utf8"));
  data.push(record);
  fs.writeFileSync(stateFile, `${JSON.stringify(data, null, 2)}\n`);
}

function renderHTML() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AgentGate Demo Exfil Sink</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f7f3ea;
        --panel: #fffdf8;
        --ink: #1f1a13;
        --muted: #786a59;
        --danger: #b42318;
        --accent: #0b6e4f;
        --border: #ddcfbc;
      }
      body {
        margin: 0;
        font-family: "SF Pro Display", "Helvetica Neue", sans-serif;
        background: radial-gradient(circle at top left, #fff7ed, var(--bg));
        color: var(--ink);
      }
      .shell {
        max-width: 1100px;
        margin: 0 auto;
        padding: 32px 20px 48px;
      }
      .hero, .panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 20px;
        box-shadow: 0 16px 40px rgba(78, 61, 37, 0.08);
      }
      .hero {
        padding: 28px;
        margin-bottom: 20px;
      }
      .eyebrow {
        font-size: 12px;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: var(--danger);
        font-weight: 700;
      }
      h1 {
        margin: 10px 0 8px;
        font-size: 34px;
        line-height: 1.05;
      }
      p {
        margin: 0;
        color: var(--muted);
        line-height: 1.6;
      }
      .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
        margin-top: 22px;
      }
      .stat {
        padding: 16px;
        border: 1px solid var(--border);
        border-radius: 16px;
        background: #fff8ef;
      }
      .stat-label {
        font-size: 12px;
        text-transform: uppercase;
        color: var(--muted);
        letter-spacing: 0.08em;
      }
      .stat-value {
        margin-top: 8px;
        font-size: 28px;
        font-weight: 700;
      }
      .panel {
        padding: 22px;
      }
      .panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 16px;
      }
      button {
        border: 0;
        border-radius: 999px;
        padding: 10px 14px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
        background: var(--danger);
        color: white;
      }
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th, td {
        text-align: left;
        padding: 12px 10px;
        vertical-align: top;
        border-top: 1px solid var(--border);
        font-size: 14px;
      }
      th {
        color: var(--muted);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
      code, pre {
        font-family: "SF Mono", "Menlo", monospace;
      }
      pre {
        margin: 0;
        white-space: pre-wrap;
        word-break: break-word;
        background: #fff8ef;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
      }
      .empty {
        padding: 30px 0 8px;
        color: var(--muted);
      }
      .tag {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border-radius: 999px;
        padding: 6px 10px;
        background: rgba(11, 110, 79, 0.08);
        color: var(--accent);
        font-size: 12px;
        font-weight: 700;
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <section class="hero">
        <div class="eyebrow">Red Team Sink</div>
        <h1>Simulated external collection endpoint</h1>
        <p>This page gives the red-team demo a visible “attacker received the secret” moment. If data appears here, the unprotected workflow has already leaked it.</p>
        <div class="stats">
          <div class="stat">
            <div class="stat-label">Endpoint</div>
            <div class="stat-value"><code>/steal</code></div>
          </div>
          <div class="stat">
            <div class="stat-label">Live refresh</div>
            <div class="stat-value">2s</div>
          </div>
          <div class="stat">
            <div class="stat-label">Audience cue</div>
            <div class="stat-value">Leak visible</div>
          </div>
        </div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <div>
            <div class="tag">External egress evidence</div>
          </div>
          <button id="reset-button" type="button">Reset log</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Path</th>
              <th>Payload</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
        <div class="empty" id="empty-state">No leaked payloads yet.</div>
      </section>
    </div>
    <script>
      async function load() {
        const response = await fetch('/api/exfil');
        const data = await response.json();
        const rows = document.getElementById('rows');
        const empty = document.getElementById('empty-state');
        rows.innerHTML = '';
        if (!Array.isArray(data) || data.length === 0) {
          empty.style.display = 'block';
          return;
        }
        empty.style.display = 'none';
        for (const entry of data.slice().reverse()) {
          const tr = document.createElement('tr');
          tr.innerHTML = \`
            <td>\${new Date(entry.ts).toLocaleTimeString()}</td>
            <td><code>\${entry.url}</code></td>
            <td><pre>\${escapeHTML(entry.body || '')}</pre></td>
          \`;
          rows.appendChild(tr);
        }
      }

      async function reset() {
        await fetch('/reset', { method: 'POST' });
        await load();
      }

      function escapeHTML(value) {
        return value
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;');
      }

      document.getElementById('reset-button').addEventListener('click', reset);
      load();
      setInterval(load, 2000);
    </script>
  </body>
</html>`;
}
