#!/usr/bin/env python3
"""SuperScalar Web Dashboard — stdlib-only (http.server + sqlite3 + subprocess).

Read-only monitoring dashboard for SuperScalar signet deployments.
Polls process status, Bitcoin network, SQLite databases, and CLN nodes.

Usage:
    python3 tools/dashboard.py --port 8080 \
        --lsp-db /tmp/superscalar-signet/lsp.db \
        --client-db /tmp/superscalar-signet/client.db \
        --btc-cli /home/obscurity/superscalar-ln/bin/bitcoin-cli \
        --btc-network signet --btc-rpcuser superscalar --btc-rpcpassword superscalar123 \
        --cln-cli /home/obscurity/cln-test-8849/lightning/cli/lightning-cli \
        --cln-a-dir /tmp/superscalar-signet/cln-a \
        --cln-b-dir /tmp/superscalar-signet/cln-b
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Holds all CLI-supplied paths and settings."""
    def __init__(self, args):
        self.port = args.port
        self.lsp_db = args.lsp_db
        self.client_db = args.client_db
        self.btc_cli = args.btc_cli
        self.btc_network = args.btc_network
        self.btc_rpcuser = args.btc_rpcuser
        self.btc_rpcpassword = args.btc_rpcpassword
        self.cln_cli = args.cln_cli
        self.cln_a_dir = args.cln_a_dir
        self.cln_b_dir = args.cln_b_dir


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_cmd(args, timeout=5):
    """Run a command and return (stdout, ok)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip(), True
        return result.stderr.strip(), False
    except FileNotFoundError:
        return "command not found: " + str(args[0]), False
    except subprocess.TimeoutExpired:
        return "timeout", False
    except Exception as e:
        return str(e), False


def btc_cmd(cfg, *rpc_args):
    """Build and run a bitcoin-cli command."""
    cmd = [cfg.btc_cli]
    if cfg.btc_network and cfg.btc_network != "mainnet":
        cmd.append("-" + cfg.btc_network)
    if cfg.btc_rpcuser:
        cmd.append("-rpcuser=" + cfg.btc_rpcuser)
    if cfg.btc_rpcpassword:
        cmd.append("-rpcpassword=" + cfg.btc_rpcpassword)
    cmd.extend(rpc_args)
    return run_cmd(cmd)


def cln_cmd(cfg, lightning_dir, *rpc_args):
    """Build and run a lightning-cli command."""
    cmd = [cfg.cln_cli, "--lightning-dir=" + lightning_dir]
    cmd.extend(rpc_args)
    return run_cmd(cmd)


def pgrep_check(pattern):
    """Check if a process matching pattern is running."""
    out, ok = run_cmd(["pgrep", "-f", pattern])
    return ok


def query_db(db_path, sql, params=()):
    """Run a read-only query against a SQLite database."""
    if not db_path or not os.path.exists(db_path):
        return None, "database not found: " + str(db_path)
    try:
        uri = "file:" + db_path + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows, None
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_processes(cfg):
    """Check which components are running."""
    procs = {}
    for name, pattern in [
        ("bitcoind", "bitcoind.*-" + (cfg.btc_network or "signet")),
        ("cln_a", "lightningd.*" + (cfg.cln_a_dir or "/cln-a")),
        ("cln_b", "lightningd.*" + (cfg.cln_b_dir or "/cln-b")),
        ("bridge", "superscalar_bridge"),
        ("lsp", "superscalar_lsp"),
        ("client", "superscalar_client"),
    ]:
        procs[name] = pgrep_check(pattern)

    # Fallback: try RPC for bitcoind
    if not procs["bitcoind"] and cfg.btc_cli:
        _, ok = btc_cmd(cfg, "getblockchaininfo")
        procs["bitcoind"] = ok

    # Fallback: try RPC for CLN nodes
    if not procs["cln_a"] and cfg.cln_cli and cfg.cln_a_dir:
        _, ok = cln_cmd(cfg, cfg.cln_a_dir, "getinfo")
        procs["cln_a"] = ok
    if not procs["cln_b"] and cfg.cln_cli and cfg.cln_b_dir:
        _, ok = cln_cmd(cfg, cfg.cln_b_dir, "getinfo")
        procs["cln_b"] = ok

    return procs


def collect_bitcoin(cfg):
    """Gather Bitcoin network info."""
    data = {"available": False}
    if not cfg.btc_cli:
        return data

    out, ok = btc_cmd(cfg, "getblockchaininfo")
    if ok:
        try:
            info = json.loads(out)
            data["available"] = True
            data["chain"] = info.get("chain", "?")
            data["blocks"] = info.get("blocks", 0)
            data["headers"] = info.get("headers", 0)
            data["ibd"] = info.get("initialblockdownload", False)
            data["verification"] = info.get("verificationprogress", 0)
            data["peers"] = 0
        except json.JSONDecodeError:
            pass

    out, ok = btc_cmd(cfg, "getnetworkinfo")
    if ok:
        try:
            ni = json.loads(out)
            data["peers"] = ni.get("connections", 0)
        except json.JSONDecodeError:
            pass

    out, ok = btc_cmd(cfg, "-rpcwallet=superscalar_lsp", "getbalance")
    if ok:
        try:
            data["balance"] = float(out)
        except ValueError:
            pass

    out, ok = btc_cmd(cfg, "getmempoolinfo")
    if ok:
        try:
            mi = json.loads(out)
            data["mempool_size"] = mi.get("size", 0)
        except json.JSONDecodeError:
            pass

    return data


def collect_databases(cfg):
    """Read factory, channel, HTLC, and watchtower data from SQLite."""
    data = {"lsp": {}, "client": {}}

    for label, db_path in [("lsp", cfg.lsp_db), ("client", cfg.client_db)]:
        if not db_path or not os.path.exists(str(db_path)):
            data[label]["error"] = "not configured or missing"
            continue

        rows, err = query_db(db_path, "SELECT * FROM factories ORDER BY id DESC LIMIT 5")
        data[label]["factories"] = rows if not err else {"error": err}

        rows, err = query_db(db_path, "SELECT * FROM channels ORDER BY id DESC LIMIT 20")
        data[label]["channels"] = rows if not err else {"error": err}

        rows, err = query_db(db_path, "SELECT * FROM htlcs ORDER BY id DESC LIMIT 20")
        data[label]["htlcs"] = rows if not err else {"error": err}

        rows, err = query_db(
            db_path,
            "SELECT COUNT(*) as cnt FROM old_commitments"
        )
        if not err and rows:
            data[label]["watchtower_count"] = rows[0]["cnt"]
        else:
            data[label]["watchtower_count"] = 0

    return data


def collect_cln(cfg):
    """Gather CLN node info and channel state."""
    data = {"a": {"available": False}, "b": {"available": False}}

    for label, ldir in [("a", cfg.cln_a_dir), ("b", cfg.cln_b_dir)]:
        if not cfg.cln_cli or not ldir:
            continue

        out, ok = cln_cmd(cfg, ldir, "getinfo")
        if ok:
            try:
                info = json.loads(out)
                data[label]["available"] = True
                data[label]["id"] = info.get("id", "?")[:16] + "..."
                data[label]["alias"] = info.get("alias", "")
                data[label]["blockheight"] = info.get("blockheight", 0)
                data[label]["num_peers"] = info.get("num_peers", 0)
                data[label]["num_channels"] = info.get("num_active_channels", 0)
            except json.JSONDecodeError:
                pass

        out, ok = cln_cmd(cfg, ldir, "listpeerchannels")
        if ok:
            try:
                chans = json.loads(out).get("channels", [])
                data[label]["channels"] = []
                for ch in chans:
                    data[label]["channels"].append({
                        "state": ch.get("state", "?"),
                        "total_msat": ch.get("total_msat", 0),
                        "to_us_msat": ch.get("to_us_msat", 0),
                        "peer_id": ch.get("peer_id", "?")[:16] + "...",
                        "short_channel_id": ch.get("short_channel_id", "?"),
                    })
            except json.JSONDecodeError:
                pass

    return data


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def collect_all(cfg):
    """Run all collectors and return unified status dict."""
    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "processes": collect_processes(cfg),
        "bitcoin": collect_bitcoin(cfg),
        "databases": collect_databases(cfg),
        "cln": collect_cln(cfg),
    }


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SuperScalar Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0d1117; color: #c9d1d9; font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
    font-size: 14px; padding: 16px; line-height: 1.5;
}
.header {
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 16px;
}
.header h1 { font-size: 18px; color: #58a6ff; font-weight: 600; }
.header .time { color: #8b949e; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-left: 8px; }
.dot.green { background: #3fb950; }
.dot.red { background: #f85149; }
.dot.yellow { background: #d29922; }
.section {
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px 16px; margin-bottom: 12px;
}
.section-title {
    color: #8b949e; font-size: 11px; text-transform: uppercase;
    letter-spacing: 1px; margin-bottom: 8px;
}
.status-row { display: flex; flex-wrap: wrap; gap: 16px; }
.status-item { display: flex; align-items: center; gap: 6px; }
.status-item .label { color: #8b949e; }
.status-item .value { color: #c9d1d9; font-weight: 600; }
.badge {
    display: inline-block; padding: 1px 8px; border-radius: 12px;
    font-size: 11px; font-weight: 600;
}
.badge.ok { background: #238636; color: #3fb950; }
.badge.down { background: #490202; color: #f85149; }
.badge.warn { background: #3d2e00; color: #d29922; }
table { width: 100%; border-collapse: collapse; }
th { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
     text-align: left; padding: 4px 8px; border-bottom: 1px solid #30363d; }
td { padding: 4px 8px; border-bottom: 1px solid #21262d; font-size: 13px; }
tr:hover td { background: #1c2128; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.hash { color: #79c0ff; font-size: 12px; }
.error-msg { color: #f85149; font-style: italic; }
.empty-msg { color: #484f58; font-style: italic; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 800px) { .grid2 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="header">
    <h1>SuperScalar Dashboard</h1>
    <div class="time">
        Last: <span id="timestamp">--:--:--</span>
        <span id="status-dot" class="dot red"></span>
    </div>
</div>

<div id="content">
    <div class="section"><p class="empty-msg">Loading...</p></div>
</div>

<script>
const REFRESH_MS = 5000;

function badge(ok, labelOk, labelDown) {
    return ok
        ? `<span class="badge ok">${labelOk || 'OK'}</span>`
        : `<span class="badge down">${labelDown || 'DOWN'}</span>`;
}

function formatSats(val) {
    if (val === null || val === undefined) return '—';
    return Number(val).toLocaleString() + ' sat';
}

function formatMsat(val) {
    if (val === null || val === undefined) return '—';
    let n = Number(val);
    if (typeof val === 'string' && val.endsWith('msat')) n = parseInt(val);
    return Math.floor(n / 1000).toLocaleString() + ' sat';
}

function truncHash(h) {
    if (!h || h === '?' || h === 'null') return '—';
    if (h.length > 16) return h.substring(0, 8) + '...' + h.substring(h.length - 8);
    return h;
}

function renderProcesses(procs) {
    const names = {
        bitcoind: 'bitcoind', cln_a: 'CLN-A', cln_b: 'CLN-B',
        bridge: 'Bridge', lsp: 'LSP', client: 'Client'
    };
    let html = '<div class="status-row">';
    for (const [k, label] of Object.entries(names)) {
        html += `<div class="status-item">
            <span class="label">${label}</span> ${badge(procs[k])}
        </div>`;
    }
    html += '</div>';
    return html;
}

function renderBitcoin(btc) {
    if (!btc.available) return '<p class="empty-msg">Bitcoin node unavailable</p>';
    let html = '<div class="status-row">';
    html += `<div class="status-item"><span class="label">Height</span>
             <span class="value">${Number(btc.blocks || 0).toLocaleString()}</span></div>`;
    html += `<div class="status-item"><span class="label">Chain</span>
             <span class="value">${btc.chain || '?'}</span></div>`;
    if (btc.balance !== undefined)
        html += `<div class="status-item"><span class="label">Balance</span>
                 <span class="value">${btc.balance} BTC</span></div>`;
    html += `<div class="status-item"><span class="label">Peers</span>
             <span class="value">${btc.peers || 0}</span></div>`;
    if (btc.mempool_size !== undefined)
        html += `<div class="status-item"><span class="label">Mempool</span>
                 <span class="value">${btc.mempool_size} tx</span></div>`;
    if (btc.ibd)
        html += `<div class="status-item"><span class="badge warn">IBD</span>
                 <span class="value">${(btc.verification * 100).toFixed(1)}%</span></div>`;
    html += '</div>';
    return html;
}

function renderFactory(factories) {
    if (!factories || factories.error) return `<p class="error-msg">${factories?.error || 'unavailable'}</p>`;
    if (!factories.length) return '<p class="empty-msg">No factories</p>';
    let html = '<table><tr><th>ID</th><th>Participants</th><th class="num">Amount</th><th>Funding TXID</th><th>State</th></tr>';
    for (const f of factories) {
        html += `<tr>
            <td>${f.id}</td>
            <td>${f.n_participants || '?'}</td>
            <td class="num">${formatSats(f.funding_amount)}</td>
            <td class="hash">${truncHash(f.funding_txid)}</td>
            <td>${f.state || '?'}</td>
        </tr>`;
    }
    html += '</table>';
    return html;
}

function renderChannels(channels) {
    if (!channels || channels.error) return `<p class="error-msg">${channels?.error || 'unavailable'}</p>`;
    if (!channels.length) return '<p class="empty-msg">No channels</p>';
    let html = '<table><tr><th>ID</th><th class="num">Local</th><th class="num">Remote</th><th class="num">Commits</th><th class="num">HTLCs</th></tr>';
    for (const c of channels) {
        html += `<tr>
            <td>${c.id}</td>
            <td class="num">${formatSats(c.local_amount)}</td>
            <td class="num">${formatSats(c.remote_amount)}</td>
            <td class="num">${c.commitment_number ?? '?'}</td>
            <td class="num">${c.htlc_count ?? '—'}</td>
        </tr>`;
    }
    html += '</table>';
    return html;
}

function renderHTLCs(htlcs) {
    if (!htlcs || htlcs.error) return '';
    if (!htlcs.length) return '';
    let html = '<table><tr><th>Ch</th><th>Dir</th><th class="num">Amount</th><th>State</th><th>Payment Hash</th></tr>';
    for (const h of htlcs) {
        html += `<tr>
            <td>${h.channel_id}</td>
            <td>${h.direction || '?'}</td>
            <td class="num">${formatSats(h.amount)}</td>
            <td>${h.state || '?'}</td>
            <td class="hash">${truncHash(h.payment_hash)}</td>
        </tr>`;
    }
    html += '</table>';
    return html;
}

function renderCLN(cln) {
    let html = '<div class="grid2">';
    for (const [key, label] of [['a', 'Node A (plugin)'], ['b', 'Node B (vanilla)']]) {
        const n = cln[key];
        html += '<div>';
        html += `<div class="section-title" style="margin-top:4px">${label}</div>`;
        if (!n || !n.available) {
            html += '<p class="empty-msg">Unavailable</p>';
        } else {
            html += `<div class="status-row" style="margin-bottom:6px">
                <div class="status-item"><span class="label">ID</span>
                    <span class="value hash">${n.id || '?'}</span></div>
                <div class="status-item"><span class="label">Height</span>
                    <span class="value">${n.blockheight || '?'}</span></div>
                <div class="status-item"><span class="label">Peers</span>
                    <span class="value">${n.num_peers || 0}</span></div>
            </div>`;
            if (n.channels && n.channels.length) {
                html += '<table><tr><th>State</th><th class="num">Capacity</th><th class="num">Local</th><th>Peer</th><th>SCID</th></tr>';
                for (const ch of n.channels) {
                    html += `<tr>
                        <td>${ch.state}</td>
                        <td class="num">${formatMsat(ch.total_msat)}</td>
                        <td class="num">${formatMsat(ch.to_us_msat)}</td>
                        <td class="hash">${ch.peer_id}</td>
                        <td>${ch.short_channel_id || '—'}</td>
                    </tr>`;
                }
                html += '</table>';
            } else {
                html += '<p class="empty-msg">No channels</p>';
            }
        }
        html += '</div>';
    }
    html += '</div>';
    return html;
}

function render(data) {
    document.getElementById('timestamp').textContent = data.timestamp || '--:--:--';
    const dot = document.getElementById('status-dot');
    const allUp = data.processes && Object.values(data.processes).every(v => v);
    const anyUp = data.processes && Object.values(data.processes).some(v => v);
    dot.className = 'dot ' + (allUp ? 'green' : anyUp ? 'yellow' : 'red');

    const db = data.databases || {};
    const lsp = db.lsp || {};
    const client = db.client || {};

    let html = '';

    // System processes
    html += `<div class="section">
        <div class="section-title">System</div>
        ${renderProcesses(data.processes || {})}
    </div>`;

    // Bitcoin network
    html += `<div class="section">
        <div class="section-title">Bitcoin Network</div>
        ${renderBitcoin(data.bitcoin || {})}
    </div>`;

    // Factory
    html += `<div class="section">
        <div class="section-title">Factories (LSP DB)</div>
        ${renderFactory(lsp.factories)}
    </div>`;

    // Channels
    html += `<div class="section">
        <div class="section-title">Channels (LSP DB)</div>
        ${renderChannels(lsp.channels)}
    </div>`;

    // HTLCs
    const htlcHtml = renderHTLCs(lsp.htlcs);
    if (htlcHtml) {
        html += `<div class="section">
            <div class="section-title">HTLCs (LSP DB)</div>
            ${htlcHtml}
        </div>`;
    }

    // CLN nodes
    html += `<div class="section">
        <div class="section-title">Lightning Network (CLN)</div>
        ${renderCLN(data.cln || {})}
    </div>`;

    // Watchtower
    const wtLsp = lsp.watchtower_count || 0;
    const wtClient = client.watchtower_count || 0;
    html += `<div class="section">
        <div class="section-title">Watchtower</div>
        <div class="status-row">
            <div class="status-item"><span class="label">LSP old commitments</span>
                <span class="value">${wtLsp}</span></div>
            <div class="status-item"><span class="label">Client old commitments</span>
                <span class="value">${wtClient}</span></div>
        </div>
    </div>`;

    document.getElementById('content').innerHTML = html;
}

async function refresh() {
    try {
        const resp = await fetch('/api/status');
        if (resp.ok) {
            const data = await resp.json();
            render(data);
        }
    } catch (e) {
        // Network error — leave last state
    }
}

refresh();
setInterval(refresh, REFRESH_MS);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard HTML and status API."""

    cfg = None  # set before server starts

    def log_message(self, fmt, *args):
        # Suppress default request logging to keep terminal clean
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif self.path == "/api/status":
            data = collect_all(self.cfg)
            payload = json.dumps(data, default=str)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
        else:
            self.send_error(404)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SuperScalar Web Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default 8080)")
    parser.add_argument("--lsp-db", default=None, help="Path to LSP SQLite database")
    parser.add_argument("--client-db", default=None, help="Path to client SQLite database")
    parser.add_argument("--btc-cli", default="bitcoin-cli", help="Path to bitcoin-cli")
    parser.add_argument("--btc-network", default="signet", help="Bitcoin network (signet/regtest/testnet)")
    parser.add_argument("--btc-rpcuser", default=None, help="Bitcoin RPC username")
    parser.add_argument("--btc-rpcpassword", default=None, help="Bitcoin RPC password")
    parser.add_argument("--cln-cli", default="lightning-cli", help="Path to lightning-cli")
    parser.add_argument("--cln-a-dir", default=None, help="CLN Node A lightning-dir")
    parser.add_argument("--cln-b-dir", default=None, help="CLN Node B lightning-dir")

    args = parser.parse_args()
    cfg = Config(args)
    DashboardHandler.cfg = cfg

    server = HTTPServer(("0.0.0.0", cfg.port), DashboardHandler)
    print(f"SuperScalar Dashboard running at http://localhost:{cfg.port}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
