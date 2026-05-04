# GuacTunnel

Turns Apache Guacamole's clipboard channel (CLIPRDR) into a bidirectional data
tunnel — exposing a local SOCKS5 proxy that forwards traffic into an internal
network via an RDP session where only the browser/clipboard is available.

```
Operator machine          Guacamole server          Windows RDP target
─────────────────         ─────────────────         ─────────────────
SOCKS5 app                                           Internal hosts
    │                                                      │
client.py ─── WebSocket (Guac protocol) ─── CLIPRDR ─── agent.ps1
              clipboard GT:… frames                 polls clipboard
```

> **Use only in authorized environments.** This tool is for security research,
> red team engagements, and lab testing where you own or have explicit written
> permission for all systems involved.

---

## Architecture

| Component | File | Language |
|-----------|------|----------|
| Operator client | `client.py` | Python 3, asyncio |
| Target agent | `agent.ps1` | PowerShell 5.1+ |
| Tunnel protocol | text-over-clipboard | — |

### Tunnel frame format

```
GT:<seq>:<chan_id>:<ctrl>:<base64_payload>
```

| Field | Description |
|-------|-------------|
| `GT` | Magic prefix |
| `seq` | Monotonically increasing, used for dedup |
| `chan_id` | Multiplexed connection ID |
| `ctrl` | `CONNECT` / `CONNECTED` / `DATA` / `CLOSE` / `PING` / `PONG` |
| `base64_payload` | Raw bytes, base64-encoded |

---

## Requirements

### Operator side (your machine)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install websockets aiohttp
```

Python 3.10+ recommended.

### Target side (Windows RDP session)

PowerShell 5.1+ — ships with every Windows 10/11 and Server 2016+ install.
No extra dependencies.

---

## Quick Start

### Step 1 — Get the Guacamole connection ID

Open Guacamole in a browser, right-click your RDP connection → **Settings** or
look at the URL when the connection is active. The numeric ID appears as
`#/client/<id>`. Alternatively, `client.py` will print all available connections
after authentication.

```bash
python client.py \
  --url  http://10.0.10.2:8080 \
  --user guacadmin \
  --password guacadmin \
  --conn-id 1          # will list connections and exit if ID is wrong
```

Sample output:

```
[INFO] Authenticated, token=c8f3a1b2…
[INFO] Available connections:
[INFO]   [1] Win10-Internal (rdp)
[INFO]   [3] Server2019 (rdp)
```

### Step 2 — Start the agent on the target

In the RDP session (via Guacamole browser or any other path), open a PowerShell
window and run:

```powershell
# Allow running local scripts if blocked
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\agent.ps1
# or with debug output:
.\agent.ps1 -Debug -PollMs 100
```

Expected output:

```
GuacTunnel agent started (poll=150ms)
Waiting for operator connection…
```

### Step 3 — Start the operator client

```bash
python client.py \
  --url      http://10.0.10.2:8080 \
  --user     guacadmin \
  --password guacadmin \
  --conn-id  1 \
  --socks    127.0.0.1:1080
```

Expected output:

```
[INFO] Authenticated, token=c8f3a1b2…
[INFO] WebSocket connected
[INFO] SOCKS5 proxy listening on 127.0.0.1:1080
```

### Step 4 — Use the SOCKS5 proxy

```bash
# curl
curl --socks5 127.0.0.1:1080 http://192.168.1.100/

# nmap through proxychains
proxychains nmap -sT -Pn 192.168.1.0/24 -p 80,443,445

# SSH
ssh -o ProxyCommand='ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p' user@192.168.1.50

# Browser (Firefox → Settings → Proxy → Manual → SOCKS5 127.0.0.1:1080)
```

---

## Parameters

### client.py

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Guacamole base URL |
| `--user` | — | Username |
| `--password` | — | Password |
| `--conn-id` | — | Connection ID (numeric) |
| `--socks` | `127.0.0.1:1080` | Local SOCKS5 bind address |
| `--debug` | off | Verbose logging |

### agent.ps1

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-PollMs` | `150` | Clipboard poll interval in milliseconds |
| `-MaxChunk` | `800` | Max payload bytes per frame |
| `-Debug` | off | Print every frame sent/received |

---

## Performance Characteristics

| Metric | Approximate value |
|--------|------------------|
| Round-trip latency | 300 – 800 ms |
| Effective throughput | 1 – 8 KB/s |
| Concurrent channels | Limited by poll rate |

**Good for:** interactive shells (`ssh`, `netcat`), port scanning, small file
transfers, SMB enumeration.

**Not suitable for:** web browsing, large file transfers, video/audio streams.

---

## Troubleshooting

### Clipboard not syncing

- Verify Guacamole has clipboard integration enabled (Admin → Connection →
  Parameters → **Enable clipboard integration**).
- Check that the RDP server policy allows clipboard redirection
  (`gpedit.msc` → Computer Configuration → Administrative Templates →
  Windows Components → Remote Desktop Services → **Do not allow clipboard
  redirection** must be **Disabled**).

### Authentication fails

- Confirm the URL path — some deployments use `/guacamole`, others just `/`.
  `client.py` tries the supplied URL first and then the common alternate path.
  The provided lab Guacamole endpoint is rooted at `http://10.0.10.2:8080`.
- Check Guacamole logs: `docker logs <container>` or
  `/var/log/tomcat*/catalina.out`.

### agent.ps1 clipboard errors

The script requires an STA (Single-Threaded Apartment) thread for
`System.Windows.Forms.Clipboard`. If you see errors, launch explicitly:

```powershell
powershell -STA -File .\agent.ps1
```

### Connection IDs

Guacamole connection IDs are found via the REST API:

```bash
curl -s "http://10.0.10.2:8080/guacamole/api/session/data/postgresql/connections?token=<token>" | python -m json.tool
```

---

## Detection Notes (Blue Team)

If you are a defender evaluating this technique:

- Look for unusually high clipboard event frequency in Guacamole audit logs.
- Clipboard blobs matching `^GT:\d+:\d+:(CONNECT|DATA|CLOSE|PING):` are tunnel
  frames — a Sigma rule on Guacamole's event log or a transparent proxy
  inspecting clipboard opcodes can catch this.
- Baseline normal clipboard sizes; tunnel frames are typically 100–1200 chars.
- Network-level: even if the tunnel is active, all traffic appears as normal
  Guacamole WebSocket to/from the browser — detection must happen at the
  Guacamole server layer.

---

## License

MIT — research / educational use. Use responsibly.
