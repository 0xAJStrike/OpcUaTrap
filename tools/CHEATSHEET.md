# OpcUaTrap Attack Simulation — Cheatsheet

Target: `127.0.0.1:4840` (OpcUaTrap honeypot)

All commands run from: `c:\Tools\OpcUaTrap\tools\`

---

## Setup (Windows Terminal / PowerShell)

```powershell
# Install uv (if not already installed)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Navigate to tools directory
cd c:\Tools\OpcUaTrap\tools

# Install Python 3.12 + dependencies (one command, uv handles everything)
uv sync

# Verify it works
uv run python -c "from asyncua import Client; print('asyncua ready')"
```

> **Note:** `uv sync` reads the `pyproject.toml` in the tools folder and installs Python 3.12 + asyncua automatically. No need to install Python separately.

---

## Attack Simulation Script

```bash
# Run ALL phases (full attack chain: recon -> safety -> manipulate -> cover -> exfil)
uv run python attack_simulation.py

# Run individual phases
uv run python attack_simulation.py --phase recon
uv run python attack_simulation.py --phase safety
uv run python attack_simulation.py --phase manipulate
uv run python attack_simulation.py --phase cover
uv run python attack_simulation.py --phase exfil

# Target a remote host
uv run python attack_simulation.py --host 192.168.1.50 --port 4840
uv run python attack_simulation.py --host 10.0.0.5 --phase recon
```

---

## UaExpert (GUI)

1. Connect to `opc.tcp://127.0.0.1:4840`
2. Browse: `Objects -> PetroVista Central Processing Facility -> [section]`
3. Drag a variable node into the center **Data Access View**
4. Double-click the **Value** cell to write a new value

### Critical nodes to test writes on:

| Node Path | Node ID | Test Value | Effect |
|-----------|---------|------------|--------|
| Separators > HP Separator > Pressure Setpoint | `SEP_HP_201_PSP_2001` | `9999` | Overpressure |
| Separators > LP Separator > Pressure Setpoint | `SEP_LP_202_PSP_2001` | `5` | Underpressure |
| Safety Systems > ESD > ESD Status | `ESD_STATUS` | `1` | Force unhealthy |
| Safety Systems > ESD > Shutdown Valve 701 | `SDV_701_POS` | `false` | Close valve |
| Pump Stations > Transfer Pump 401 > Stop Command | `PMP_XFER_401_CMD_STOP` | `true` | Stop pump |
| Pipelines > Export Pipeline > Block Valve | `PL_EXPORT_601_XV` | `false` | Close valve |
| Tank Farm > Tank 301 > High-High Alarm | `TK_OIL_301_LAHH` | `99.9` | Disable alarm |

---

## Checking Honeypot Logs

```bash
# Live console output (run from OpcUaTrap directory)
cd c:\Tools\OpcUaTrap\src\OpcUaTrap && dotnet run

# View latest NDJSON log entries
tail -20 c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-2026-02-15.jsonl

# Filter for write attempts only
grep "WriteAttempt" c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-*.jsonl

# Filter for CRITICAL alerts
grep "CRITICAL" c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-*.jsonl

# Filter for method calls (ESD trigger, etc.)
grep "MethodCall" c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-*.jsonl

# View session summaries (shows threat scores and triggered rules)
grep "SessionClosed" c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-*.jsonl

# Count events by type
grep -o '"operation":"[^"]*"' c:\Tools\OpcUaTrap\src\OpcUaTrap\logs\opcuatrap-*.jsonl | sort | uniq -c | sort -rn
```

---

## Managing the Honeypot Server

```bash
# Start the server
cd c:\Tools\OpcUaTrap\src\OpcUaTrap && dotnet run

# Kill existing instance (if port 4840 is busy)
taskkill /F /IM OpcUaTrap.exe

# Rebuild after LibUA changes
taskkill /F /IM OpcUaTrap.exe
cd c:\Tools\OpcUaTrap\src\OpcUaTrap && dotnet build
```
