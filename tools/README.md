# OpcUaTrap — Attack Simulation & Testing

Tools for testing the honeypot from an attacker's perspective. All scripts in this directory connect to the honeypot as an OPC UA client and perform realistic ICS attack actions — generating threat events and log entries you can review.

---

## Setup

All dependencies are managed by [uv](https://github.com/astral-sh/uv). No separate Python install required.

```bash
# Install uv (Windows)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Install uv (Linux/macOS)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Python 3.12 + asyncua (one command)
cd c:\Tools\OpcUaTrap\tools
uv sync

# Verify
uv run python -c "from asyncua import Client; print('asyncua OK')"
```

---

## attack_simulation.py

Simulates a full ICS attack chain against the oil-gas profile. Each phase is independent and can be run separately or all together.

### Usage

```bash
# Run all phases in sequence
uv run python attack_simulation.py

# Run a single phase
uv run python attack_simulation.py --phase recon
uv run python attack_simulation.py --phase credential
uv run python attack_simulation.py --phase safety
uv run python attack_simulation.py --phase manipulate
uv run python attack_simulation.py --phase cover
uv run python attack_simulation.py --phase exfil

# Target a remote host
uv run python attack_simulation.py --host 192.168.1.50
uv run python attack_simulation.py --host 192.168.1.50 --port 4841

# Combine flags
uv run python attack_simulation.py --host 10.0.0.5 --port 4840 --phase recon
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Honeypot IP address |
| `--port` | `4840` | Honeypot port |
| `--phase` | *(all)* | Run a specific phase only. Values: `recon`, `credential`, `safety`, `manipulate`, `cover`, `exfil` |

---

## Attack Phases

### Phase 1 — RECON

**What it does:** Browses the full address space, reads site identity nodes, and identifies critical nodes.

**Threat rules triggered:**
- `AddressSpaceEnumeration` — >100 browse operations (+10)
- `BulkReadExfil` — reads many nodes in one request (+10)
- `CriticalTagRead` — reads ESD status, pressure setpoints (+5 each)

**What to look for in logs:**
```
[BROWSE] AddressSpaceEnumeration detected (143 ops) | threatScore=10
[READ] BulkReadExfil — 28 nodes read in single request | threatScore=20
```

---

### Phase 2 — CREDENTIAL

**What it does:** Tries all honeytoken credentials (operator, admin, engineer) plus a few wrong-password attempts to simulate a credential spray.

**Threat rules triggered:**
- `HoneytokenLogin` — each honeytoken used (+15)
- `FailedAuth` — wrong password attempts (+5 each)
- `CredentialSpraying` — 3+ distinct usernames from same IP (+15)

**What to look for in logs:**
```
[AUTH] HoneytokenLogin — username=admin | severity=CRITICAL | threatScore=15
[AUTH] CredentialSpraying detected from 127.0.0.1 (4 usernames) | +15
```

---

### Phase 3 — SAFETY OFF

**What it does:** Writes to ESD shutdown valves and calls the ESD trigger method — simulating an attacker disabling safety systems before causing damage.

**Threat rules triggered:**
- `Write_Critical` — SDV_701_POS, SDV_702_POS (+25 each)
- `WriteEscalation` — 3+ writes in session (+15)
- `MethodCall_Critical` — ESD_CMD_TRIGGER (+30)

**What to look for in logs:**
```
[WRITE-ATTEMPT] [CRITICAL] node=SDV_701_POS value=False | threatScore=58
[METHOD-CALL] [CRITICAL] ESD_CMD_TRIGGER called | threatScore=88 rule=MethodCall_Critical
```

**Real-world equivalent:** In the 2015 Ukraine power grid attack, attackers disabled protection systems before manually tripping breakers. Disabling ESD before manipulating setpoints follows the same playbook.

---

### Phase 4 — MANIPULATE

**What it does:** Writes dangerous values to critical process nodes — separator pressure setpoints, pipeline valves, pump commands, and alarm thresholds.

**Nodes targeted:**

| Node | Dangerous Value | Real-world consequence |
|------|-----------------|------------------------|
| `SEP_HP_201_PSP_2001` | 9999 PSI | Vessel overpressure → rupture |
| `SEP_LP_202_PSP_2001` | 5 PSI | Underpressure → process upset |
| `PMP_XFER_401_CMD_STOP` | True | Stop transfer pump → tank overflow |
| `PL_EXPORT_601_XV` | False | Close pipeline valve → upstream overpressure |
| `TK_OIL_301_LAHH` | 99.9% | Raise alarm threshold → disable high-level protection |

**Threat rules triggered:**
- `Write_Critical` on each node (+25 each)
- `WriteEscalation` if not already triggered (+15)

**What to look for in logs:**
```
[WRITE-ATTEMPT] [CRITICAL] node=SEP_HP_201_PSP_2001 value=9999 classification=Critical | threatScore=HIGH
```

---

### Phase 5 — COVER

**What it does:** Writes the original safe values back to all manipulated nodes — simulating an attacker attempting to hide evidence of the intrusion.

**Threat rules triggered:**
- `Write_Critical` still triggered (values still classified regardless of content)

**What to look for:** The cover phase will still score the same writes as critical — the honeypot cannot distinguish "restoring" from "attacking." This is intentional: any write to a critical tag is suspicious regardless of value.

---

### Phase 6 — EXFIL

**What it does:** Reads all process variables across the entire address space and requests 30 days of historical data — simulating data theft before or after sabotage.

**Threat rules triggered:**
- `BulkReadExfil` — reads all nodes (+10)
- `DataExfiltration` — >1000 history points read (+10)

**What to look for in logs:**
```
[HISTORY-READ] DataExfiltration — 8640 points read (30d) | threatScore=HIGH
```

---

## Session Summary

At the end of a full run, the honeypot logs a session summary when the connection closes:

```
[SESSION-END] session=a3f7c2d1 src=127.0.0.1 duration=12.4s
  browse=143 read=89 write=8 calls=1
  threatScore=97 severity=CRITICAL
  rules=[AddressSpaceEnumeration, HoneytokenLogin, CredentialSpraying,
         Write_Critical, WriteEscalation, MethodCall_Critical, DataExfiltration]
```

A full run of all phases should produce a threat score near 100 and trigger most detection rules.

---

## Reviewing Logs

After running the simulation, inspect the NDJSON log:

```bash
# View all events from this session
cat logs/opcuatrap-$(date +%Y-%m-%d).jsonl | python -m json.tool | head -100

# Filter write attempts only
grep "WriteAttempt" logs/opcuatrap-*.jsonl

# Filter CRITICAL severity events
grep '"severity":"CRITICAL"' logs/opcuatrap-*.jsonl

# Filter method calls
grep "MethodCall" logs/opcuatrap-*.jsonl

# View session summaries with threat scores
grep "SessionClosed" logs/opcuatrap-*.jsonl

# Count events by operation type
grep -o '"operation":"[^"]*"' logs/opcuatrap-*.jsonl | sort | uniq -c | sort -rn
```

---

## Manual Testing with UaExpert

[UaExpert](https://www.unified-automation.com/products/development-tools/uaexpert.html) is a free GUI OPC UA client — useful for interactive demos.

1. Connect to `opc.tcp://127.0.0.1:4840`
2. Accept the server certificate
3. Browse: `Objects → [Facility Name] → [Section]`
4. Drag a variable into the **Data Access View** pane to monitor live values
5. Double-click the **Value** column to write a new value

### Critical nodes to write to (oil-gas profile)

| Section | Node ID | Safe Value | Dangerous Value | Effect |
|---------|---------|------------|-----------------|--------|
| Separators | `SEP_HP_201_PSP_2001` | 1050 | 9999 | Overpressure |
| Separators | `SEP_LP_202_PSP_2001` | 150 | 5 | Underpressure |
| Safety Systems | `SDV_701_POS` | true | false | Close shutdown valve |
| Safety Systems | `ESD_STATUS` | 0 | 1 | Force ESD unhealthy |
| Pump Stations | `PMP_XFER_401_CMD_STOP` | false | true | Stop transfer pump |
| Pipelines | `PL_EXPORT_601_XV` | true | false | Close block valve |
| Tank Farm | `TK_OIL_301_LAHH` | 92 | 99.9 | Disable high-level alarm |

### Critical nodes to write to (power-grid profile)

| Section | Node ID | Dangerous Value | Effect |
|---------|---------|-----------------|--------|
| HV Bus | `CB_138KV_MAIN_CMD_OPEN` | true | Trip main 138kV breaker — blackout |
| Transformers | `TX_001_TAP_CMD_RAISE` | true | Raise LTC tap — overvoltage |
| Feeders | `FDR_004_CB_CMD_OPEN` | true | Trip hospital feeder — critical load lost |
| Protection | `REL_OC_001_ENABLED` | false | Disable overcurrent relay — allows fault cascade |
| Protection | `REL_DIFF_001_ENABLED` | false | Disable transformer differential — transformer unprotected |
| Safety | `LOCKOUT_RLY_001_CMD_TRIP` | *(method call)* | Trip all breakers via lockout relay |

---

## Vulnerability Scanning with OpalOPC

[OpalOPC](https://opalopc.com) is an OPC UA security scanner that checks for misconfigurations and known vulnerabilities.

```bash
# Install
dotnet tool install -g OpalOPC

# Scan the honeypot
OpalOPC -t opc.tcp://127.0.0.1:4840 -o report.html

# Open the report
start report.html       # Windows
xdg-open report.html   # Linux
```

OpalOPC will report findings like anonymous authentication, missing security policies, and open endpoints — all intentional in some profiles.

---

## Managing the Honeypot

```bash
# Start (from repo root)
dotnet run --project src/OpcUaTrap

# Start with a specific profile
dotnet run --project src/OpcUaTrap -- --profile power-grid

# Kill a running instance (Windows)
taskkill /F /IM OpcUaTrap.exe

# Kill and rebuild
taskkill /F /IM OpcUaTrap.exe
dotnet build src/OpcUaTrap/OpcUaTrap.csproj
dotnet run --project src/OpcUaTrap
```
