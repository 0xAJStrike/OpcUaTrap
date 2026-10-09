# OpcUaTrap

A **high-interaction OPC UA honeypot** for ICS/SCADA environments. Built on [LibUA](https://github.com/nauful/libua) — a full OPC UA Binary stack, not a protocol emulator. Simulates realistic industrial control systems across multiple industry profiles with live process values, comprehensive threat detection, and SIEM-ready logging.

*Built by [0xAJStrike](https://github.com/0xAJStrike).*

📄 **Talk:** [*Read the Plant like a Blueprint*](docs/Read_the_Plant_like_Blueprint.pdf) — the SecTor 2026 presentation this tool was built for (OPC UA attack surface, honeypot design, and a live demo).

## Why High Interaction?

Most ICS honeypots (Conpot, GRFICSv2) offer partial protocol emulation. OpcUaTrap implements the full OPC UA Binary protocol — secure channel negotiation, session lifecycle, subscriptions, history, and all service sets. Real exploit tools and scanners (OpalOPC, Nmap OPC UA scripts) interact with it as they would a production system.

| | Low | Medium | OpcUaTrap |
|--|-----|--------|-----------|
| Protocol | Banner only | Partial emulation | Full real stack |
| Session state | None | Basic | Full lifecycle |
| Address space | Static / empty | Handful of nodes | 100–130 realistic nodes |
| Subscriptions | No | No | Yes — live data pushed |
| Exploit resilience | Crashes | Partial | Survives full frameworks |

---

## Features

- **Three industry profiles** — oil & gas, water treatment, power grid — each with 100–130 live process nodes
- **Full OPC UA protocol** — browse, read, write, call, history read, subscriptions, 4 security endpoints
- **Live simulation** — 1-second tick, gaussian noise, mean-reverting drift, tank fill/drain dynamics
- **12 threat detection rules** — per-session scoring (0–100), honeytoken detection, enumeration detection, bulk exfil, credential spraying, and more
- **Anti-fingerprinting** — fake vendor identity, response timing jitter, realistic error codes, uptime randomization
- **Pluggable SIEM logging** — NDJSON (always on), syslog RFC 5424, ArcSight CEF, HTTP webhooks, Elasticsearch direct ingest
- **Profile-driven hardening** — authentication policy, account lockout, service restrictions — all configurable per JSON profile

---

## Quick Start

### Run with Docker (fastest)

```bash
docker run -d --name opcuatrap -p 4840:4840 \
  -e OPCUATRAP_PROFILE=oil-gas \
  -v opcuatrap-data:/data \
  ghcr.io/0xajstrike/opcuatrap:latest
```

The honeypot is now live on `opc.tcp://<host>:4840`. Switch the facility with
`-e OPCUATRAP_PROFILE=water-treatment` (or `power-grid`). The image is multi-arch
(amd64 + arm64, so it runs on a Raspberry Pi too), non-root, and persists its
certificate and NDJSON logs to the `opcuatrap-data` volume. Full Docker details
(Compose, all env vars) are under [Deployment → Docker](#docker-recommended).

### Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) or newer — required to **build** from source, because the bundled LibUA multi-targets up to `net9.0`. The honeypot itself runs on the **.NET 8** runtime. *(Not needed if you use Docker — the image builds everything internally.)*
- **LibUA** — the OPC UA stack. OpcUaTrap builds against a lightly modified fork
  ([0xAJStrike/LibUA](https://github.com/0xAJStrike/LibUA), a fork of
  [nauful/LibUA](https://github.com/nauful/LibUA)) that adds defense-in-depth
  limits for several OPC UA CVEs plus optional honeypot deception responses.

  Clone both repositories **side by side** under a common parent directory:

  ```bash
  git clone https://github.com/0xAJStrike/OpcUaTrap.git
  git clone https://github.com/0xAJStrike/LibUA.git
  ```

  Expected layout (OpcUaTrap references `../../../LibUA/NET-Core/LibUA/LibUA.csproj`
  relative to its project file, i.e. LibUA sits next to OpcUaTrap):

  ```
  parent/
  ├── OpcUaTrap/   # this repo
  └── LibUA/       # the fork, cloned as a sibling
  ```

### Build

```bash
dotnet build src/OpcUaTrap/OpcUaTrap.csproj
```

### Run

```bash
# Oil & gas profile (default, port 4840)
dotnet run --project src/OpcUaTrap

# Water treatment profile
dotnet run --project src/OpcUaTrap -- --profile water-treatment

# Power grid profile
dotnet run --project src/OpcUaTrap -- --profile power-grid

# Custom port
dotnet run --project src/OpcUaTrap -- --port 7718

# Custom log directory
dotnet run --project src/OpcUaTrap -- --log-dir /var/log/opcuatrap
```

The server starts in ~400ms and begins simulating process values immediately.

---

## Industry Profiles

Profiles are JSON files in `src/OpcUaTrap/Profiles/`. Each defines the facility identity, full address space, tag classification, simulation rules, and hardening config.

| Profile | `--profile` | Facility | Nodes | Vendor Identity |
|---------|-------------|----------|-------|-----------------|
| `oil-gas` | *(default)* | PetroVista Central Processing Facility | ~120 | Schneider Electric SCADAPack 57x |
| `water-treatment` | `water-treatment` | Cascade Municipal Water Treatment Plant | ~100 | Rockwell Automation ControlLogix |
| `power-grid` | `power-grid` | Ridgeline 138kV Transmission Substation | ~130 | ABB RTU560 |

### Oil & Gas — Address Space

```
PetroVista Central Processing Facility/
  Site_Information/
  Wellheads/            WH_101 – WH_104  (pressure, temp, flow, choke position)
  Separators/           SEP_HP_201, SEP_LP_202  (pressure, level, setpoints)
  TankFarm/             TK_OIL_301, TK_OIL_302  (level, alarms, inlet/outlet valves)
  PumpStations/         PMP_XFER_401  (speed, discharge pressure, start/stop commands)
  CompressorStation/    COMP_501  (RPM, vibration, discharge temp, load %)
  Pipelines/            PL_EXPORT_601  (pressure, flow, block valve)
  SafetySystems/        ESD  (status, shutdown valves, trigger/reset methods)
                        FireAndGas  (gas detectors %LEL, flame detectors)
  Utilities/            Instrument air, fuel gas, power generation
```

### Water Treatment — Address Space

```
Cascade Municipal Water Treatment Plant/
  Site_Information/
  RawWaterIntake/       Flow, turbidity, pH, temp, intake pumps, isolation valve
  Coagulation/          Rapid mix, alum dose rate and setpoint
  Flocculation/         Slow mixer, polymer feed rate and setpoint
  Sedimentation/        Basin levels, turbidity, sludge blanket, scrapers
  Filtration/           4 filters — differential pressure, turbidity, backwash status
  Disinfection/         Primary/secondary chlorination, ammonia feed (chloramine)
  ClearWell/            Finished water storage — level, turbidity, pH, Cl2 residual
  Distribution/         High-service pumps, pressure zones, elevated tank level
  SafetySystems/        ESD, chlorine/ammonia leak detectors and isolation valves
  Utilities/            Power, backup generator, SCADA system status
```

### Power Grid — Address Space

```
Ridgeline 138kV Transmission Substation/
  Site_Information/
  HV_Bus (138kV)/       Phase voltages, line voltage, frequency, MW/MVAR/PF
                        CB-101 main breaker, CB-102 bus tie (status, SF6, trip/close)
  Transformers/         T1 & T2, 50 MVA each — voltage, current, oil temp, winding temp,
                        LTC tap position (1–17), loading %, tap raise/lower commands
  LV_Bus (13.8kV)/      Bus voltage, frequency, total MW/MVAR/PF
  Feeders/              F1 Residential, F2 Industrial, F3 Commercial, F4 Hospital/Critical
                        (current, MW, MVAR, recloser ops, trip/close commands)
  CapacitorBanks/       CAP-1 (energized), CAP-2 (standby) — 5 MVAR each
  ProtectionRelays/     SEL-351S overcurrent, SEL-387 differential, SEL-421 distance
                        All have _ENABLED flag — disabling them is a critical attack target
  DC_System/            125VDC station battery — voltage, SOC, charger status, ground fault
  SafetySystems/        86 Lockout relay (trip-all-breakers), ESD
  SCADA_RTU/            ABB RTU560 status, EMS comm link, historian connection
```

---

## Security Endpoints

| # | Policy | Mode |
|---|--------|------|
| 1 | None | None |
| 2 | Basic256Sha256 | Sign |
| 3 | Basic256Sha256 | SignAndEncrypt |
| 4 | Aes128_Sha256_RsaOaep | SignAndEncrypt |

Profiles can restrict which policies are offered via the `hardening.authentication.allowedSecurityPolicies` config.

---

## Honeytoken Credentials

Pre-planted weak credentials that trigger alerts on use. Defined in `appsettings.json`.

| Username | Password | Alert Level |
|----------|----------|-------------|
| `operator` | `op3rator!` | HIGH |
| `admin` | `admin123` | CRITICAL |
| `engineer` | `Welcome1` | CRITICAL |
| `readonly` | `readonly` | MEDIUM |
| `svc_historian` | `h1st0rian` | HIGH |

Authentication behaviour varies by profile — oil-gas uses `selective` mode (rejects unknown credentials), water-treatment uses `accept-all`.

---

## Honeypot Behaviour

| Operation | Response | Logging |
|-----------|----------|---------|
| Browse | Full address space returned | Detects enumeration >100 ops |
| Read | Returns live simulated values | Silent unless bulk (>20 nodes) or critical tag |
| Write | Returns `Good` — **value reverts in 1 second** | Logged + threat scored by tag classification |
| Call (ESD/Lockout methods) | Returns `Good` — **nothing happens** | CRITICAL alert, +30 threat score |
| History Read | Returns 30 days of sine-wave data | Detects bulk exfil >1000 points |
| Subscribe (critical tag) | Returns real subscription | CRITICAL alert, +20 threat score |
| Honeytoken login | Session accepted | HIGH/CRITICAL alert |
| Anonymous auth | Accepted or rejected per profile | Logged |

---

## Threat Detection

### Tag Classification

Tags are classified per profile. Classification drives the write threat score.

| Classification | Example Tags | Write Score |
|---|---|---|
| **Critical** | ESD_*, SDV_*, *_CMD_*, *_PSP_*, *_LAHH, *_XV, CB_*_CMD_*, REL_*_ENABLED | +25 |
| **Sensitive** | Process variables (pressure, temp, flow, voltage, current) | +10 |
| **Normal** | Utilities, site info, run hours, status counters | +5 |

### Threat Rules (12 total)

| Rule | Trigger | Score |
|------|---------|-------|
| `SecurityDowngrade` | SecurityPolicy=None | +3 |
| `AddressSpaceEnumeration` | >100 browse operations | +10 |
| `BulkReadExfil` | >20 nodes in one read | +10 |
| `CriticalTagRead` | Read of critical tag | +5 |
| `Write_Normal / Sensitive / Critical` | Write by tag class | +5 / +10 / +25 |
| `WriteEscalation` | 3+ writes in one session | +15 |
| `MethodCall_Critical` | Call to ESD / lockout method | +30 |
| `SubscriptionCritical` | Subscribe to critical tag | +20 |
| `HoneytokenLogin` | Planted credential used | +15 |
| `FailedAuth` | Authentication failure | +5 |
| `RapidReconnection` | 3+ connections from same IP in 60s | +10 |
| `CredentialSpraying` | 3+ different usernames from same IP | +15 |
| `DataExfiltration` | >1000 history points read | +10 |

---

## Logging

### Console

```
info: [SESSION] New connection from 10.20.30.45:49821 | session=a3f7c2d1
info: [AUTH] username=admin accepted=True | src=10.20.30.45
crit: [WRITE-ATTEMPT] [CRITICAL] node=ESD_CMD_TRIGGER value=True | src=10.20.30.45 threatScore=58
info: [SESSION-END] session=a3f7c2d1 duration=45s browse=87 read=34 write=3 threatScore=58
```

### NDJSON (`./logs/opcuatrap-YYYY-MM-DD.jsonl`)

One JSON object per line, daily rotation, thread-safe.

```json
{"timestamp":"2026-04-27T14:32:34Z","operation":"WriteAttempt","session_id":"a3f7c2d1","source_ip":"10.20.30.45","threat_score":28,"profile":"oil-gas","details":{"node_id":"SEP_HP_201_PSP_2001","attempted_value":"9999","classification":"Critical","severity":"CRITICAL"}}
```

### SIEM Sinks (configured in `appsettings.json`)

| Sink | Protocol | Config Key |
|------|----------|------------|
| NDJSON | File | Always on |
| Syslog | UDP or TCP, RFC 5424 | `Syslog` |
| CEF | ArcSight format over syslog | `Cef` |
| Webhook | HTTP POST, severity-filtered | `Webhooks` |
| Elasticsearch | Direct bulk API, daily indices | `Elasticsearch` |

---

## Configuration

`src/OpcUaTrap/appsettings.json` controls port, profile, honeytoken credentials, and SIEM sinks. Profile-level hardening (auth policy, timing, vendor identity, service limits) is configured in each profile JSON under the `hardening` key.

```json
{
  "OpcUaTrap": {
    "Port": 4840,
    "MaxClients": 50,
    "TimeoutSeconds": 30,
    "LogDirectory": "./logs",
    "Profile": "oil-gas",
    "HoneytokenCredentials": [
      { "Username": "operator",      "Password": "op3rator!"  },
      { "Username": "admin",         "Password": "admin123"   },
      { "Username": "engineer",      "Password": "Welcome1"   },
      { "Username": "readonly",      "Password": "readonly"   },
      { "Username": "svc_historian", "Password": "h1st0rian"  }
    ],
    "Syslog": {
      "Enabled": false,
      "Host": "127.0.0.1",
      "Port": 514,
      "Transport": "UDP",
      "Facility": "local0"
    },
    "Elasticsearch": {
      "Enabled": false,
      "Url": "http://127.0.0.1:9200",
      "IndexPrefix": "opcuatrap"
    }
  }
}
```

---

## Deployment

### Docker (recommended)

Run the published multi-arch image (amd64 + arm64):

```bash
docker run -d --name opcuatrap \
  -p 4840:4840 \
  -e OPCUATRAP_PROFILE=oil-gas \
  -v opcuatrap-data:/data \
  ghcr.io/0xajstrike/opcuatrap:latest
```

Or with Docker Compose (see [`docker-compose.yml`](docker-compose.yml)):

```bash
docker compose up -d
docker compose logs -f        # watch live alerts
```

Configuration is via environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPCUATRAP_PROFILE` | `oil-gas` | `oil-gas`, `water-treatment`, or `power-grid` |
| `OPCUATRAP_PORT` | `4840` | OPC UA listener port |
| `OPCUATRAP_LOG_DIR` | `/data/logs` | NDJSON log directory |
| `OPCUATRAP_VERBOSE` | `0` | `1`/`true` for debug console output |

The `/data` volume persists the auto-generated certificate and NDJSON logs across
restarts. To build the image yourself instead of pulling it:

```bash
docker build -t opcuatrap .
```

The Dockerfile clones the [LibUA fork](https://github.com/0xAJStrike/LibUA)
automatically during the build — you do **not** need to clone it separately for Docker.

### Standalone (Windows / Linux / macOS)

```bash
# Build self-contained binary
dotnet publish src/OpcUaTrap -c Release -r linux-x64 --self-contained -o ./publish

# Run
./publish/OpcUaTrap --profile oil-gas
```

### Raspberry Pi (ARM64)

```bash
dotnet publish src/OpcUaTrap -c Release -r linux-arm64 --self-contained -o ./publish
```

---

## Quick Connectivity Test

```bash
# From the tools/ directory
cd tools
uv sync
uv run python -c "
import asyncio
from asyncua import Client
async def main():
    async with Client('opc.tcp://127.0.0.1:4840') as c:
        node = c.get_node('ns=2;s=WH_101_PT_1001')
        print(f'Well 101 Tubing Pressure: {await node.read_value():.1f} PSI')
asyncio.run(main())
"
```

For full attack simulation and manual testing, see [tools/README.md](tools/README.md).

---

## Architecture

```
Program.cs              CLI args, config load, sink wiring, server lifecycle
HoneypotApplication     Extends LibUA.Server.Application — overrides all OPC UA handlers
ProfileLoader           Loads JSON profile → address space + tag classifier + simulation specs
SimulationEngine        1s timer — gaussian noise + mean-reverting drift + profile rules
InteractionLogger       Fan-out hub → List<ILogSink>
Hardening/              TimingJitter, AuthenticationPolicy, HardeningConfig
Logging/                NdjsonSink, SyslogSink, CefSink, WebhookSink, ElasticsearchSink
                        ConnectionTracker (cross-session IP threat tracking)
```

Certificate is auto-generated (RSA 2048, 3-year validity) and saved as `ServerCert.pem` / `ServerKey.pem`. It regenerates if the profile identity (CN) changes.

---

## License

Licensed under the **Apache License 2.0** — Copyright © 2026 0xAJStrike. Built on [LibUA](https://github.com/nauful/LibUA) (also Apache 2.0). See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Authored and maintained by [0xAJStrike](https://github.com/0xAJStrike).

## Disclaimer

Deploy in your own networks for threat detection, security research, or lab environments only. Not for use against systems you do not own or have explicit written permission to test.
