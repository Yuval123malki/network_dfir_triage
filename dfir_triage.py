#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline Windows Drive DFIR Triage Script
=========================================

Purpose
-------
Triage a SECONDARY, OFFLINE Windows drive mounted on an investigation
workstation (e.g. a drive letter such as E:\\, or an arbitrary mount point
that represents the root of the dead system, such as E:\\mnt\\C). The script
NEVER opens a file on the target drive for writing, and never calls any API
that mutates timestamps/metadata on the target. All parsing is done by:

  1. Copying the raw artifact (read-only) into the output folder, then
  2. Parsing the local COPY.

This means that after the initial copy pass, the target drive is never
touched again, which keeps the chain of custody clean and avoids any
"locked file" surprises on a live/indexed volume.

Optional third-party dependencies (pure-Python, no admin rights needed):
    pip install python-evtx regipy olefile

If a dependency is missing, the module(s) that need it are skipped (logged
as a warning) rather than crashing the whole run. Every artifact module is
wrapped in its own try/except so a single corrupt/missing/locked file never
aborts the overall triage.

Usage
-----
    python dfir_triage.py --target E:\\ --output D:\\Cases\\Case001 --name VICTIM-PC

See --help for all options. A full breakdown of the generated output folder
structure is printed at the end of the run and is also included in the
chat response that accompanies this script.

Author: DFIR tooling (generated), reviewed for offline/read-only triage use.
"""

import argparse
import csv
import ctypes
import datetime
import json
import logging
import os
import re
import struct
import sys
import time
import traceback
from pathlib import Path, PureWindowsPath

# --------------------------------------------------------------------------
# Optional dependency flags (resolved lazily inside each module so a single
# missing library never breaks unrelated modules).
# --------------------------------------------------------------------------
HAVE_EVTX = False
HAVE_REGIPY = False
HAVE_OLEFILE = False

try:
    import Evtx.Evtx as _evtx_probe  # noqa: F401
    HAVE_EVTX = True
except Exception:
    HAVE_EVTX = False

try:
    import regipy  # noqa: F401
    HAVE_REGIPY = True
except Exception:
    HAVE_REGIPY = False

try:
    import olefile  # noqa: F401
    HAVE_OLEFILE = True
except Exception:
    HAVE_OLEFILE = False


# ==========================================================================
# Generic helpers
# ==========================================================================

EPOCH_1601 = datetime.datetime(1601, 1, 1)
EPOCH_1970 = datetime.datetime(1970, 1, 1)


def filetime_to_iso(filetime):
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO8601 UTC."""
    if filetime in (None, 0):
        return None
    try:
        filetime = int(filetime)
        if filetime <= 0:
            return None
        dt = EPOCH_1601 + datetime.timedelta(microseconds=filetime / 10)
        return dt.isoformat() + "Z"
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def dosdate_to_iso(dos_date, dos_time):
    """Convert packed MS-DOS date/time (as used in shell items) to ISO8601."""
    try:
        if not dos_date and not dos_time:
            return None
        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2
        return datetime.datetime(year, month, day, hour, minute, second).isoformat() + "Z"
    except (ValueError, TypeError):
        return None


def unix_to_iso(epoch_seconds):
    try:
        if epoch_seconds in (None, 0):
            return None
        return (EPOCH_1970 + datetime.timedelta(seconds=int(epoch_seconds))).isoformat() + "Z"
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def human_size(num_bytes):
    try:
        num_bytes = float(num_bytes)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def progress_tick(logger, label, count, interval, start_time=None, total=None):
    """Shared heartbeat helper: call inside any loop that might run long
    enough for the console to otherwise look frozen. Prints every
    `interval` items, with elapsed time and (if known) a running total."""
    if interval <= 0 or count % interval != 0:
        return
    elapsed = f", {time.time() - start_time:.0f}s elapsed" if start_time else ""
    of_total = f" / {total:,}" if total else ""
    logger.info(f"  ...{label}: {count:,}{of_total} processed{elapsed}")


def safe_copy(src: Path, dest_dir: Path, logger, announce=True) -> Path:
    """Read-only copy of a single file from the target drive into our output
    tree. Returns the destination Path, or None on failure. Never opens the
    source for writing. Streams in chunks (never loads the whole file into
    memory) so multi-GB EVTX logs / hives don't blow up RAM, and announces
    large copies (plus periodic progress) on the console so the tool never
    looks frozen during a slow copy."""
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / src.name
        # Avoid collisions when the same filename exists under multiple
        # user profiles (e.g. NTUSER.DAT, USRCLASS.DAT, $I files, etc.)
        if dest_path.exists():
            dest_path = dest_dir / f"{src.parent.name}_{src.name}"

        size = src.stat().st_size
        is_large = size > 25 * 1024 * 1024
        if announce and is_large:
            logger.info(f"Copying {src.name} ({human_size(size)}) - this may take a moment...")

        start = time.time()
        chunk_size = 4 * 1024 * 1024
        copied = 0
        last_announce = start
        with open(src, "rb") as fsrc, open(dest_path, "wb") as fdst:
            while True:
                chunk = fsrc.read(chunk_size)
                if not chunk:
                    break
                fdst.write(chunk)
                copied += len(chunk)
                if is_large and (time.time() - last_announce) >= 10:
                    pct = (copied / size * 100) if size else 100
                    logger.info(f"  ...copying {src.name}: {human_size(copied)} / {human_size(size)} ({pct:.0f}%)")
                    last_announce = time.time()

        if announce and is_large:
            elapsed = time.time() - start
            logger.info(f"Copied {src.name} ({human_size(size)}) in {elapsed:.1f}s")
        return dest_path
    except Exception as e:
        logger.warning(f"Could not copy {src}: {e} - continuing with remaining artifacts")
        return None


def write_csv(records, fieldnames, csv_path, logger):
    try:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in records:
                writer.writerow(r)
    except Exception as e:
        logger.error(f"Failed to write CSV {csv_path}: {e}")


def write_json(records, json_path, logger):
    try:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to write JSON {json_path}: {e}")


def find_existing(target_root: Path, relative_parts):
    """Case-insensitive-safe join + existence check for a relative path under
    the target root. `relative_parts` is a str with backslashes, treated as a
    Windows-style relative path."""
    candidate = target_root / PureWindowsPath(relative_parts)
    candidate = Path(str(candidate))
    return candidate if candidate.exists() else None


def iter_user_profiles(target_root: Path):
    """Yield (username, profile_path) for each profile under \\Users, skipping
    the well-known non-interactive profiles that rarely matter for triage
    (still included if the analyst wants everything -- we don't skip them,
    just enumerate all directories under Users)."""
    users_dir = find_existing(target_root, "Users")
    if not users_dir:
        return
    try:
        for entry in users_dir.iterdir():
            if entry.is_dir():
                yield entry.name, entry
    except Exception:
        return


# ==========================================================================
# ntdll-based decompression (used for Windows 10/11 MAM-compressed Prefetch)
# ==========================================================================

COMPRESSION_FORMAT_XPRESS = 3
COMPRESSION_FORMAT_XPRESS_HUFF = 4
COMPRESSION_FORMAT_LZNT1 = 2


def rtl_decompress(compressed_bytes: bytes, uncompressed_size: int, fmt: int) -> bytes:
    """Use the real Windows implementation (ntdll!RtlDecompressBuffer) to
    decompress XPRESS / XPRESS-Huffman / LZNT1 data. This is far more
    reliable than a hand-rolled decompressor for a forensic tool, since it
    is the exact same code path the OS itself uses. Only works when the
    SCRIPT is run on a real Windows host (true for this environment)."""
    ntdll = ctypes.WinDLL("ntdll.dll")
    out_buf = ctypes.create_string_buffer(uncompressed_size)
    final_size = ctypes.c_ulong(0)
    status = ntdll.RtlDecompressBuffer(
        ctypes.c_ushort(fmt),
        out_buf,
        ctypes.c_ulong(uncompressed_size),
        compressed_bytes,
        ctypes.c_ulong(len(compressed_bytes)),
        ctypes.byref(final_size),
    )
    if status != 0:
        raise OSError(f"RtlDecompressBuffer failed, NTSTATUS=0x{status & 0xFFFFFFFF:08X}")
    return out_buf.raw[: final_size.value]


# ==========================================================================
# Output structure
# ==========================================================================

CATEGORY_DIRS = [
    "01_ProcessCreation",
    "02_Network",
    "03_DHCP",
    "04_DNS",
    "05_RecycleBin",
    "06_USBHistory",
    "07_Authentication",
    "08_Persistence",
    "09_Execution",
    "10_UserActivity",
]


def make_output_dirs(output_root: Path):
    dirs = {"root": output_root, "raw": output_root / "Raw_Data"}
    for cat in CATEGORY_DIRS:
        dirs[cat] = dirs["raw"] / cat
        dirs[cat].mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    return dirs


class ConsoleFormatter(logging.Formatter):
    """Makes WARNING/ERROR stand out live in the console as a visible
    ALERT banner, instead of looking like routine INFO text that's easy to
    miss while scrolling past. Normal INFO lines are left as-is."""

    def format(self, record):
        message = record.getMessage()
        if record.levelno >= logging.ERROR:
            return f"\n!!! ALERT (ERROR) !!! {message}\n"
        if record.levelno >= logging.WARNING:
            return f">>> ALERT (WARNING): {message}"
        return message


def setup_logging(output_root: Path):
    # Force line-buffered stdout/stderr so console output appears live as it
    # happens, instead of batching inside a pipe buffer (relevant when run
    # from a frozen .exe or redirected output - makes long-running modules
    # look "stuck" even though they are actively working).
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass

    log_path = output_root / "_script_execution.log"
    logger = logging.getLogger("dfir_triage")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(ConsoleFormatter())

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger, log_path


# ==========================================================================
# MODULE: Generic EVTX extraction (used by Process Creation, Network, DHCP,
# DNS and Authentication modules below)
# ==========================================================================

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_evtx_file(evtx_path: Path, logger, event_id_filter=None, max_records=None,
                     context_label=None, progress_interval=20000):
    """Generic EVTX -> list[dict] extractor. Captures all EventData/UserData
    fields dynamically (so we don't need per-EventID schema knowledge), plus
    the common System fields. A single corrupt record is skipped without
    aborting the rest of the log.

    Large EVTX files (Security.evtx / Sysmon operational especially) can
    take minutes to scan with a pure-Python parser. This logs a heartbeat
    every `progress_interval` records so the console shows the tool is
    actively working instead of looking frozen."""
    if not HAVE_EVTX:
        raise RuntimeError("python-evtx not installed (pip install python-evtx)")

    import xml.etree.ElementTree as ET
    from Evtx.Evtx import Evtx

    label = context_label or evtx_path.name
    records = []
    scanned = 0
    start = time.time()
    logger.info(f"Parsing {label} - scanning records (this can take a while for large logs)...")
    with Evtx(str(evtx_path)) as evtx:
        for record in evtx.records():
            scanned += 1
            if scanned % progress_interval == 0:
                elapsed = time.time() - start
                logger.info(
                    f"  ...{label}: {scanned:,} records scanned, {len(records):,} matched "
                    f"({elapsed:.0f}s elapsed)"
                )
            try:
                root = ET.fromstring(record.xml())
                system = root.find(f"{NS}System")
                if system is None:
                    continue

                eid_el = system.find(f"{NS}EventID")
                event_id = None
                if eid_el is not None and eid_el.text:
                    try:
                        event_id = int(eid_el.text)
                    except ValueError:
                        event_id = int(eid_el.text.strip() or 0)

                if event_id_filter and event_id not in event_id_filter:
                    continue

                time_el = system.find(f"{NS}TimeCreated")
                time_created = time_el.get("SystemTime") if time_el is not None else None
                computer_el = system.find(f"{NS}Computer")
                provider_el = system.find(f"{NS}Provider")
                channel_el = system.find(f"{NS}Channel")
                recid_el = system.find(f"{NS}EventRecordID")
                security_el = system.find(f"{NS}Security")
                user_sid = security_el.get("UserID") if security_el is not None else None

                event_data = {}
                for tag in ("EventData", "UserData"):
                    data_el = root.find(f"{NS}{tag}")
                    if data_el is None:
                        continue
                    for child in data_el.iter():
                        if child is data_el:
                            continue
                        name = child.get("Name")
                        if name:
                            event_data[name] = child.text
                        elif child.text and child.text.strip():
                            event_data.setdefault("Data", child.text)

                records.append(
                    {
                        "TimeCreated": time_created,
                        "EventID": event_id,
                        "Channel": channel_el.text if channel_el is not None else None,
                        "Provider": provider_el.get("Name") if provider_el is not None else None,
                        "Computer": computer_el.text if computer_el is not None else None,
                        "EventRecordID": recid_el.text if recid_el is not None else None,
                        "UserSID": user_sid,
                        "EventData": event_data,
                    }
                )
                if max_records and len(records) >= max_records:
                    break
            except Exception as e:
                logger.debug(f"Skipped corrupt EVTX record in {evtx_path}: {e}")
                continue
    elapsed = time.time() - start
    logger.info(f"Finished {label}: {scanned:,} records scanned, {len(records):,} matched ({elapsed:.1f}s)")
    return records


def write_evtx_records(records, out_dir: Path, base_name: str, logger):
    write_json(records, out_dir / f"{base_name}.json", logger)
    fieldnames = [
        "TimeCreated",
        "EventID",
        "Channel",
        "Provider",
        "Computer",
        "EventRecordID",
        "UserSID",
        "EventDataJSON",
    ]
    flat = []
    for r in records:
        row = {k: r.get(k) for k in fieldnames if k != "EventDataJSON"}
        row["EventDataJSON"] = json.dumps(r.get("EventData", {}), default=str)
        flat.append(row)
    write_csv(flat, fieldnames, out_dir / f"{base_name}.csv", logger)


EVTX_LOG_PATHS = {
    "Security": r"Windows\System32\winevt\Logs\Security.evtx",
    "System": r"Windows\System32\winevt\Logs\System.evtx",
    "Sysmon": r"Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "NetworkProfile": r"Windows\System32\winevt\Logs\Microsoft-Windows-NetworkProfile%4Operational.evtx",
    "WLAN-AutoConfig": r"Windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
    "Firewall": r"Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
    "DhcpClient": r"Windows\System32\winevt\Logs\Microsoft-Windows-Dhcp-Client%4Operational.evtx",
    "Dhcp-Client-Admin": r"Windows\System32\winevt\Logs\Microsoft-Windows-Dhcp-Client%4Admin.evtx",
    "DNSClient": r"Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx",
    "TaskScheduler": r"Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
}


def copy_and_parse_evtx(target_root, out_dir, logger, log_key, event_id_filter, max_records, context_label=None):
    """Copy a single named EVTX log (if present) then parse the copy."""
    rel_path = EVTX_LOG_PATHS[log_key]
    src = find_existing(target_root, rel_path)
    if not src:
        logger.info(f"[{log_key}] log not found on target (skipped): {rel_path}")
        return []
    try:
        logger.info(f"[{log_key}] found: {src.name} ({human_size(src.stat().st_size)})")
    except Exception:
        pass
    raw_dir = out_dir / "Raw_Copies"
    local_copy = safe_copy(src, raw_dir, logger)
    if not local_copy:
        return []
    try:
        return parse_evtx_file(local_copy, logger, event_id_filter, max_records, context_label=context_label or log_key)
    except Exception as e:
        logger.error(f"[{log_key}] failed to parse: {e} - continuing with remaining artifacts\n{traceback.format_exc()}")
        return []


# ==========================================================================
# MODULE 1 + 7: Process Creation (Security 4688 + Sysmon EventID 1) and
# Authentication (Security 4624/4625/4648/4720)
#
# Security.evtx is typically the largest log on the box, and is needed by
# both categories. It is parsed ONCE here (with the union of all event IDs
# either category needs) and the results are split afterward, instead of
# doing two full passes over a potentially multi-GB file.
# ==========================================================================

LOGON_TYPE_MAP = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
}


def module_process_creation_and_authentication(target_root, dirs, logger, max_records):
    pc_dir = dirs["01_ProcessCreation"]
    auth_dir = dirs["07_Authentication"]
    pc_records = []
    auth_records = []

    try:
        security_events = copy_and_parse_evtx(
            target_root, pc_dir, logger, "Security",
            {4688, 4624, 4625, 4648, 4720}, max_records,
            context_label="Security.evtx (4688/4624/4625/4648/4720)",
        )
        for r in security_events:
            if r.get("EventID") == 4688:
                r["ArtifactSource"] = "Security.evtx (EventID 4688)"
                pc_records.append(r)
            else:
                if r.get("EventID") == 4624:
                    ed = r.get("EventData", {})
                    r["LogonTypeFriendly"] = LOGON_TYPE_MAP.get(str(ed.get("LogonType")), ed.get("LogonType"))
                auth_records.append(r)
        logger.info(f"Security.evtx: {len(pc_records)} process-creation (4688) + "
                    f"{len(auth_records)} authentication (4624/4625/4648/4720) events")
        if auth_dir != pc_dir:
            try:
                note = auth_dir / "Raw_Copies" / "README_Security_evtx_location.txt"
                note.parent.mkdir(parents=True, exist_ok=True)
                note.write_text(
                    "Security.evtx is parsed once for both Process Creation and Authentication.\n"
                    "The raw copy is stored under:\n"
                    "  Raw_Data\\01_ProcessCreation\\Raw_Copies\\Security.evtx\n",
                    encoding="utf-8",
                )
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Security.evtx parsing failed: {e} - continuing with remaining artifacts"
                      f"\n{traceback.format_exc()}")

    try:
        sysmon_path = find_existing(target_root, EVTX_LOG_PATHS["Sysmon"])
        if sysmon_path:
            sysmon_records = copy_and_parse_evtx(target_root, pc_dir, logger, "Sysmon", {1}, max_records)
            for r in sysmon_records:
                r["ArtifactSource"] = "Sysmon Operational (EventID 1)"
            pc_records.extend(sysmon_records)
            logger.info(f"Process Creation: {len(sysmon_records)} Sysmon EventID 1 events parsed")
        else:
            logger.info("Sysmon operational log not present on target - skipped (not an error).")
    except Exception as e:
        logger.error(f"Process Creation (Sysmon) module failed: {e} - continuing with remaining artifacts"
                      f"\n{traceback.format_exc()}")

    try:
        write_evtx_records(pc_records, pc_dir, "process_creation", logger)
    except Exception as e:
        logger.error(f"Failed writing process creation output: {e}")

    try:
        write_evtx_records(auth_records, auth_dir, "authentication_events", logger)
    except Exception as e:
        logger.error(f"Failed writing authentication output: {e}")

    return {"process_creation": pc_records, "authentication": auth_records}


# ==========================================================================
# MODULE 2/3/4: Network, DHCP, DNS (generic EVTX dumps + hosts file +
# interface configuration from the SYSTEM hive)
# ==========================================================================

def module_hosts_and_interfaces(target_root, out_dir, logger):
    records = []
    try:
        hosts_path = find_existing(target_root, r"Windows\System32\drivers\etc\hosts")
        if hosts_path:
            safe_copy(hosts_path, out_dir / "Raw_Copies", logger)
            with open(hosts_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split()
                    if len(parts) >= 2:
                        records.append({"LineNumber": line_num, "IPAddress": parts[0], "Hostname": " ".join(parts[1:])})
            logger.info(f"hosts file: {len(records)} entries parsed")
        else:
            logger.info("hosts file not found on target - skipped.")
    except Exception as e:
        logger.error(f"hosts file parsing failed: {e}")
    write_csv(records, ["LineNumber", "IPAddress", "Hostname"], out_dir / "hosts_file.csv", logger)
    return records


def module_interface_config(target_root, out_dir, logger):
    """Best-effort dump of per-interface TCP/IP + DHCP lease registry values
    from the offline SYSTEM hive. Requires regipy."""
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping interface/DHCP registry config (pip install regipy)")
        return records
    try:
        from regipy.registry import RegistryHive

        system_hive_path = find_existing(target_root, r"Windows\System32\config\SYSTEM")
        if not system_hive_path:
            logger.info("SYSTEM hive not found - skipping interface config.")
            return records
        local_copy = safe_copy(system_hive_path, out_dir / "Raw_Copies" / "Hives", logger)
        if not local_copy:
            return records

        hive = RegistryHive(str(local_copy))
        current_cs = get_current_control_set(hive, logger)
        base_path = rf"{current_cs}\Services\Tcpip\Parameters\Interfaces"
        try:
            key = hive.get_key(base_path)
        except Exception:
            logger.info("Tcpip Interfaces key not found in SYSTEM hive - skipping.")
            return records

        for sk in safe_iter_subkeys(key, logger):
            entry = {"InterfaceGUID": getattr(sk, "name", "?")}
            for v in safe_iter_values(sk, logger):
                name = v.name
                val = v.value
                if "Lease" in name or "T1" in name or "T2" in name:
                    try:
                        val_display = f"{val} ({unix_to_iso(val)})"
                    except Exception:
                        val_display = val
                else:
                    val_display = val
                entry[name] = str(val_display)[:500]
            records.append(entry)
        logger.info(f"Interface config: {len(records)} interfaces parsed from SYSTEM hive")
    except Exception as e:
        logger.error(f"Interface config parsing failed: {e}\n{traceback.format_exc()}")

    if records:
        fieldnames = sorted({k for r in records for k in r.keys()})
        write_csv(records, fieldnames, out_dir / "interface_dhcp_config.csv", logger)
        write_json(records, out_dir / "interface_dhcp_config.json", logger)
    return records


def module_network(target_root, dirs, logger, max_records):
    out_dir = dirs["02_Network"]
    all_records = []
    for log_key in ("NetworkProfile", "WLAN-AutoConfig", "Firewall"):
        try:
            recs = copy_and_parse_evtx(target_root, out_dir, logger, log_key, None, max_records)
            for r in recs:
                r["ArtifactSource"] = log_key
            all_records.extend(recs)
            logger.info(f"Network: {len(recs)} events from {log_key}")
        except Exception as e:
            logger.error(f"Network module ({log_key}) failed: {e}")
    write_evtx_records(all_records, out_dir, "network_events", logger)
    module_hosts_and_interfaces(target_root, out_dir, logger)
    return all_records


def module_dhcp(target_root, dirs, logger, max_records):
    out_dir = dirs["03_DHCP"]
    all_records = []
    for log_key in ("DhcpClient", "Dhcp-Client-Admin"):
        try:
            recs = copy_and_parse_evtx(target_root, out_dir, logger, log_key, None, max_records)
            for r in recs:
                r["ArtifactSource"] = log_key
            all_records.extend(recs)
            logger.info(f"DHCP: {len(recs)} events from {log_key}")
        except Exception as e:
            logger.error(f"DHCP module ({log_key}) failed: {e}")
    write_evtx_records(all_records, out_dir, "dhcp_events", logger)
    module_interface_config(target_root, out_dir, logger)
    return all_records


def module_dns(target_root, dirs, logger, max_records):
    out_dir = dirs["04_DNS"]
    all_records = []
    try:
        recs = copy_and_parse_evtx(target_root, out_dir, logger, "DNSClient", None, max_records)
        for r in recs:
            r["ArtifactSource"] = "DNSClient"
        all_records.extend(recs)
        logger.info(f"DNS: {len(recs)} DNS-Client operational events")
    except Exception as e:
        logger.error(f"DNS module failed: {e}")
    write_evtx_records(all_records, out_dir, "dns_client_events", logger)
    module_hosts_and_interfaces(target_root, out_dir, logger)
    return all_records


# ==========================================================================
# MODULE 5: Recycle Bin ($I / $R enumeration, pure stdlib)
# ==========================================================================

def parse_i_file(path: Path, logger):
    """Parse a $I recycle-bin metadata file. Supports both the legacy format
    (Vista-7, version=1, fixed 260-WCHAR path) and the modern format
    (8.1/10/11, version=2, variable-length path with explicit length)."""
    try:
        data = path.read_bytes()
        if len(data) < 24:
            return None
        version = struct.unpack("<q", data[0:8])[0]
        file_size = struct.unpack("<q", data[8:16])[0]
        deleted_filetime = struct.unpack("<q", data[16:24])[0]

        if version == 1:
            raw_name = data[24:24 + 520]
            original_path = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        elif version == 2:
            name_len = struct.unpack("<I", data[24:28])[0]
            raw_name = data[28:28 + (name_len * 2)]
            original_path = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        else:
            # Unknown/future version - still try the v2 layout as a best effort.
            name_len = struct.unpack("<I", data[24:28])[0]
            raw_name = data[28:28 + (name_len * 2)]
            original_path = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]

        return {
            "FormatVersion": version,
            "OriginalFileSize": file_size,
            "DeletedTimestampUTC": filetime_to_iso(deleted_filetime),
            "OriginalPath": original_path,
        }
    except Exception as e:
        logger.debug(f"Failed to parse $I file {path}: {e}")
        return None


def resolve_sid_to_username(target_root, sid, logger, _cache={}):
    """Best-effort SID -> profile path lookup via the offline SOFTWARE hive
    ProfileList key. Cached per-run since this is called once per Recycle
    Bin SID folder."""
    if sid in _cache:
        return _cache[sid]
    if not HAVE_REGIPY:
        _cache[sid] = None
        return None
    try:
        from regipy.registry import RegistryHive

        software_path = find_existing(target_root, r"Windows\System32\config\SOFTWARE")
        if not software_path:
            _cache[sid] = None
            return None
        hive = RegistryHive(str(software_path))
        key = hive.get_key(rf"Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}")
        for v in safe_iter_values(key, logger):
            if v.name == "ProfileImagePath":
                _cache[sid] = str(v.value)
                return _cache[sid]
    except Exception as e:
        logger.debug(f"SID resolution failed for {sid}: {e}")
    _cache[sid] = None
    return None


def module_recycle_bin(target_root, dirs, logger):
    out_dir = dirs["05_RecycleBin"]
    records = []
    recycle_root = find_existing(target_root, "$Recycle.Bin")
    if not recycle_root:
        logger.info("$Recycle.Bin not found on target - skipped.")
        write_csv(records, ["UserSID", "Username", "DeletedItemID", "OriginalPath", "OriginalFileSize",
                             "DeletedTimestampUTC", "RFilePresent", "RFileSizeOnDisk"], out_dir / "recycle_bin_items.csv", logger)
        return records

    try:
        sid_dirs = [d for d in recycle_root.iterdir() if d.is_dir()]
        logger.info(f"Recycle Bin: found {len(sid_dirs)} user SID folder(s) to scan")
        start = time.time()
        scanned_items = 0
        for sid_dir in sid_dirs:
            sid = sid_dir.name
            username = resolve_sid_to_username(target_root, sid, logger)
            try:
                for item in sid_dir.iterdir():
                    if not item.is_file() or not item.name.startswith("$I"):
                        continue
                    scanned_items += 1
                    progress_tick(logger, "Recycle Bin", scanned_items, 500, start_time=start)
                    parsed = parse_i_file(item, logger)
                    if not parsed:
                        continue
                    r_name = "$R" + item.name[2:]
                    r_path = sid_dir / r_name
                    r_present = r_path.exists()
                    r_size = None
                    if r_present:
                        try:
                            r_size = r_path.stat().st_size
                        except Exception:
                            r_size = None
                        safe_copy(item, out_dir / "Raw_Copies" / sid, logger)
                    records.append({
                        "UserSID": sid,
                        "Username": username,
                        "DeletedItemID": item.name,
                        "OriginalPath": parsed["OriginalPath"],
                        "OriginalFileSize": parsed["OriginalFileSize"],
                        "DeletedTimestampUTC": parsed["DeletedTimestampUTC"],
                        "RFilePresent": r_present,
                        "RFileSizeOnDisk": r_size,
                    })
            except Exception as e:
                logger.warning(f"Error enumerating Recycle Bin SID folder {sid_dir}: {e}")
        logger.info(f"Recycle Bin: {len(records)} deleted-item records recovered")
    except Exception as e:
        logger.error(f"Recycle Bin module failed: {e}\n{traceback.format_exc()}")

    write_csv(records, ["UserSID", "Username", "DeletedItemID", "OriginalPath", "OriginalFileSize",
                         "DeletedTimestampUTC", "RFilePresent", "RFileSizeOnDisk"], out_dir / "recycle_bin_items.csv", logger)
    write_json(records, out_dir / "recycle_bin_items.json", logger)
    return records


# ==========================================================================
# Registry helpers shared by Persistence / USB modules
# ==========================================================================

def safe_iter_subkeys(key, logger):
    try:
        for sk in key.iter_subkeys():
            yield sk
    except Exception as e:
        logger.debug(f"iter_subkeys failed: {e}")
        return


def safe_iter_values(key, logger):
    try:
        for v in key.get_values():
            yield v
    except Exception as e:
        logger.debug(f"get_values failed: {e}")
        return


def get_current_control_set(hive, logger):
    """Resolve CurrentControlSet -> ControlSet00N using SYSTEM\\Select\\Current,
    falling back to ControlSet001 if unavailable."""
    try:
        key = hive.get_key("Select")
        for v in safe_iter_values(key, logger):
            if v.name == "Current":
                return f"ControlSet{int(v.value):03d}"
    except Exception as e:
        logger.debug(f"Could not resolve current control set: {e}")
    return "ControlSet001"


def recurse_registry(key, base_path, logger, max_depth=6, _depth=0):
    """Yield (path, value_name, value_type, value) tuples for a key and all
    descendants, bounded by max_depth to avoid runaway recursion on the
    (very large) DeviceClasses tree."""
    for v in safe_iter_values(key, logger):
        try:
            yield (base_path, v.name, getattr(v, "value_type", None), v.value)
        except Exception:
            continue
    if _depth >= max_depth:
        return
    for sk in safe_iter_subkeys(key, logger):
        try:
            name = getattr(sk, "name", None) or "?"
            yield from recurse_registry(sk, f"{base_path}\\{name}", logger, max_depth, _depth + 1)
        except Exception as e:
            logger.debug(f"Recursion error under {base_path}: {e}")
            continue


# ==========================================================================
# MODULE 6: USB Device History (SetupAPI logs + SYSTEM hive)
# ==========================================================================

SETUPAPI_LINE_RE = re.compile(r"^>>>\s*\[(?P<section>.+?)\]\s*$")
SETUPAPI_TS_RE = re.compile(r"^>>>\s*Section start\s+(?P<ts>[\d/\.: ]+)$")


def module_setupapi_logs(target_root, out_dir, logger):
    records = []
    candidates = [
        r"Windows\inf\setupapi.dev.log",
        r"Windows\inf\setupapi.offline.log",
        r"Windows\inf\setupapi.app.log",
    ]
    for rel in candidates:
        path = find_existing(target_root, rel)
        if not path:
            continue
        try:
            safe_copy(path, out_dir / "Raw_Copies", logger)
            current_section = None
            current_ts = None
            with open(path, "r", encoding="utf-16", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except Exception as e:
                logger.warning(f"Could not read {path}: {e}")
                continue
        try:
            logger.info(f"Scanning {path.name}: {len(lines):,} lines")
            scan_start = time.time()
            for i, line in enumerate(lines, 1):
                progress_tick(logger, f"SetupAPI {path.name}", i, 100000, start_time=scan_start, total=len(lines))
                line = line.rstrip("\n")
                m = SETUPAPI_LINE_RE.match(line)
                if m:
                    current_section = m.group("section")
                    current_ts = None
                    continue
                m_ts = SETUPAPI_TS_RE.match(line)
                if m_ts:
                    current_ts = m_ts.group("ts").strip()
                    continue
                if current_section and ("usb" in current_section.lower() or "usbstor" in line.lower() or "vid_" in line.lower() or "pid_" in line.lower()):
                    records.append({
                        "SourceLog": path.name,
                        "SectionTimestamp": current_ts,
                        "Section": current_section,
                        "Line": line.strip(),
                    })
            logger.info(f"SetupAPI log {path.name}: {len(records)} USB-relevant lines captured")
        except Exception as e:
            logger.error(f"Failed parsing SetupAPI log {path}: {e}")
    return records


def module_usb_registry(target_root, out_dir, logger):
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping USBSTOR/Enum\\USB/DeviceClasses registry parsing")
        return records
    try:
        from regipy.registry import RegistryHive

        system_hive_path = find_existing(target_root, r"Windows\System32\config\SYSTEM")
        if not system_hive_path:
            logger.info("SYSTEM hive not found - skipping USB registry parsing.")
            return records
        local_copy = safe_copy(system_hive_path, out_dir / "Raw_Copies" / "Hives", logger)
        if not local_copy:
            return records
        hive = RegistryHive(str(local_copy))
        ccs = get_current_control_set(hive, logger)

        targets = {
            "USBSTOR": rf"{ccs}\Enum\USBSTOR",
            "USB": rf"{ccs}\Enum\USB",
            "DeviceClasses": rf"{ccs}\Control\DeviceClasses",
        }
        for label, path in targets.items():
            try:
                key = hive.get_key(path)
            except Exception:
                logger.info(f"USB registry key not present: {path}")
                continue
            # Limit DeviceClasses recursion depth more aggressively - it is huge
            # and mostly not USB-relevant; we still capture subkey names/timestamps.
            max_depth = 3 if label == "DeviceClasses" else 5
            count_before = len(records)
            logger.info(f"Scanning registry key [{label}]: {path} (max depth {max_depth})...")
            scan_start = time.time()
            scanned = 0
            for sub_path, value_name, value_type, value in recurse_registry(key, path, logger, max_depth=max_depth):
                scanned += 1
                progress_tick(logger, f"USB registry [{label}]", scanned, 5000, start_time=scan_start)
                name_lower = (sub_path or "").lower()
                if label == "DeviceClasses" and "usb" not in name_lower and "disk" not in name_lower:
                    continue
                records.append({
                    "Category": label,
                    "KeyPath": sub_path,
                    "ValueName": value_name,
                    "ValueType": value_type,
                    "Value": str(value)[:500],
                })
            logger.info(f"USB registry [{label}]: {scanned:,} values scanned, "
                        f"{len(records) - count_before} captured ({time.time() - scan_start:.1f}s)")
    except Exception as e:
        logger.error(f"USB registry module failed: {e}\n{traceback.format_exc()}")
    return records


def module_usb_history(target_root, dirs, logger):
    out_dir = dirs["06_USBHistory"]
    setupapi_records = []
    registry_records = []
    try:
        setupapi_records = module_setupapi_logs(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"SetupAPI module failed: {e}\n{traceback.format_exc()}")
    try:
        registry_records = module_usb_registry(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"USB registry module failed: {e}\n{traceback.format_exc()}")

    if setupapi_records:
        write_csv(setupapi_records, ["SourceLog", "SectionTimestamp", "Section", "Line"],
                  out_dir / "setupapi_usb_entries.csv", logger)
        write_json(setupapi_records, out_dir / "setupapi_usb_entries.json", logger)
    if registry_records:
        write_csv(registry_records, ["Category", "KeyPath", "ValueName", "ValueType", "Value"],
                  out_dir / "usb_registry_entries.csv", logger)
        write_json(registry_records, out_dir / "usb_registry_entries.json", logger)

    return {"setupapi": setupapi_records, "registry": registry_records}


# Authentication (4624/4625/4648/4720) is now parsed together with Process
# Creation by module_process_creation_and_authentication() above, since both
# read from Security.evtx and that log is the expensive part to scan.


# ==========================================================================
# MODULE 8: Persistence (Run keys, Services, Scheduled Tasks)
# ==========================================================================

RUN_KEY_PATHS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]


def dump_run_keys(hive, base_label, run_key_paths, logger):
    results = []
    for rel_path in run_key_paths:
        try:
            key = hive.get_key(rel_path)
        except Exception:
            continue
        for v in safe_iter_values(key, logger):
            results.append({
                "Hive": base_label,
                "KeyPath": rel_path,
                "ValueName": v.name,
                "Value": str(v.value)[:500],
            })
    return results


def module_persistence_run_keys(target_root, out_dir, logger):
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping Run/RunOnce key parsing")
        return records
    from regipy.registry import RegistryHive

    try:
        software_path = find_existing(target_root, r"Windows\System32\config\SOFTWARE")
        if software_path:
            local_copy = safe_copy(software_path, out_dir / "Raw_Copies" / "Hives", logger)
            if local_copy:
                hive = RegistryHive(str(local_copy))
                records.extend(dump_run_keys(hive, "SOFTWARE", RUN_KEY_PATHS, logger))
    except Exception as e:
        logger.error(f"SOFTWARE Run key parsing failed: {e}")

    profiles = list(iter_user_profiles(target_root))
    logger.info(f"Run keys: checking NTUSER.DAT for {len(profiles)} user profile(s)")
    for username, profile_path in profiles:
        ntuser_path = profile_path / "NTUSER.DAT"
        if not ntuser_path.exists():
            continue
        logger.info(f"  ...scanning NTUSER.DAT for user '{username}'")
        try:
            local_copy = safe_copy(ntuser_path, out_dir / "Raw_Copies" / "NTUSER" / username, logger)
            if not local_copy:
                continue
            hive = RegistryHive(str(local_copy))
            user_run_key_paths = [rf"Software\{p}" for p in RUN_KEY_PATHS]
            user_records = dump_run_keys(hive, f"NTUSER.DAT ({username})", user_run_key_paths, logger)
            for r in user_records:
                r["Username"] = username
            records.extend(user_records)
        except Exception as e:
            logger.warning(f"NTUSER.DAT Run key parsing failed for {username}: {e}")

    logger.info(f"Persistence (Run keys): {len(records)} values captured")
    return records


def module_persistence_services(target_root, out_dir, logger):
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping Services enumeration")
        return records
    try:
        from regipy.registry import RegistryHive

        system_hive_path = find_existing(target_root, r"Windows\System32\config\SYSTEM")
        if not system_hive_path:
            logger.info("SYSTEM hive not found - skipping Services.")
            return records
        local_copy = safe_copy(system_hive_path, out_dir / "Raw_Copies" / "Hives", logger)
        if not local_copy:
            return records
        hive = RegistryHive(str(local_copy))
        ccs = get_current_control_set(hive, logger)
        services_path = rf"{ccs}\Services"
        key = hive.get_key(services_path)
        logger.info("Persistence: enumerating Services...")
        scan_start = time.time()
        scanned = 0
        for sk in safe_iter_subkeys(key, logger):
            scanned += 1
            progress_tick(logger, "Services", scanned, 200, start_time=scan_start)
            entry = {"ServiceName": getattr(sk, "name", "?")}
            for v in safe_iter_values(sk, logger):
                if v.name in ("ImagePath", "DisplayName", "Start", "Type", "Description"):
                    entry[v.name] = str(v.value)[:500]
            records.append(entry)
        logger.info(f"Persistence (Services): {len(records)} services enumerated ({time.time() - scan_start:.1f}s)")
    except Exception as e:
        logger.error(f"Services enumeration failed: {e}\n{traceback.format_exc()}")
    return records


def module_persistence_scheduled_tasks(target_root, out_dir, logger):
    """Scheduled Task XML files are plain-text/XML on disk (Vista+), so this
    module uses only the standard library's ElementTree - no optional deps,
    high reliability."""
    import xml.etree.ElementTree as ET

    records = []
    tasks_root = find_existing(target_root, r"Windows\System32\Tasks")
    if not tasks_root:
        logger.info("Scheduled Tasks folder not found - skipped.")
        return records

    task_files = [f for f in tasks_root.rglob("*") if f.is_file()]
    logger.info(f"Scheduled Tasks: found {len(task_files):,} file(s) to parse")
    scan_start = time.time()
    for i, task_file in enumerate(task_files, 1):
        progress_tick(logger, "Scheduled Tasks", i, 1000, start_time=scan_start, total=len(task_files))
        try:
            raw = task_file.read_text(encoding="utf-16", errors="ignore")
            if not raw.strip().startswith("<?xml") and "<Task" not in raw:
                continue
            root = ET.fromstring(raw)
            ns_match = re.match(r"\{.*\}", root.tag)
            ns_uri = ns_match.group(0) if ns_match else ""

            def tag(name):
                return f"{ns_uri}{name}"

            author = root.findtext(f"{tag('RegistrationInfo')}/{tag('Author')}")
            reg_date = root.findtext(f"{tag('RegistrationInfo')}/{tag('Date')}")
            commands = []
            for exec_el in root.iter(tag("Exec")):
                cmd = exec_el.findtext(tag("Command"))
                args = exec_el.findtext(tag("Arguments"))
                commands.append(f"{cmd} {args or ''}".strip())
            records.append({
                "TaskPath": str(task_file.relative_to(tasks_root)),
                "Author": author,
                "RegistrationDate": reg_date,
                "Commands": " | ".join(c for c in commands if c),
            })
        except Exception as e:
            logger.debug(f"Could not parse scheduled task {task_file}: {e}")
            continue

    logger.info(f"Persistence (Scheduled Tasks): {len(records)} task definitions parsed")
    return records


def module_persistence(target_root, dirs, logger):
    out_dir = dirs["08_Persistence"]
    run_keys = []
    services = []
    tasks = []
    try:
        run_keys = module_persistence_run_keys(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"Run key module failed: {e}\n{traceback.format_exc()}")
    try:
        services = module_persistence_services(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"Services module failed: {e}\n{traceback.format_exc()}")
    try:
        tasks = module_persistence_scheduled_tasks(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"Scheduled Tasks module failed: {e}\n{traceback.format_exc()}")

    if run_keys:
        fieldnames = sorted({k for r in run_keys for k in r.keys()})
        write_csv(run_keys, fieldnames, out_dir / "run_keys.csv", logger)
        write_json(run_keys, out_dir / "run_keys.json", logger)
    if services:
        fieldnames = sorted({k for r in services for k in r.keys()})
        write_csv(services, fieldnames, out_dir / "services.csv", logger)
        write_json(services, out_dir / "services.json", logger)
    if tasks:
        write_csv(tasks, ["TaskPath", "Author", "RegistrationDate", "Commands"], out_dir / "scheduled_tasks.csv", logger)
        write_json(tasks, out_dir / "scheduled_tasks.json", logger)

    return {"run_keys": run_keys, "services": services, "scheduled_tasks": tasks}


# ==========================================================================
# MODULE 9: Execution artifacts - Prefetch, Amcache, Shimcache
# ==========================================================================

# Offsets below follow the published libscca / Prefetch-file-format
# documentation (Joachim Metz) and are consistent with values reported by
# community tooling (e.g. Eric Zimmerman's PECmd) for each format version.
# Unknown/unsupported versions are skipped rather than guessed.
PREFETCH_VERSION_OFFSETS = {
    17: {"last_run_count": 1, "last_run_offset": 0x78, "run_count_offset": 0x90},   # XP/2003
    23: {"last_run_count": 1, "last_run_offset": 0x80, "run_count_offset": 0x98},   # Vista/7
    26: {"last_run_count": 8, "last_run_offset": 0x80, "run_count_offset": 0xD0},   # 8 / 8.1
    30: {"last_run_count": 8, "last_run_offset": 0x80, "run_count_offset": 0xD0},   # 10 / 11
}


def decompress_prefetch(raw: bytes, logger):
    if raw[:3] == b"MAM":
        uncompressed_size = struct.unpack("<I", raw[4:8])[0]
        compressed = raw[8:]
        try:
            return rtl_decompress(compressed, uncompressed_size, COMPRESSION_FORMAT_XPRESS_HUFF)
        except Exception as e:
            logger.debug(f"Prefetch decompression failed: {e}")
            return None
    return raw


def parse_prefetch_file(path: Path, logger):
    try:
        raw = path.read_bytes()
        data = decompress_prefetch(raw, logger)
        if not data or len(data) < 84:
            return None
        version = struct.unpack("<I", data[0:4])[0]
        signature = data[4:8]
        if signature != b"SCCA":
            logger.debug(f"{path.name}: not a recognized Prefetch file (bad signature)")
            return None
        exe_name = data[16:76].decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
        file_size_field = struct.unpack("<I", data[12:16])[0]
        prefetch_hash = f"{struct.unpack('<I', data[76:80])[0]:08X}"

        result = {
            "FileName": path.name,
            "ExecutableName": exe_name,
            "PrefetchHash": prefetch_hash,
            "Version": version,
            "FileSizeField": file_size_field,
            "RunCount": None,
            "LastRunTimestampsUTC": None,
        }

        offsets = PREFETCH_VERSION_OFFSETS.get(version)
        if not offsets:
            logger.debug(f"{path.name}: unsupported Prefetch version {version} - run-count/last-run skipped")
            return result

        run_count = struct.unpack("<I", data[offsets["run_count_offset"]:offsets["run_count_offset"] + 4])[0]
        result["RunCount"] = run_count

        times = []
        base = offsets["last_run_offset"]
        for i in range(offsets["last_run_count"]):
            ft = struct.unpack("<Q", data[base + i * 8: base + i * 8 + 8])[0]
            iso = filetime_to_iso(ft)
            if iso:
                times.append(iso)
        result["LastRunTimestampsUTC"] = "; ".join(times) if times else None
        return result
    except Exception as e:
        logger.debug(f"Failed to parse Prefetch file {path}: {e}")
        return None


def module_prefetch(target_root, out_dir, logger, copy_raw):
    records = []
    pf_dir = find_existing(target_root, r"Windows\Prefetch")
    if not pf_dir:
        logger.info("Prefetch folder not found - skipped.")
        return records
    try:
        pf_files = list(pf_dir.glob("*.pf"))
        logger.info(f"Prefetch: found {len(pf_files):,} .pf file(s) to parse")
        scan_start = time.time()
        for i, pf_file in enumerate(pf_files, 1):
            progress_tick(logger, "Prefetch", i, 1000, start_time=scan_start, total=len(pf_files))
            parsed = parse_prefetch_file(pf_file, logger)
            if parsed:
                records.append(parsed)
                if copy_raw:
                    safe_copy(pf_file, out_dir / "Raw_Copies" / "Prefetch", logger, announce=False)
        logger.info(f"Prefetch: {len(records)} .pf files parsed ({time.time() - scan_start:.1f}s)")
    except Exception as e:
        logger.error(f"Prefetch module failed: {e}\n{traceback.format_exc()}")
    return records


def module_amcache(target_root, out_dir, logger):
    """Amcache.hve is itself a registry hive. We try the modern
    Root\\InventoryApplicationFile layout (Win10/11) first, then fall back to
    the legacy Root\\File\\{VolumeGUID}\\# layout (Win8/8.1/early Win10).
    The raw hive is always copied for deep-dive with AmcacheParser if needed."""
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping Amcache parsing")
        return records
    amcache_path = find_existing(target_root, r"Windows\AppCompat\Programs\Amcache.hve")
    if not amcache_path:
        logger.info("Amcache.hve not found - skipped.")
        return records
    local_copy = safe_copy(amcache_path, out_dir / "Raw_Copies" / "Hives", logger)
    if not local_copy:
        return records
    try:
        from regipy.registry import RegistryHive

        hive = RegistryHive(str(local_copy))
        scan_start = time.time()
        try:
            key = hive.get_key(r"Root\InventoryApplicationFile")
            scanned = 0
            for sk in safe_iter_subkeys(key, logger):
                scanned += 1
                progress_tick(logger, "Amcache (InventoryApplicationFile)", scanned, 2000, start_time=scan_start)
                entry = {"Source": "InventoryApplicationFile", "Key": getattr(sk, "name", "?")}
                for v in safe_iter_values(sk, logger):
                    if v.name in ("LowerCaseLongPath", "ProductName", "Publisher", "Version",
                                  "Size", "FileId", "LinkDate", "ProgramId"):
                        entry[v.name] = str(v.value)[:500]
                records.append(entry)
        except Exception:
            logger.debug("InventoryApplicationFile key not present - trying legacy Root\\File layout")

        if not records:
            try:
                key = hive.get_key(r"Root\File")
                scanned = 0
                for vol_key in safe_iter_subkeys(key, logger):
                    for file_key in safe_iter_subkeys(vol_key, logger):
                        scanned += 1
                        progress_tick(logger, "Amcache (Root\\File legacy)", scanned, 2000, start_time=scan_start)
                        entry = {"Source": "Root\\File (legacy)", "Key": getattr(file_key, "name", "?")}
                        for v in safe_iter_values(file_key, logger):
                            entry[f"Value_{v.name}"] = str(v.value)[:500]
                        records.append(entry)
            except Exception:
                logger.debug("Legacy Root\\File Amcache layout not present either.")

        logger.info(f"Amcache: {len(records)} executed-binary records in {time.time() - scan_start:.1f}s "
                    f"(best effort - verify with AmcacheParser for deep dive)")
    except Exception as e:
        logger.error(f"Amcache parsing failed: {e}\n{traceback.format_exc()}")
    return records


def module_shimcache(target_root, out_dir, logger):
    """Extracts the raw AppCompatCache binary blob (always) plus a best-effort
    decode. Shimcache's on-disk binary layout differs meaningfully across
    Windows versions and has subtle edge cases; this triage script favors
    preserving the RAW value for verification with a dedicated parser
    (e.g. Eric Zimmerman's AppCompatCacheParser) over guessing wrong
    offsets. The best-effort decode below only covers the modern Windows
    10/11 (10.0 build >= 1809-ish) layout."""
    records = []
    raw_saved_path = None
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping Shimcache parsing")
        return records, raw_saved_path
    system_hive_path = find_existing(target_root, r"Windows\System32\config\SYSTEM")
    if not system_hive_path:
        logger.info("SYSTEM hive not found - skipping Shimcache.")
        return records, raw_saved_path
    local_copy = safe_copy(system_hive_path, out_dir / "Raw_Copies" / "Hives", logger)
    if not local_copy:
        return records, raw_saved_path
    try:
        from regipy.registry import RegistryHive

        hive = RegistryHive(str(local_copy))
        ccs = get_current_control_set(hive, logger)
        key = hive.get_key(rf"{ccs}\Control\Session Manager\AppCompatCache")
        blob = None
        for v in safe_iter_values(key, logger):
            if v.name in ("AppCompatCache", ""):
                blob = v.value if isinstance(v.value, bytes) else None
        if blob is None:
            logger.info("AppCompatCache value not found/not binary - skipping.")
            return records, raw_saved_path

        raw_saved_path = out_dir / "Raw_Copies" / "shimcache_raw.bin"
        raw_saved_path.parent.mkdir(parents=True, exist_ok=True)
        raw_saved_path.write_bytes(blob)

        records = best_effort_decode_shimcache(blob, logger)
        logger.info(f"Shimcache: raw blob saved; best-effort decode produced {len(records)} entries "
                    f"(verify with AppCompatCacheParser for a definitive parse)")
    except Exception as e:
        logger.error(f"Shimcache parsing failed: {e}\n{traceback.format_exc()}")
    return records, raw_saved_path


def best_effort_decode_shimcache(blob: bytes, logger):
    """Best-effort decode for the Windows 10/11 AppCompatCache format
    (10.0 'ts' signature variant). Any failure simply returns an empty list
    - the raw blob is still preserved by the caller."""
    records = []
    try:
        if len(blob) < 12:
            return records
        magic = blob[0:4]
        # Windows 10/11 entries begin with a 4-byte tag b'10ts' at the start
        # of the cache, followed by a 4-byte CacheEntryPosition, 4-byte
        # NumberOfEntries, then CacheEntry structures. This layout is
        # documented in community Shimcache research; treat any parsing
        # exception as "could not best-effort decode" rather than guessing.
        if magic != b"ts10" and magic != b"10ts":
            return records
        offset = 12
        while offset + 2 <= len(blob):
            try:
                path_len = struct.unpack("<H", blob[offset:offset + 2])[0]
                offset += 2
                if path_len == 0 or path_len > 2000 or offset + path_len > len(blob):
                    break
                path = blob[offset:offset + path_len].decode("utf-16-le", errors="replace")
                offset += path_len
                # Followed by an 8-byte FILETIME (last modified) in this layout.
                if offset + 8 > len(blob):
                    break
                last_mod = struct.unpack("<Q", blob[offset:offset + 8])[0]
                offset += 8
                records.append({"Path": path, "LastModifiedUTC": filetime_to_iso(last_mod)})
            except Exception:
                break
    except Exception as e:
        logger.debug(f"Shimcache best-effort decode aborted: {e}")
        return []
    return records


def module_execution(target_root, dirs, logger, copy_raw):
    out_dir = dirs["09_Execution"]
    prefetch_records = []
    amcache_records = []
    shimcache_records = []

    try:
        prefetch_records = module_prefetch(target_root, out_dir, logger, copy_raw)
    except Exception as e:
        logger.error(f"Prefetch module failed: {e}\n{traceback.format_exc()}")
    try:
        amcache_records = module_amcache(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"Amcache module failed: {e}\n{traceback.format_exc()}")
    try:
        shimcache_records, _ = module_shimcache(target_root, out_dir, logger)
    except Exception as e:
        logger.error(f"Shimcache module failed: {e}\n{traceback.format_exc()}")

    if prefetch_records:
        write_csv(prefetch_records, ["FileName", "ExecutableName", "PrefetchHash", "Version",
                                      "FileSizeField", "RunCount", "LastRunTimestampsUTC"],
                  out_dir / "prefetch.csv", logger)
        write_json(prefetch_records, out_dir / "prefetch.json", logger)
    if amcache_records:
        fieldnames = sorted({k for r in amcache_records for k in r.keys()})
        write_csv(amcache_records, fieldnames, out_dir / "amcache.csv", logger)
        write_json(amcache_records, out_dir / "amcache.json", logger)
    if shimcache_records:
        write_csv(shimcache_records, ["Path", "LastModifiedUTC"], out_dir / "shimcache_best_effort.csv", logger)
        write_json(shimcache_records, out_dir / "shimcache_best_effort.json", logger)

    return {"prefetch": prefetch_records, "amcache": amcache_records, "shimcache": shimcache_records}


# ==========================================================================
# MODULE 10: User Activity - LNK files, Jump Lists, Shellbags
# ==========================================================================

def extract_best_effort_shell_item_name(item_bytes: bytes):
    """Heuristic/best-effort extraction of a display name from a shell-item
    byte blob (used both for LNK target ID lists and Shellbags). This is NOT
    a complete libfwsi-equivalent implementation; it looks for the first
    printable, null-terminated string after the fixed 14-byte common file
    entry prefix, falling back to a raw printable-string scan. Treat results
    as supplementary / best-effort, not forensically definitive."""
    try:
        if len(item_bytes) > 14:
            tail = item_bytes[14:]
            null_idx = tail.find(b"\x00")
            if null_idx > 0:
                candidate = tail[:null_idx]
                try:
                    name = candidate.decode("mbcs" if os.name == "nt" else "latin1", errors="ignore")
                    if name and all(31 < ord(c) < 127 or ord(c) > 127 for c in name):
                        return name
                except Exception:
                    pass
        # Fallback: find the longest run of printable ASCII characters.
        printable = re.findall(rb"[\x20-\x7E]{4,}", item_bytes)
        if printable:
            return max(printable, key=len).decode("ascii", errors="ignore")
    except Exception:
        pass
    return None


def parse_lnk_bytes(data: bytes, logger):
    """Parses the MS-SHLLINK binary format: fixed 76-byte header, optional
    LinkTargetIDList, optional LinkInfo, optional StringData section. Field
    offsets below are per the published MS-SHLLINK specification."""
    if len(data) < 76:
        return None
    header_size, clsid, link_flags, file_attrs, ctime, atime, wtime, file_size, icon_index, show_cmd, hotkey, _r1, _r2, _r3 = struct.unpack(
        "<I16sIIQQQIIIHHII", data[0:76]
    )
    if header_size != 0x4C:
        return None

    HAS_LINK_TARGET_IDLIST = 0x1
    HAS_LINK_INFO = 0x2
    HAS_NAME = 0x4
    HAS_RELATIVE_PATH = 0x8
    HAS_WORKING_DIR = 0x10
    HAS_ARGUMENTS = 0x20
    HAS_ICON_LOCATION = 0x40
    IS_UNICODE = 0x80

    offset = 76
    target_display_name = None

    if link_flags & HAS_LINK_TARGET_IDLIST:
        if offset + 2 > len(data):
            return None
        idlist_size = struct.unpack("<H", data[offset:offset + 2])[0]
        idlist_start = offset + 2
        idlist_end = idlist_start + idlist_size
        # Walk the shell item ID list to grab the *last* (most specific) item
        pos = idlist_start
        last_item = None
        while pos + 2 <= idlist_end and pos + 2 <= len(data):
            item_size = struct.unpack("<H", data[pos:pos + 2])[0]
            if item_size == 0:
                break
            last_item = data[pos:pos + item_size]
            pos += item_size
        if last_item:
            target_display_name = extract_best_effort_shell_item_name(last_item)
        offset = idlist_end

    local_base_path = None
    if link_flags & HAS_LINK_INFO and offset + 4 <= len(data):
        li_start = offset
        link_info_size = struct.unpack("<I", data[li_start:li_start + 4])[0]
        try:
            li_header_size = struct.unpack("<I", data[li_start + 4:li_start + 8])[0]
            local_base_offset = struct.unpack("<I", data[li_start + 16:li_start + 20])[0]
            if local_base_offset:
                abs_off = li_start + local_base_offset
                end = data.find(b"\x00", abs_off)
                if end > abs_off:
                    local_base_path = data[abs_off:end].decode("mbcs" if os.name == "nt" else "latin1", errors="replace")
        except Exception as e:
            logger.debug(f"LinkInfo parse best-effort failed: {e}")
        offset = li_start + link_info_size

    strings = {"Name": None, "RelativePath": None, "WorkingDir": None, "Arguments": None, "IconLocation": None}
    is_unicode = bool(link_flags & IS_UNICODE)
    for flag, key in (
        (HAS_NAME, "Name"),
        (HAS_RELATIVE_PATH, "RelativePath"),
        (HAS_WORKING_DIR, "WorkingDir"),
        (HAS_ARGUMENTS, "Arguments"),
        (HAS_ICON_LOCATION, "IconLocation"),
    ):
        if link_flags & flag and offset + 2 <= len(data):
            char_count = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
            byte_len = char_count * 2 if is_unicode else char_count
            raw = data[offset:offset + byte_len]
            try:
                strings[key] = raw.decode("utf-16-le" if is_unicode else "mbcs", errors="replace")
            except Exception:
                strings[key] = raw.decode("latin1", errors="replace")
            offset += byte_len

    return {
        "TargetDisplayNameBestEffort": target_display_name,
        "LocalBasePath": local_base_path,
        "RelativePath": strings["RelativePath"],
        "WorkingDir": strings["WorkingDir"],
        "Arguments": strings["Arguments"],
        "IconLocation": strings["IconLocation"],
        "FileSize": file_size,
        "CreationTimeUTC": filetime_to_iso(ctime),
        "AccessTimeUTC": filetime_to_iso(atime),
        "WriteTimeUTC": filetime_to_iso(wtime),
    }


def module_lnk_files(target_root, out_dir, logger, copy_raw):
    records = []
    profiles = list(iter_user_profiles(target_root))
    logger.info(f"LNK files: scanning {len(profiles)} user profile(s)")
    scan_start = time.time()
    scanned = 0
    for username, profile_path in profiles:
        logger.info(f"  ...scanning LNK locations for user '{username}'")
        search_roots = [
            profile_path / "Desktop",
            profile_path / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent",
            profile_path / "AppData" / "Roaming" / "Microsoft" / "Office" / "Recent",
        ]
        for root in search_roots:
            if not root.exists():
                continue
            try:
                for lnk_file in root.rglob("*.lnk"):
                    scanned += 1
                    progress_tick(logger, "LNK files", scanned, 2000, start_time=scan_start)
                    try:
                        data = lnk_file.read_bytes()
                        parsed = parse_lnk_bytes(data, logger)
                        if parsed:
                            parsed["Username"] = username
                            parsed["LnkFilePath"] = str(lnk_file)
                            parsed["LnkFileName"] = lnk_file.name
                            records.append(parsed)
                            if copy_raw:
                                safe_copy(lnk_file, out_dir / "Raw_Copies" / "LNK" / username, logger, announce=False)
                    except Exception as e:
                        logger.debug(f"Failed to parse LNK {lnk_file}: {e}")
            except Exception as e:
                logger.debug(f"Error walking {root}: {e}")
    logger.info(f"User Activity: {len(records)} LNK files parsed ({scanned:,} scanned, {time.time() - scan_start:.1f}s)")
    return records


def module_jump_lists(target_root, out_dir, logger, copy_raw):
    """AutomaticDestinations (OLE compound files, parsed via olefile - each
    non-DestList stream is itself a standard MS-SHLLINK blob and is parsed
    with the same LNK parser above) and CustomDestinations (raw concatenated
    LNK blobs, located via the ShellLink CLSID signature)."""
    records = []
    lnk_clsid = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000C000000000000046")  # HeaderSize+LinkCLSID

    profiles = list(iter_user_profiles(target_root))
    logger.info(f"Jump Lists: scanning {len(profiles)} user profile(s)")
    scan_start = time.time()
    files_scanned = 0
    for username, profile_path in profiles:
        auto_dest_dir = profile_path / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations"
        custom_dest_dir = profile_path / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "CustomDestinations"

        if auto_dest_dir.exists() and HAVE_OLEFILE:
            for ad_file in auto_dest_dir.glob("*.automaticDestinations-ms"):
                files_scanned += 1
                progress_tick(logger, "Jump Lists", files_scanned, 200, start_time=scan_start)
                try:
                    if copy_raw:
                        safe_copy(ad_file, out_dir / "Raw_Copies" / "JumpLists" / username, logger, announce=False)
                    ole = olefile.OleFileIO(str(ad_file))
                    for stream_path in ole.listdir():
                        stream_name = stream_path[-1]
                        if stream_name.lower() == "destlist":
                            continue
                        try:
                            stream_data = ole.openstream(stream_path).read()
                            parsed = parse_lnk_bytes(stream_data, logger)
                            if parsed:
                                parsed["Username"] = username
                                parsed["JumpListFile"] = ad_file.name
                                parsed["JumpListType"] = "AutomaticDestinations"
                                parsed["StreamName"] = stream_name
                                records.append(parsed)
                        except Exception as e:
                            logger.debug(f"Failed to parse jump list stream {stream_name} in {ad_file}: {e}")
                    ole.close()
                except Exception as e:
                    logger.debug(f"Failed to open AutomaticDestinations file {ad_file}: {e}")
        elif auto_dest_dir.exists() and not HAVE_OLEFILE:
            logger.warning("olefile not installed - skipping AutomaticDestinations jump lists (pip install olefile)")

        if custom_dest_dir.exists():
            for cd_file in custom_dest_dir.glob("*.customDestinations-ms"):
                files_scanned += 1
                progress_tick(logger, "Jump Lists", files_scanned, 200, start_time=scan_start)
                try:
                    if copy_raw:
                        safe_copy(cd_file, out_dir / "Raw_Copies" / "JumpLists" / username, logger, announce=False)
                    raw = cd_file.read_bytes()
                    search_from = 0
                    while True:
                        idx = raw.find(lnk_clsid, search_from)
                        if idx == -1:
                            break
                        parsed = parse_lnk_bytes(raw[idx:], logger)
                        if parsed:
                            parsed["Username"] = username
                            parsed["JumpListFile"] = cd_file.name
                            parsed["JumpListType"] = "CustomDestinations"
                            records.append(parsed)
                        search_from = idx + 1
                except Exception as e:
                    logger.debug(f"Failed to parse CustomDestinations file {cd_file}: {e}")

    logger.info(f"User Activity: {len(records)} Jump List entries parsed "
                f"({files_scanned:,} files scanned, {time.time() - scan_start:.1f}s)")
    return records


def module_shellbags(target_root, out_dir, logger, copy_raw):
    """Best-effort BagMRU enumeration from USRCLASS.DAT (and NTUSER.DAT for
    older OS versions). Extracts whatever display name can be heuristically
    recovered from each shell-item value; always preserves the raw hive copy
    so an analyst can re-run a dedicated Shellbags parser (e.g. SBECmd) for a
    forensically rigorous parse."""
    records = []
    if not HAVE_REGIPY:
        logger.warning("regipy not installed - skipping Shellbags parsing")
        return records

    from regipy.registry import RegistryHive

    bagmru_paths = [
        r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        r"Software\Microsoft\Windows\Shell\BagMRU",
    ]

    profiles = list(iter_user_profiles(target_root))
    logger.info(f"Shellbags: scanning {len(profiles)} user profile(s)")
    scan_start = time.time()
    scanned = 0
    for username, profile_path in profiles:
        usrclass_path = profile_path / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
        if not usrclass_path.exists():
            continue
        logger.info(f"  ...scanning BagMRU for user '{username}'")
        try:
            local_copy = safe_copy(usrclass_path, out_dir / "Raw_Copies" / "UsrClass" / username, logger)
            if not local_copy:
                continue
            hive = RegistryHive(str(local_copy))
            for bagmru_path in bagmru_paths:
                try:
                    key = hive.get_key(bagmru_path)
                except Exception:
                    continue
                for path, value_name, value_type, value in recurse_registry(key, bagmru_path, logger, max_depth=15):
                    scanned += 1
                    progress_tick(logger, "Shellbags", scanned, 5000, start_time=scan_start)
                    if value_name == "MRUListEx" or not isinstance(value, (bytes, bytearray)):
                        continue
                    name = extract_best_effort_shell_item_name(bytes(value))
                    if name:
                        records.append({
                            "Username": username,
                            "RegistryKeyPath": path,
                            "ValueName": value_name,
                            "FolderNameBestEffort": name,
                        })
        except Exception as e:
            logger.warning(f"Shellbags parsing failed for {username}: {e}")

    logger.info(f"User Activity: {len(records)} Shellbag entries parsed (best effort, "
                f"{scanned:,} values scanned, {time.time() - scan_start:.1f}s)")
    return records


def module_user_activity(target_root, dirs, logger, copy_raw):
    out_dir = dirs["10_UserActivity"]
    lnk_records, jumplist_records, shellbag_records = [], [], []
    try:
        lnk_records = module_lnk_files(target_root, out_dir, logger, copy_raw)
    except Exception as e:
        logger.error(f"LNK module failed: {e}\n{traceback.format_exc()}")
    try:
        jumplist_records = module_jump_lists(target_root, out_dir, logger, copy_raw)
    except Exception as e:
        logger.error(f"Jump List module failed: {e}\n{traceback.format_exc()}")
    try:
        shellbag_records = module_shellbags(target_root, out_dir, logger, copy_raw)
    except Exception as e:
        logger.error(f"Shellbags module failed: {e}\n{traceback.format_exc()}")

    if lnk_records:
        fieldnames = sorted({k for r in lnk_records for k in r.keys()})
        write_csv(lnk_records, fieldnames, out_dir / "lnk_files.csv", logger)
        write_json(lnk_records, out_dir / "lnk_files.json", logger)
    if jumplist_records:
        fieldnames = sorted({k for r in jumplist_records for k in r.keys()})
        write_csv(jumplist_records, fieldnames, out_dir / "jump_lists.csv", logger)
        write_json(jumplist_records, out_dir / "jump_lists.json", logger)
    if shellbag_records:
        write_csv(shellbag_records, ["Username", "RegistryKeyPath", "ValueName", "FolderNameBestEffort"],
                  out_dir / "shellbags_best_effort.csv", logger)
        write_json(shellbag_records, out_dir / "shellbags_best_effort.json", logger)

    return {"lnk": lnk_records, "jumplists": jumplist_records, "shellbags": shellbag_records}


# ==========================================================================
# Summary report generator
# ==========================================================================

def top_n(records, key_fn, n=10):
    from collections import Counter
    counter = Counter()
    for r in records:
        try:
            k = key_fn(r)
            if k:
                counter[k] += 1
        except Exception:
            continue
    return counter.most_common(n)


def generate_summary_report(output_root, target_root, target_name, start_time, results, logger, deps_status):
    summary_path = output_root / "Investigation_Summary.txt"
    end_time = datetime.datetime.now()
    lines = []

    def hr():
        lines.append("=" * 78)

    def sub_hr():
        lines.append("-" * 78)

    hr()
    lines.append("  OFFLINE WINDOWS DRIVE TRIAGE - INVESTIGATION SUMMARY")
    hr()
    lines.append(f"Target drive / root path : {target_root}")
    lines.append(f"Target label             : {target_name}")
    lines.append(f"Script run started (UTC) : {start_time.isoformat()}")
    lines.append(f"Script run finished (UTC): {end_time.isoformat()}")
    lines.append(f"Duration                 : {end_time - start_time}")
    lines.append(f"Output folder            : {output_root}")
    lines.append("")
    lines.append("Mode: READ-ONLY. All artifacts were copied from the target drive before")
    lines.append("parsing; the target drive was never opened for writing by this tool.")
    lines.append("")
    lines.append("Optional parser libraries detected this run:")
    for name, present in deps_status.items():
        lines.append(f"  - {name:<15s}: {'AVAILABLE' if present else 'NOT INSTALLED (module skipped/limited)'}")
    lines.append("")

    # ---- Process Creation ----
    hr()
    lines.append("1. PROCESS CREATION (Security 4688 / Sysmon EventID 1)")
    hr()
    pc = results.get("process_creation", [])
    lines.append(f"Total process-creation events parsed: {len(pc)}")
    procs = top_n(pc, lambda r: (r.get("EventData", {}).get("NewProcessName") or r.get("EventData", {}).get("Image")))
    if procs:
        lines.append("Top processes observed:")
        for name, count in procs:
            lines.append(f"  {count:>6}  {name}")
    with_cmdline = sum(1 for r in pc if r.get("EventData", {}).get("CommandLine") or r.get("EventData", {}).get("ProcessCommandLine"))
    lines.append(f"Events with a captured command line: {with_cmdline}")
    lines.append("Full detail: Raw_Data\\01_ProcessCreation\\process_creation.csv / .json")
    lines.append("")

    # ---- Network / DHCP / DNS ----
    hr()
    lines.append("2. NETWORK EVENTS")
    hr()
    net = results.get("network", [])
    lines.append(f"Total network-related events parsed (NetworkProfile/WLAN/Firewall): {len(net)}")
    lines.append("Full detail: Raw_Data\\02_Network\\")
    lines.append("")

    hr()
    lines.append("3. DHCP NETWORK CONNECTION EVENTS")
    hr()
    dhcp = results.get("dhcp", [])
    lines.append(f"Total DHCP client events parsed: {len(dhcp)}")
    lines.append("Full detail: Raw_Data\\03_DHCP\\")
    lines.append("")

    hr()
    lines.append("4. DNS ARTIFACTS")
    hr()
    dns = results.get("dns", [])
    lines.append(f"Total DNS Client operational events parsed: {len(dns)}")
    lines.append("Full detail: Raw_Data\\04_DNS\\ (also see hosts_file.csv)")
    lines.append("")

    # ---- Recycle Bin ----
    hr()
    lines.append("5. RECYCLE BIN")
    hr()
    rb = results.get("recycle_bin", [])
    lines.append(f"Total deleted-item records recovered: {len(rb)}")
    users_in_rb = top_n(rb, lambda r: r.get("UserSID"))
    if users_in_rb:
        lines.append("Items per user SID:")
        for sid, count in users_in_rb:
            lines.append(f"  {count:>6}  {sid}")
    lines.append("Full detail: Raw_Data\\05_RecycleBin\\recycle_bin_items.csv / .json")
    lines.append("")

    # ---- USB ----
    hr()
    lines.append("6. USB DEVICE HISTORY")
    hr()
    usb = results.get("usb", {})
    lines.append(f"SetupAPI log lines (USB-relevant): {len(usb.get('setupapi', []))}")
    lines.append(f"Registry entries (USBSTOR/Enum\\USB/DeviceClasses): {len(usb.get('registry', []))}")
    lines.append("Full detail: Raw_Data\\06_USBHistory\\")
    lines.append("")

    # ---- Authentication ----
    hr()
    lines.append("7. AUTHENTICATION (4624 / 4625 / 4648 / 4720)")
    hr()
    auth = results.get("authentication", [])
    by_id = top_n(auth, lambda r: r.get("EventID"), n=10)
    for eid, count in by_id:
        label = {4624: "Successful Logon", 4625: "Failed Logon",
                 4648: "Explicit Credentials Logon", 4720: "User Account Created"}.get(eid, str(eid))
        lines.append(f"  EventID {eid} ({label}): {count}")
    failed_users = top_n([r for r in auth if r.get("EventID") == 4625],
                         lambda r: r.get("EventData", {}).get("TargetUserName"))
    if failed_users:
        lines.append("Top usernames targeted by failed logons:")
        for name, count in failed_users:
            lines.append(f"  {count:>6}  {name}")
    new_accounts = [r for r in auth if r.get("EventID") == 4720]
    if new_accounts:
        lines.append("Accounts created:")
        for r in new_accounts:
            lines.append(f"  {r.get('TimeCreated')}  {r.get('EventData', {}).get('TargetUserName')}")
    lines.append("Full detail: Raw_Data\\07_Authentication\\authentication_events.csv / .json")
    lines.append("")

    # ---- Persistence ----
    hr()
    lines.append("8. PERSISTENCE MECHANISMS")
    hr()
    persist = results.get("persistence", {})
    lines.append(f"Run/RunOnce values (SOFTWARE + all NTUSER.DAT): {len(persist.get('run_keys', []))}")
    lines.append(f"Services enumerated: {len(persist.get('services', []))}")
    lines.append(f"Scheduled Task definitions parsed: {len(persist.get('scheduled_tasks', []))}")
    lines.append("Full detail: Raw_Data\\08_Persistence\\")
    lines.append("")

    # ---- Execution ----
    hr()
    lines.append("9. EXECUTION & STAGING ARTIFACTS")
    hr()
    exe = results.get("execution", {})
    lines.append(f"Prefetch files parsed: {len(exe.get('prefetch', []))}")
    lines.append(f"Amcache executed-binary records (best effort): {len(exe.get('amcache', []))}")
    lines.append(f"Shimcache best-effort decoded entries: {len(exe.get('shimcache', []))}")
    lines.append("NOTE: Amcache/Shimcache decoding is best-effort. The raw AppCompatCache")
    lines.append("value and Amcache.hve are preserved under Raw_Copies for verification")
    lines.append("with a dedicated tool (e.g. Eric Zimmerman's AppCompatCacheParser /")
    lines.append("AmcacheParser) before relying on these fields in a report.")
    lines.append("Full detail: Raw_Data\\09_Execution\\")
    lines.append("")

    # ---- User Activity ----
    hr()
    lines.append("10. USER ACTIVITY (LNK / Jump Lists / Shellbags)")
    hr()
    ua = results.get("user_activity", {})
    lines.append(f"LNK files parsed: {len(ua.get('lnk', []))}")
    lines.append(f"Jump List entries parsed: {len(ua.get('jumplists', []))}")
    lines.append(f"Shellbag entries parsed (best effort): {len(ua.get('shellbags', []))}")
    lines.append("NOTE: Shellbag folder names are recovered heuristically, not via a full")
    lines.append("shell-item-type decoder. Verify with SBECmd for court-ready findings.")
    lines.append("Full detail: Raw_Data\\10_UserActivity\\")
    lines.append("")

    hr()
    lines.append("END OF SUMMARY - see _script_execution.log for per-artifact warnings,")
    lines.append("missing files, and anything that was skipped during this run.")
    hr()

    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("\r\n".join(lines))  # CRLF for clean Notepad rendering
        logger.info(f"Summary report written: {summary_path}")
    except Exception as e:
        logger.error(f"Failed to write summary report: {e}")


# ==========================================================================
# Main
# ==========================================================================

def parse_args():
    p = argparse.ArgumentParser(description="Offline Windows drive DFIR triage (read-only).")
    p.add_argument("--target", required=True, help=r"Root of the offline/mounted drive to triage, e.g. E:\ or E:\mnt\C")
    p.add_argument("--output", default=".", help="Base folder where the Investigation_Output_* folder will be created")
    p.add_argument("--name", default=None, help="Label for the target system (default: derived from --target)")
    p.add_argument("--max-evtx-records", type=int, default=None, help="Optional cap on records parsed per EVTX log (for quick test runs)")
    p.add_argument("--no-copy-raw", action="store_true", help="Skip copying raw artifact files (Prefetch/LNK/JumpList); CSV/JSON output still produced")
    return p.parse_args()


def main():
    args = parse_args()
    target_root = Path(args.target).resolve()
    if not target_root.exists():
        print(f"ERROR: target path does not exist: {target_root}", file=sys.stderr)
        sys.exit(1)

    target_name = args.name or (target_root.drive.rstrip(":") or target_root.name or "UNKNOWN")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = Path(args.output).resolve() / f"Investigation_Output_{target_name}_{timestamp}"

    # Safety: never let the output folder live inside the target drive/evidence path.
    try:
        output_root.relative_to(target_root)
        print("ERROR: --output resolves to a location inside --target. Refusing to write "
              "into the evidence drive. Choose an output path on your analysis workstation.", file=sys.stderr)
        sys.exit(1)
    except ValueError:
        pass  # good: output is NOT inside target

    dirs = make_output_dirs(output_root)
    logger, log_path = setup_logging(output_root)

    start_time = datetime.datetime.now()
    logger.info(f"=== DFIR Triage started: target={target_root} output={output_root} ===")
    logger.info(f"Optional deps - python-evtx: {HAVE_EVTX}, regipy: {HAVE_REGIPY}, olefile: {HAVE_OLEFILE}")
    if not (HAVE_EVTX and HAVE_REGIPY and HAVE_OLEFILE):
        logger.warning("Some optional dependencies are missing. Affected modules will be skipped or "
                        "limited (see per-module log lines below). Install with: "
                        "pip install python-evtx regipy olefile")

    copy_raw = not args.no_copy_raw
    max_records = args.max_evtx_records

    results = {}

    # Ordered fastest-first: quick, self-contained modules run up front so the
    # console shows steady progress immediately after launch, and the slow,
    # potentially multi-GB EVTX logs (Security.evtx especially) run last,
    # with their own progress heartbeats (see parse_evtx_file) so they never
    # look frozen even though they can legitimately take minutes.
    module_plan = [
        ("recycle_bin", "Recycle Bin", lambda: module_recycle_bin(target_root, dirs, logger)),
        ("usb", "USB Device History", lambda: module_usb_history(target_root, dirs, logger)),
        ("persistence", "Persistence Mechanisms", lambda: module_persistence(target_root, dirs, logger)),
        ("execution", "Execution Artifacts (Prefetch/Amcache/Shimcache)",
         lambda: module_execution(target_root, dirs, logger, copy_raw)),
        ("user_activity", "User Activity (LNK/JumpLists/Shellbags)",
         lambda: module_user_activity(target_root, dirs, logger, copy_raw)),
        ("network", "Network Events", lambda: module_network(target_root, dirs, logger, max_records)),
        ("dhcp", "DHCP Events", lambda: module_dhcp(target_root, dirs, logger, max_records)),
        ("dns", "DNS Artifacts", lambda: module_dns(target_root, dirs, logger, max_records)),
        ("security", "Process Creation + Authentication (Security.evtx / Sysmon)",
         lambda: module_process_creation_and_authentication(target_root, dirs, logger, max_records)),
    ]

    total_modules = len(module_plan)
    for i, (key, label, fn) in enumerate(module_plan, start=1):
        logger.info(f"\n========== [{i}/{total_modules}] {label} ==========")
        module_start = time.time()
        try:
            results[key] = fn()
        except Exception as e:
            logger.error(f"Uncaught error in module '{label}': {e} - continuing with remaining "
                         f"modules, nothing collected here will be lost from the rest of the run"
                         f"\n{traceback.format_exc()}")
            results[key] = {}
        logger.info(f"[{i}/{total_modules}] {label} finished in {time.time() - module_start:.1f}s")

    # The combined Security.evtx module returns a dict with both of its
    # category results; unpack it into the two separate keys the summary
    # report expects.
    combined = results.pop("security", {})
    results["process_creation"] = combined.get("process_creation", [])
    results["authentication"] = combined.get("authentication", [])

    deps_status = {"python-evtx": HAVE_EVTX, "regipy": HAVE_REGIPY, "olefile": HAVE_OLEFILE}
    generate_summary_report(output_root, target_root, target_name, start_time, results, logger, deps_status)

    total_elapsed = datetime.datetime.now() - start_time
    logger.info(f"=== DFIR Triage finished in {total_elapsed}. Output: {output_root} ===")
    print(f"\nDone. Output folder:\n  {output_root}\n")
    print(f"Execution log: {log_path}")
    print(f"Summary report: {output_root / 'Investigation_Summary.txt'}")


if __name__ == "__main__":
    main()
