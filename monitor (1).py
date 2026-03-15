#!/usr/bin/env python3
"""
NetSentinel — Network Security Monitor
Monitors traffic for MAC/IP spoofing, logs devices, and pulls DHCP snooping
& DAI data from switches via SSH or console cable.
"""

import os
import sys
import json
import time
import logging
import threading
import re
import sqlite3
import getpass
import glob
from datetime import datetime, timedelta
from collections import defaultdict

# ── third-party ──────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, ARP, Ether, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netmiko
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False

try:
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

from flask import Flask, jsonify, render_template_string
from flask_cors import CORS

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("net_monitor.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

DB_PATH = "net_monitor.db"

# populated by the startup wizard
SWITCH_CONFIGS = []

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI helpers
# ─────────────────────────────────────────────────────────────────────────────
CYAN   = "\033[96m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
CLEAR  = "\033[2J\033[H"

def c(color, text): return f"{color}{text}{RESET}"

def banner():
    print(CLEAR)
    print(c(CYAN, r"""
  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""))
    print(c(DIM,  "  " + "─" * 88))
    print(c(BLUE, "  NETWORK SECURITY MONITOR") + c(DIM, "  //  MAC & IP Spoof Detection  //  DHCP Snooping  //  DAI"))
    print(c(DIM,  "  " + "─" * 88))
    print()

def section(title):
    print(f"\n{c(CYAN, '  ┌─')} {c(BOLD, title)}")
    print(c(CYAN, "  │"))

def _prompt_raw(label, secret=False):
    full = f"  {c(CYAN, '  │')}  {c(YELLOW, label)}: "
    if secret:
        return getpass.getpass(full)
    return input(full).strip()

def prompt(label, default=None, secret=False, allow_empty=False):
    suffix = f" {c(DIM, f'[{default}]')}" if default is not None else ""
    full = f"  {c(CYAN, '  │')}  {c(YELLOW, label)}{suffix}: "
    while True:
        if secret:
            val = getpass.getpass(full)
        else:
            val = input(full).strip()
        if not val and default is not None:
            return default
        if val or allow_empty:
            return val
        print(c(RED, "  │    ✗  Required. Please enter a value."))

def choose(label, options, default=None):
    """options: list of (key, description). Returns chosen key."""
    print(f"\n  {c(CYAN, '  │')}  {c(YELLOW, label)}")
    for i, (key, desc) in enumerate(options, 1):
        marker = c(GREEN, "►") if (default and key == default) else " "
        print(f"  {c(CYAN, '  │')}    {marker} {c(BOLD, str(i))}.  {desc}")
    while True:
        raw = input(f"  {c(CYAN, '  │')}  {c(DIM, 'Enter number')}: ").strip()
        if not raw and default:
            for key, _ in options:
                if key == default:
                    return key
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(c(RED, "  │    ✗  Invalid choice."))

def yn(label, default="y"):
    d_str = "Y/n" if default == "y" else "y/N"
    raw = input(f"\n  {c(CYAN, '  │')}  {c(YELLOW, label)} {c(DIM, f'({d_str})')}: ").strip().lower()
    if not raw:
        return default == "y"
    return raw in ("y", "yes")

def ok(msg):   print(f"  {c(CYAN, '  │')}  {c(GREEN,  '✓')}  {msg}")
def warn(msg): print(f"  {c(CYAN, '  │')}  {c(YELLOW, '⚠')}  {msg}")
def err(msg):  print(f"  {c(CYAN, '  │')}  {c(RED,    '✗')}  {msg}")
def info(msg): print(f"  {c(CYAN, '  │')}  {c(DIM,    '·')}  {msg}")

# ─────────────────────────────────────────────────────────────────────────────
#  COM port discovery
# ─────────────────────────────────────────────────────────────────────────────

def list_com_ports():
    """Return list of (device, label) tuples for available serial ports."""
    ports = []
    if SERIAL_AVAILABLE:
        for p in serial.tools.list_ports.comports():
            desc = p.description or ""
            ports.append((p.device, f"{p.device}  {c(DIM, desc)}"))
    else:
        # Fallback scan
        if sys.platform.startswith("win"):
            for i in range(1, 33):
                ports.append((f"COM{i}", f"COM{i}"))
        else:
            for pat in ["/dev/ttyUSB*", "/dev/ttyS[0-9]*", "/dev/tty.usbserial*", "/dev/tty.PL*"]:
                for p in sorted(glob.glob(pat)):
                    ports.append((p, p))
    return ports

# ─────────────────────────────────────────────────────────────────────────────
#  STARTUP WIZARD
# ─────────────────────────────────────────────────────────────────────────────

def wizard():
    global SWITCH_CONFIGS

    banner()

    # ── 1. Sniffer ────────────────────────────────────────────────────────────
    section("STEP 1 / 3  —  PACKET SNIFFER")

    sniffer_iface = None
    if not SCAPY_AVAILABLE:
        warn("Scapy is not installed — live ARP sniffing is disabled.")
        warn("Install with:  pip install scapy")
    else:
        ifaces = get_if_list()
        if not ifaces:
            warn("No network interfaces detected.")
        else:
            info(f"Available interfaces: {c(BOLD, '  '.join(ifaces))}")
            default_iface = next((i for i in ifaces if i not in ("lo",)), ifaces[0])
            if yn("Enable live ARP sniffing (requires root/admin)?", "y"):
                sniffer_iface = prompt("Network interface to sniff", default=default_iface)
                ok(f"Will sniff on: {c(BOLD, sniffer_iface)}")
            else:
                warn("Live sniffing disabled — demo data will be shown in the dashboard.")

    # ── 2. Switches ───────────────────────────────────────────────────────────
    section("STEP 2 / 3  —  SWITCH CONNECTIONS")
    info("Add managed switches to pull DHCP Snooping bindings and DAI statistics.")
    info("You can add multiple switches (SSH and/or Console).")

    switch_list = []
    add_switch = yn("Add a switch now?", "y")

    while add_switch:
        print()
        sw_num = len(switch_list) + 1
        print(f"  {c(CYAN, '  │')}  {c(BOLD, f'─── Switch #{sw_num} ───')}")

        # Connection method
        conn_method = choose(
            "Connection method",
            [
                ("ssh",     "SSH  (connect over the network by IP address)"),
                ("console", "Console cable  (serial / COM port)"),
            ],
            default="ssh",
        )

        # OS / vendor
        dev_type = choose(
            "Switch OS / vendor",
            [
                ("cisco_ios",    "Cisco IOS          (Catalyst 2960/3560/3750/4500)"),
                ("cisco_iosxe",  "Cisco IOS-XE       (Catalyst 9k / ISR 4k)"),
                ("cisco_nxos",   "Cisco NX-OS        (Nexus 3k/5k/7k/9k)"),
                ("cisco_asa",    "Cisco ASA          (Firewall)"),
                ("arista_eos",   "Arista EOS"),
                ("hp_procurve",  "HP / Aruba ProCurve"),
                ("juniper_junos","Juniper JunOS"),
            ],
            default="cisco_ios",
        )

        if conn_method == "ssh":
            # ── SSH ───────────────────────────────────────────────────────────
            host     = prompt("Switch IP address or hostname")
            port     = prompt("SSH port", default="22")
            username = prompt("Username")
            password = prompt("Password", secret=True)
            secret   = ""
            if yn("Does this switch require an enable/privilege secret?", "n"):
                secret = prompt("Enable secret", secret=True)

            cfg = {
                "device_type": dev_type,
                "host":        host,
                "port":        int(port),
                "username":    username,
                "password":    password,
                "secret":      secret,
                "_label":      f"{host} (SSH)",
            }

            if yn("Test SSH connection now?", "y"):
                _test_ssh(cfg)

        else:
            # ── Console cable ─────────────────────────────────────────────────
            print()
            info("Scanning for serial / COM ports…")
            com_ports = list_com_ports()

            if com_ports:
                ok(f"Found {len(com_ports)} port(s):")
                opts = [(p[0], p[1]) for p in com_ports]
                opts.append(("manual", c(DIM, "Enter port manually")))
                com_port = choose("Select COM / serial port", opts)
            else:
                warn("No serial ports detected automatically.")
                com_port = "manual"

            if com_port == "manual":
                if sys.platform.startswith("win"):
                    com_port = prompt("COM port", default="COM1")
                else:
                    com_port = prompt("Serial device", default="/dev/ttyUSB0")

            baud = choose(
                "Baud rate",
                [
                    ("9600",   "9600    — Cisco default RJ-45 console"),
                    ("115200", "115200  — Cisco USB console / NX-OS"),
                    ("38400",  "38400"),
                    ("19200",  "19200"),
                    ("4800",   "4800"),
                    ("custom", "Custom…"),
                ],
                default="9600",
            )
            if baud == "custom":
                baud = prompt("Baud rate", default="9600")

            data_bits = choose(
                "Data bits",
                [("8","8  (standard)"),("7","7")],
                default="8",
            )
            parity = choose(
                "Parity",
                [("N","None (standard)"),("E","Even"),("O","Odd")],
                default="N",
            )
            stop_bits = choose(
                "Stop bits",
                [("1","1  (standard)"),("2","2")],
                default="1",
            )

            username = prompt("Username (press Enter to skip)", allow_empty=True)
            password = ""
            if username:
                password = prompt("Password", secret=True, allow_empty=True)
            secret = ""
            if yn("Does this switch require an enable/privilege secret?", "n"):
                secret = prompt("Enable secret", secret=True)

            # Netmiko serial device type
            serial_type = dev_type + "_serial"

            cfg = {
                "device_type":     serial_type,
                "serial_settings": {
                    "port":     com_port,
                    "baudrate": int(baud),
                    "bytesize": int(data_bits),
                    "parity":   parity,
                    "stopbits": int(stop_bits),
                },
                "host":     "",   # required key for Netmiko even with serial
                "username": username,
                "password": password,
                "secret":   secret,
                "_label":   f"{com_port} @ {baud} baud (Console)",
            }

            if yn("Test serial connection now?", "y"):
                _test_serial(cfg)

        switch_list.append(cfg)
        ok(f"Added: {c(BOLD, cfg['_label'])}  [{cfg['device_type']}]")

        add_switch = yn("\nAdd another switch?", "n")

    SWITCH_CONFIGS = switch_list

    # ── 3. Dashboard ─────────────────────────────────────────────────────────
    section("STEP 3 / 3  —  WEB DASHBOARD")
    dash_port = prompt("Dashboard port", default="5000")
    bind_all  = yn("Bind to all interfaces (0.0.0.0) so other hosts can reach it?", "y")
    bind_host = "0.0.0.0" if bind_all else "127.0.0.1"

    # ── Summary ───────────────────────────────────────────────────────────────
    section("CONFIGURATION SUMMARY")
    print()
    info(f"Sniffer iface    : {c(BOLD, sniffer_iface or 'disabled')}")
    info(f"Switches         : {c(BOLD, str(len(switch_list)))}")
    for sw in switch_list:
        info(f"  ↳  {sw['_label']}  [{sw['device_type']}]")
    info(f"Dashboard URL    : {c(BOLD, f'http://localhost:{dash_port}')}")
    print()

    if not yn("Launch NetSentinel with this configuration?", "y"):
        print(c(YELLOW, "\n  Aborted.\n"))
        sys.exit(0)

    print(f"\n  {c(GREEN, '▶')}  Starting…\n")
    return sniffer_iface, bind_host, int(dash_port)


def _test_ssh(cfg):
    if not NETMIKO_AVAILABLE:
        warn("Netmiko not installed — cannot test now.")
        return
    info("Attempting SSH connection…")
    net_cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
    try:
        with ConnectHandler(**net_cfg) as net:
            if cfg.get("secret"):
                net.enable()
            out = net.send_command("show version | include uptime")
        ok(f"SSH OK!  {c(DIM, out[:80] if out else '')}")
    except Exception as e:
        err(f"Connection failed: {e}")
        warn("Switch will still be saved — re-check credentials at runtime.")


def _test_serial(cfg):
    if not NETMIKO_AVAILABLE:
        warn("Netmiko not installed — cannot test now.")
        return
    info("Opening serial port…")
    net_cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
    try:
        with ConnectHandler(**net_cfg) as net:
            out = net.send_command("\r\n", expect_string=r"[>#]", delay_factor=3)
        ok(f"Console OK!  {c(DIM, out[:80] if out else '')}")
    except Exception as e:
        err(f"Serial failed: {e}")
        warn("Port will still be saved — check cable / baud rate.")


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac          TEXT PRIMARY KEY,
            ip           TEXT,
            vendor       TEXT,
            first_seen   TEXT,
            last_seen    TEXT,
            packet_count INTEGER DEFAULT 0,
            trusted      INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            severity   TEXT,
            event_type TEXT,
            mac        TEXT,
            ip         TEXT,
            detail     TEXT
        );
        CREATE TABLE IF NOT EXISTS snoop_bindings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            mac          TEXT,
            ip           TEXT,
            vlan         TEXT,
            interface    TEXT,
            lease_time   TEXT,
            switch_host  TEXT,
            pulled_at    TEXT
        );
        CREATE TABLE IF NOT EXISTS dai_stats (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            interface    TEXT,
            vlan         TEXT,
            forwarded    INTEGER,
            dropped      INTEGER,
            switch_host  TEXT,
            pulled_at    TEXT
        );
    """)
    conn.commit()
    conn.close()

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─────────────────────────────────────────────────────────────────────────────
#  OUI / VENDOR LOOKUP
# ─────────────────────────────────────────────────────────────────────────────
OUI_MAP = {
    "00:50:56": "VMware",     "00:0c:29": "VMware",    "08:00:27": "VirtualBox",
    "00:1a:2b": "Cisco",      "00:1b:54": "Cisco",     "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi","00:16:3e": "Xen",      "52:54:00": "QEMU/KVM",
    "00:e0:4c": "Realtek",    "ac:de:48": "Apple",     "a4:c3:f0": "Apple",
    "18:65:90": "Apple",      "f0:18:98": "Apple",     "00:1d:0f": "Intel",
    "8c:ec:4b": "Intel",      "00:25:22": "Intel",
}
def oui_vendor(mac):
    p = mac[:8].lower()
    return next((v for k, v in OUI_MAP.items() if p == k.lower()), "Unknown")

# ─────────────────────────────────────────────────────────────────────────────
#  SPOOF DETECTION
# ─────────────────────────────────────────────────────────────────────────────
mac_to_ips = defaultdict(set)
ip_to_macs = defaultdict(set)
state_lock = threading.Lock()

def record_arp(mac, ip):
    if not mac or mac == "ff:ff:ff:ff:ff:ff" or ip in ("0.0.0.0", ""):
        return
    now = datetime.utcnow().isoformat()
    with state_lock:
        prev_ips  = mac_to_ips[mac].copy()
        prev_macs = ip_to_macs[ip].copy()
        mac_to_ips[mac].add(ip)
        ip_to_macs[ip].add(mac)

    conn = db_conn(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO devices (mac,ip,vendor,first_seen,last_seen,packet_count)
        VALUES (?,?,?,?,?,1)
        ON CONFLICT(mac) DO UPDATE SET
            ip=excluded.ip, last_seen=excluded.last_seen,
            packet_count=packet_count+1
    """, (mac, ip, oui_vendor(mac), now, now))
    conn.commit()

    if ip not in prev_ips and prev_ips:
        detail = f"MAC {mac} previously seen with {sorted(prev_ips)}, now claiming {ip}"
        log.warning("MAC SPOOF? %s", detail)
        cur.execute("INSERT INTO events (timestamp,severity,event_type,mac,ip,detail) VALUES (?,?,?,?,?,?)",
                    (now,"HIGH","MAC_SPOOF",mac,ip,detail))
        conn.commit()

    if mac not in prev_macs and prev_macs:
        detail = f"IP {ip} previously owned by {sorted(prev_macs)}, now claimed by {mac}"
        log.warning("IP SPOOF? %s", detail)
        cur.execute("INSERT INTO events (timestamp,severity,event_type,mac,ip,detail) VALUES (?,?,?,?,?,?)",
                    (now,"HIGH","IP_SPOOF",mac,ip,detail))
        conn.commit()

    conn.close()

def log_new_device(mac, ip):
    now = datetime.utcnow().isoformat()
    conn = db_conn(); cur = conn.cursor()
    if not cur.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone():
        detail = f"New device: MAC={mac}  IP={ip}  Vendor={oui_vendor(mac)}"
        log.info("%s", detail)
        cur.execute("INSERT INTO events (timestamp,severity,event_type,mac,ip,detail) VALUES (?,?,?,?,?,?)",
                    (now,"INFO","NEW_DEVICE",mac,ip,detail))
        conn.commit()
    conn.close()

def packet_handler(pkt):
    if ARP in pkt:
        mac = pkt[Ether].src if Ether in pkt else pkt[ARP].hwsrc
        ip  = pkt[ARP].psrc
        log_new_device(mac, ip)
        record_arp(mac, ip)

def start_sniffer(iface):
    log.info("ARP sniffer starting on %s", iface)
    sniff(iface=iface, filter="arp", prn=packet_handler, store=False)

# ─────────────────────────────────────────────────────────────────────────────
#  SWITCH POLLING
# ─────────────────────────────────────────────────────────────────────────────

def parse_snoop_bindings(raw, host):
    now = datetime.utcnow().isoformat()
    conn = db_conn(); cur = conn.cursor()
    pat = re.compile(r"([0-9a-fA-F:]{17})\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\S+\s+(\d+)\s+(\S+)")
    count = 0
    for m in pat.finditer(raw):
        mac, ip, lease, vlan, intf = m.groups()
        cur.execute("INSERT INTO snoop_bindings (mac,ip,vlan,interface,lease_time,switch_host,pulled_at) VALUES (?,?,?,?,?,?,?)",
                    (mac.lower(), ip, vlan, intf, lease, host, now))
        count += 1
    conn.commit(); conn.close()
    log.info("Stored %d DHCP snooping bindings from %s", count, host)

def parse_dai_stats(raw, host):
    now = datetime.utcnow().isoformat()
    conn = db_conn(); cur = conn.cursor()
    pat = re.compile(r"(\d+)\s+(\d+)\s+(\d+)")
    count = 0
    for m in pat.finditer(raw):
        vlan, fwd, drop = m.groups()
        cur.execute("INSERT INTO dai_stats (interface,vlan,forwarded,dropped,switch_host,pulled_at) VALUES (?,?,?,?,?,?)",
                    ("N/A", vlan, int(fwd), int(drop), host, now))
        count += 1
    conn.commit(); conn.close()
    log.info("Stored %d DAI stat rows from %s", count, host)

def pull_switch_data():
    if not NETMIKO_AVAILABLE:
        log.warning("Netmiko unavailable — switch polling skipped.")
        return
    if not SWITCH_CONFIGS:
        log.info("No switches configured.")
        return
    for cfg in SWITCH_CONFIGS:
        label   = cfg.get("_label", cfg.get("host", "switch"))
        net_cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
        try:
            log.info("Polling switch: %s", label)
            with ConnectHandler(**net_cfg) as net:
                if cfg.get("secret"):
                    net.enable()
                snoop_raw = net.send_command("show ip dhcp snooping binding")
                dai_raw   = net.send_command("show ip arp inspection statistics")
            parse_snoop_bindings(snoop_raw, label)
            parse_dai_stats(dai_raw, label)
        except Exception as e:
            log.error("Switch %s error: %s", label, e)

def switch_poll_loop(interval=300):
    while True:
        pull_switch_data()
        time.sleep(interval)

# ─────────────────────────────────────────────────────────────────────────────
#  DEMO DATA
# ─────────────────────────────────────────────────────────────────────────────
DEMO_MACS = [
    ("aa:bb:cc:11:22:33", "192.168.1.10", "Cisco"),
    ("de:ad:be:ef:00:01", "192.168.1.20", "Apple"),
    ("b8:27:eb:12:34:56", "192.168.1.30", "Raspberry Pi"),
    ("00:50:56:ab:cd:ef", "192.168.1.40", "VMware"),
    ("f0:18:98:aa:bb:cc", "192.168.1.50", "Apple"),
]

def seed_demo_data():
    log.info("Seeding demo data…")
    conn = db_conn(); cur = conn.cursor()
    now = datetime.utcnow()
    for mac, ip, vendor in DEMO_MACS:
        cur.execute("INSERT OR IGNORE INTO devices (mac,ip,vendor,first_seen,last_seen,packet_count,trusted) VALUES (?,?,?,?,?,?,?)",
                    (mac, ip, vendor, (now-timedelta(hours=12)).isoformat(), (now-timedelta(minutes=5)).isoformat(), 142, 1))
    cur.execute("INSERT OR IGNORE INTO devices (mac,ip,vendor,first_seen,last_seen,packet_count,trusted) VALUES (?,?,?,?,?,?,?)",
                ("ca:fe:ba:be:00:01","192.168.1.10","Unknown",
                 (now-timedelta(minutes=20)).isoformat(),(now-timedelta(minutes=18)).isoformat(),4,0))
    for i,(sev,etype,mac,ip,detail) in enumerate([
        ("INFO","NEW_DEVICE","aa:bb:cc:11:22:33","192.168.1.10","New device detected"),
        ("INFO","NEW_DEVICE","de:ad:be:ef:00:01","192.168.1.20","New device detected"),
        ("HIGH","IP_SPOOF","ca:fe:ba:be:00:01","192.168.1.10",
         "IP 192.168.1.10 previously owned by ['aa:bb:cc:11:22:33'], now claimed by ca:fe:ba:be:00:01"),
        ("HIGH","MAC_SPOOF","aa:bb:cc:11:22:33","192.168.1.99",
         "MAC aa:bb:cc:11:22:33 previously seen with ['192.168.1.10'], now claiming 192.168.1.99"),
        ("MEDIUM","NEW_DEVICE","b8:27:eb:12:34:56","192.168.1.30","New Raspberry Pi joined network"),
    ]):
        cur.execute("INSERT INTO events (timestamp,severity,event_type,mac,ip,detail) VALUES (?,?,?,?,?,?)",
                    ((now-timedelta(minutes=60-i*10)).isoformat(),sev,etype,mac,ip,detail))
    for mac,ip,vlan,intf,lease,sw in [
        ("aa:bb:cc:11:22:33","192.168.1.10","10","GigE0/1","86400","sw1"),
        ("de:ad:be:ef:00:01","192.168.1.20","10","GigE0/2","86400","sw1"),
        ("b8:27:eb:12:34:56","192.168.1.30","20","GigE0/5","43200","sw1"),
        ("00:50:56:ab:cd:ef","192.168.1.40","20","GigE0/6","43200","sw2"),
        ("f0:18:98:aa:bb:cc","192.168.1.50","30","GigE1/1","28800","sw2"),
    ]:
        cur.execute("INSERT INTO snoop_bindings (mac,ip,vlan,interface,lease_time,switch_host,pulled_at) VALUES (?,?,?,?,?,?,?)",
                    (mac,ip,vlan,intf,lease,sw,now.isoformat()))
    for vlan,fwd,drop,sw in [("10",4821,3,"sw1"),("20",1203,12,"sw1"),("30",892,0,"sw2")]:
        cur.execute("INSERT INTO dai_stats (interface,vlan,forwarded,dropped,switch_host,pulled_at) VALUES (?,?,?,?,?,?)",
                    ("N/A",vlan,fwd,drop,sw,now.isoformat()))
    conn.commit(); conn.close()
    log.info("Demo data seeded.")

# ─────────────────────────────────────────────────────────────────────────────
#  FLASK API
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
HTML_PAGE  = open(_html_path).read()

@app.route("/")
def index(): return render_template_string(HTML_PAGE)

@app.route("/api/devices")
def api_devices():
    conn = db_conn()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/events")
def api_events():
    conn = db_conn()
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 200").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/snoop")
def api_snoop():
    conn = db_conn()
    rows = conn.execute("""SELECT s.*,d.vendor,d.trusted FROM snoop_bindings s
                           LEFT JOIN devices d ON s.mac=d.mac
                           ORDER BY s.pulled_at DESC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/dai")
def api_dai():
    conn = db_conn()
    rows = conn.execute("SELECT * FROM dai_stats ORDER BY pulled_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/summary")
def api_summary():
    conn = db_conn(); d = {}
    d["total_devices"]       = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    d["trusted_devices"]     = conn.execute("SELECT COUNT(*) FROM devices WHERE trusted=1").fetchone()[0]
    d["total_events"]        = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    d["high_alerts"]         = conn.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
    d["spoof_events"]        = conn.execute("SELECT COUNT(*) FROM events WHERE event_type IN ('MAC_SPOOF','IP_SPOOF')").fetchone()[0]
    d["snoop_bindings"]      = conn.execute("SELECT COUNT(*) FROM snoop_bindings").fetchone()[0]
    d["dai_dropped_packets"] = conn.execute("SELECT COALESCE(SUM(dropped),0) FROM dai_stats").fetchone()[0]
    conn.close(); return jsonify(d)

@app.route("/api/switches")
def api_switches():
    return jsonify([{"label": s.get("_label",""), "type": s.get("device_type","")}
                    for s in SWITCH_CONFIGS])

@app.route("/api/pull-switch", methods=["POST"])
def api_pull_switch():
    threading.Thread(target=pull_switch_data, daemon=True).start()
    return jsonify({"status": "triggered"})

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sniffer_iface, bind_host, dash_port = wizard()

    init_db()

    conn = db_conn()
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    conn.close()
    if count == 0:
        seed_demo_data()

    if SCAPY_AVAILABLE and sniffer_iface:
        threading.Thread(target=start_sniffer, args=(sniffer_iface,), daemon=True).start()
        log.info("Sniffer active on %s", sniffer_iface)

    threading.Thread(target=switch_poll_loop, args=(300,), daemon=True).start()

    if SWITCH_CONFIGS:
        threading.Thread(target=pull_switch_data, daemon=True).start()

    log.info("Dashboard → http://%s:%d", bind_host, dash_port)
    print(f"\n  {c(GREEN, '●')}  Dashboard running at {c(CYAN, f'http://localhost:{dash_port}')}\n")

    app.run(host=bind_host, port=dash_port, debug=False)
