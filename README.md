# 🦉 ORouteX

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ONetwork%20%2F%20Protocol%20Security-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Requires-Root-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ORouteX** is a routing protocol security testing suite — CDP spoofing, HSRP hijack, IGRP route injection, and multi-threaded network mass scanning for authorised penetration testing engagements.

---

> ⚠️ **AUTHORISED PENETRATION TESTING USE ONLY** — Use only on networks you own or have explicit written permission to test. Unauthorised use is illegal and unethical.

---

## 📌 Overview

ORouteX tests the resilience of network infrastructure against routing protocol attacks. It crafts and injects raw packets directly onto the network segment, targeting Cisco and legacy routing protocols commonly found in enterprise environments.

---

## 🖥️ Modules

| # | Module | Protocol | Description |
|---|--------|----------|-------------|
| **[1]** | **CDP Spoof** | CDP | Continuously sends forged Cisco Discovery Protocol announcements, impersonating a rogue Cisco device on the LAN segment |
| **[2]** | **HSRP Hijack** | HSRP | Floods `224.0.0.2:1985` with maximum-priority Hello packets to seize the Active Router role and redirect network traffic |
| **[3]** | **IGRP Route Injection** | IGRP | Crafts and sends IGRP Update packets (IP proto 9) to poison the routing tables of legacy Cisco routers still running IGRP |
| **[4]** | **Netmass Scanner** | ICMP/TCP | ICMP host discovery across a CIDR range followed by multi-threaded TCP connect scan — results exported as timestamped JSON |

---

## 🔬 Module Details

### [1] CDP Spoof
Sends forged CDP packets to the CDP multicast address `01:00:0c:cc:cc:cc` with a configurable fake device name, platform string, and Cisco IOS version banner. Runs continuously until stopped with Ctrl+C.

**Configurable:** Interface · Target IP · Fake device name · Fake platform

### [2] HSRP Hijack
Sends 100 HSRP Hello packets with `state=Active` and `priority=255` (highest possible) to force this machine to become the Active router for the configured group. Supports configurable group number and authentication password.

**Configurable:** Interface · Virtual IP · HSRP group · Password

### [3] IGRP Route Injection
Sends 50 IGRP Update packets injecting a custom route (`/24` mask) into the routing table of legacy routers still running IGRP. Targets the IGRP multicast `224.0.0.9`.

**Configurable:** Interface · Target network · Route metric · AS number

### [4] Netmass Scanner
Performs ICMP ping discovery across all hosts in a CIDR range, then TCP connect-scans configurable ports on each live host. Default ports: `21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 8080, 8443`. Results saved to `netmass_YYYYMMDD_HHMMSS.json`.

**Configurable:** CIDR range · Port list · Thread count (default 50)

---

## ⚙️ Requirements

- **Linux** — uses raw sockets (AF_PACKET)
- **Root privileges** — required for all modules
- **Scapy** with CDP contrib — required for CDP Spoof module
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
sudo ./ORouteX
```

---

## 📤 Output

| Module | Output |
|--------|--------|
| **Netmass Scanner** | `netmass_YYYYMMDD_HHMMSS.json` — network, live hosts, open ports per IP |

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
