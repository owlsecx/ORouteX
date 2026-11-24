# 🦉 ORouteX

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OAttack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--2.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ORouteX** — Routing Protocol Attack Suite

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ORouteX is a routing-protocol security testing suite for Linux. It bundles modules for CDP, HSRP, IGRP, OSPF and RIP manipulation, ARP spoofing and network scanning, intended for authorised testing. It runs in a safe dry-run mode by default and requires explicit confirmation before transmitting live packets.

---

## ✨ Features

- Routing-protocol modules for CDP, HSRP, IGRP, OSPF and RIP
- ARP cache poisoning / MITM module
- ICMP host discovery with threaded TCP port scanning
- Session logging for recording and replaying scans
- Direct module launch from the command line
- Safe dry-run mode by default with an explicit live-transmission authorization flag

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
./ORouteX
./ORouteX --module 7
./ORouteX --module 4 --i-am-authorized
./ORouteX --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v2.0** — © 2026 Owlsec LLC

This tool links against [Scapy](https://scapy.net/) (GPL-2.0), so the tool as a whole is distributed under GPL-2.0. Its full source code is published in this repository (`ORouteX.py`).

> Other OwlSec tools are separate, independent programs and remain proprietary. This license applies only to this repository.

---

## 🔍 Verification & Transparency

This tool is closed-source. These files let you see exactly what is inside it,
without the source:

- [`SBOM.cdx.json`](SBOM.cdx.json) — CycloneDX inventory: SHA-256 of this
  binary, bundled CPython version, and every bundled library with its exact
  version and license. Feed it to Grype, Trivy or Dependency-Track to audit
  our dependencies for CVEs yourself.
- [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) — the full license text
  of every third-party component, extracted from this binary.

**No telemetry, no analytics, no licence check-in.** This tool does not phone
home. Verify that claim yourself:

```bash
sudo strace -f -e trace=network ./ORouteX --help   # watch every network call
firejail --net=none ./ORouteX --help               # deny the network entirely
```

Release signing, GPL compliance and vulnerability reporting:
[**TRUST.md**](https://github.com/owlsecx/owl-os/blob/main/TRUST.md)
