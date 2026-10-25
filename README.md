# 🦉 ORouteX

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OAttack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ORouteX** — Routing Protocol Attack Suite ║

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

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
