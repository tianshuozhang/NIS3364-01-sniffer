<div align="center">

# 🕵️ NIS3364-01-sniffer

**A GUI network packet sniffer built with Scapy & Tkinter**
**基于 Scapy 与 Tkinter 的图形化网络嗅探器**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2C3E50?style=flat-square)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)

</div>

---

## 📖 Overview · 简介

**English** — Course project for *NIS3364*. A Wireshark-like packet capture tool for Windows: pick a NIC, set a capture filter, inspect each packet layer by layer, view traffic statistics, reassemble fragmented IP packets and save/load logs.

**中文** — *NIS3364* 课程设计。一个运行在 Windows 上的类 Wireshark 抓包工具：选择网卡、设置过滤器、逐层解析数据包、统计流量、重组 IP 分片，并支持日志的保存与读取。

## ✨ Features · 功能

| Feature · 功能 | Description · 说明 |
| --- | --- |
| 🖧 NIC selection · 网卡选择 | List all available interfaces on the host · 列出本机所有可用网卡 |
| 🔍 Capture filter · 捕获过滤器 | Filter by source / destination address, protocol, etc. (BPF) · 按源/目的地址、协议类型等过滤 |
| 📋 Packet list · 数据包列表 | Per-layer field tree + raw hexdump · 分层字段树与原始十六进制数据 |
| 📊 Statistics · 会话统计 | Ethernet & IP statistics · 以太网统计、IP 统计 |
| 🧩 IP reassembly · IP 重组 | Reassemble fragmented packets via flags · 依据分片标志重组报文 |
| 💾 Logging · 日志记录 | Save as `.pcap` (reopen in app / Wireshark) or `.txt` · 支持 pcap 与 txt 两种格式 |

## 📁 Structure · 目录结构

```text
NIS3364-01-sniffer
├── source/
│   ├── packet.py   # main window: NIC, filter, packet table, logging
│   ├── static.py   # statistics & IP reassembly windows
│   ├── pcaps/      # saved .pcap logs
│   └── txts/       # saved .txt logs
└── bin/
    ├── packet.spec # PyInstaller spec
    └── dist/packet.exe  # prebuilt Windows executable
```

## 🚀 Quick Start · 快速开始

```bash
# Option 1: run from source (Npcap required on Windows)
pip install scapy
cd source
python packet.py

# Option 2: run the prebuilt executable
bin/dist/packet.exe
```

> Capturing packets usually requires administrator privileges.
> 抓包通常需要管理员权限。
