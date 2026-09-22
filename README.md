# 🛡️ CyberForge — AI-Powered Malware Analysis & Virtual Sandbox Platform

> **Forensics Platform v3.0** — Advanced static & dynamic malware analysis, behavioral virtualization, YARA scanning, MITRE ATT&CK mapping, PCAP network inspection, memory forensics, and CIPHER AI assistant.

---

## 🚀 Features

- 🖥️ **Live Virtual Sandbox Simulator**: Air-gapped VM simulation of file downloads, SmartScreen/UAC prompts, process injection, registry persistence, and C2 exfiltration attempts.
- ⚡ **Real-Time Static Analysis**: Automated PE parsing, entropy maps, cryptographic hashing (MD5, SHA-1, SHA-256, SSDeep), and string classification.
- 🎯 **Curated YARA Threat Scanning**: Pattern detection against 1000+ known signatures.
- 🗺️ **MITRE ATT&CK Matrix & IOC DB**: Automated tactic/technique mapping and indicator extraction.
- 🌐 **Network & Memory Forensics**: PCAP packet inspection and memory dump artifact extraction.
- 🤖 **CIPHER AI Investigator**: Incident triage and malware explanation assistant.
- 📋 **Machine Harm Report**: Detailed breakdown of system, data, credential, and network harm.

---

## 🏗️ Architecture

- **Frontend**: React 18, Vite, Lucide Icons, Recharts, Vanilla CSS Design System with dark mode glassmorphism.
- **Backend**: FastAPI (Python), SQLite / SQLAlchemy, Static Analyzers, WebSocket streaming.

---

## 💻 Getting Started

### 1. Prerequisites
- Python 3.9+
- Node.js 18+ and npm

### 2. Backend Setup
```bash
cd cyberforge-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Frontend Setup
```bash
cd cyberforge-frontend
npm install
npm run dev
```

Visit `http://localhost:5173/` in your browser.

---

## 🔒 Security Notice
CyberForge is designed for cybersecurity researchers, malware analysts, and educational environments. Always detonate untrusted binaries in isolated, air-gapped test environments.
