# 🛡️ CyberForge — Forensics Platform Backend

Production-grade backend for the **AI-Powered Malware Analysis, Digital Forensics & Threat Intelligence Platform**, built for law enforcement cyber units, SOC analysts, and CERT teams.

---

## What's Real Here

This is a **fully functional backend** — not a mock. Specifically:

| Component | Status |
|---|---|
| SHA-256/SHA-1/MD5/SHA-512 hashing | ✅ Real (Python hashlib) |
| PE file parsing (sections, imports, entropy) | ✅ Real (`pefile`) |
| YARA rule scanning | ✅ Real (`yara-python`, 30+ custom rules included) |
| IOC extraction (domains/IPs/URLs/regkeys/wallets) | ✅ Real (regex-based string analysis) |
| MITRE ATT&CK mapping | ✅ Real (rule-based mapping engine) |
| VirusTotal integration | ✅ Real (needs your API key) |
| AbuseIPDB integration | ✅ Real (needs your API key) |
| PDF forensic report generation | ✅ Real (ReportLab, court-style report) |
| CIPHER AI Assistant (Claude) | ✅ Real (needs `ANTHROPIC_API_KEY`) |
| Case management + chain of custody | ✅ Real (PostgreSQL + audit log) |
| Dynamic sandbox execution | ❌ Not included — needs Cuckoo/Any.Run integration |
| Memory forensics (Volatility) | ❌ Not included — separate module needed |
| Network/PCAP deep analysis | ⚠️ Partial — basic PCAP file handling only |

---

## Quick Start (Docker — Recommended)

```bash
# 1. Set your API keys
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export ANTHROPIC_API_KEY="your_key_here"

# 2. Bring up the full stack
docker-compose up --build

# 3. API is now live at http://localhost:8000
# Interactive docs: http://localhost:8000/docs
```

## Quick Start (Local Development)

```bash
chmod +x setup.sh
./setup.sh

# Start Postgres + Redis only via Docker
docker-compose up postgres redis -d

# Run the API
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Architecture

```
cyberforge-backend/
├── app/
│   ├── main.py                 # FastAPI app entrypoint
│   ├── config.py                # Settings (env vars)
│   ├── database.py              # SQLAlchemy session management
│   ├── models/
│   │   └── models.py            # ORM models: Case, Sample, IOC, AuditLog, User
│   ├── schemas/
│   │   └── schemas.py           # Pydantic request/response models
│   ├── core/                    # ★ Analysis engines (the "brain") ★
│   │   ├── hash_engine.py       # Crypto hash computation, entropy calc
│   │   ├── pe_parser.py         # Full PE structure parser (pefile)
│   │   ├── yara_scanner.py      # YARA rule compilation + scanning
│   │   ├── ioc_extractor.py     # Regex-based IOC extraction
│   │   ├── mitre_mapper.py      # API/YARA family → ATT&CK technique mapping
│   │   ├── static_analyzer.py   # Orchestrates the full analysis pipeline
│   │   ├── report_generator.py  # PDF forensic report builder
│   │   └── intel/
│   │       ├── virustotal.py    # VT API v3 client
│   │       └── abuseipdb.py     # AbuseIPDB API client
│   └── api/routes/
│       ├── samples.py           # Upload, analyze, retrieve samples
│       ├── cases.py             # Case CRUD + chain-of-custody notes
│       ├── cipher.py            # CIPHER AI chat (Claude-powered)
│       ├── dashboard.py         # Stats, weekly activity, IOC database
│       ├── mitre.py             # Org-wide ATT&CK matrix aggregation
│       └── reports.py           # PDF report download endpoint
├── yara_rules/                  # 30+ custom YARA rules across 6 categories
│   ├── ransomware.yar
│   ├── injection.yar
│   ├── persistence.yar
│   ├── packers.yar
│   ├── c2_patterns.yar
│   └── infostealer.yar
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── setup.sh
```

---

## Key API Endpoints

### Sample Analysis
```
POST   /api/samples/upload-sync       # Upload + analyze in one request (recommended)
POST   /api/samples/upload            # Upload + analyze in background
GET    /api/samples/{id}              # Get full analysis results
GET    /api/samples                   # List samples (filter by case/threat level)
POST   /api/samples/{id}/rescan       # Re-run analysis (e.g. after YARA updates)
```

### Case Management
```
POST   /api/cases                     # Create new case
GET    /api/cases                     # List all cases
PATCH  /api/cases/{id}                # Update case status/severity
POST   /api/cases/{id}/notes          # Add chain-of-custody note
```

### CIPHER AI Assistant
```
POST   /api/cipher/chat               # Chat with Claude (auto-injects sample context)
```

### Threat Intelligence
```
GET    /api/iocs                      # Search global IOC database
GET    /api/iocs/export?format=stix   # Export IOCs as STIX 2.1 bundle
GET    /api/mitre/matrix              # Org-wide ATT&CK heatmap
```

### Reports
```
GET    /api/reports/sample/{id}/pdf   # Download court-style PDF report
```

### Dashboard
```
GET    /api/dashboard/stats           # Total files/cases/threats/IOCs
GET    /api/dashboard/weekly-activity # 7-day trend data
GET    /api/dashboard/threat-families # Top malware families detected
```

Full interactive documentation: **`/docs`** (Swagger UI, auto-generated)

---

## Connecting the Frontend

The React MVP (`cyberforge-platform.jsx`) currently calls the Anthropic API directly from the browser. To connect it to this real backend instead:

1. Replace the direct `fetch("https://api.anthropic.com/...")` call in the CIPHER component with:
   ```js
   fetch("http://localhost:8000/api/cipher/chat", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({ messages, sample_id: currentSampleId })
   })
   ```
2. Replace the simulated `buildAnalysis()` function with a real upload:
   ```js
   const formData = new FormData();
   formData.append("file", file);
   const res = await fetch("http://localhost:8000/api/samples/upload-sync", {
     method: "POST", body: formData
   });
   const sample = await res.json();
   ```
3. Point dashboard/case/IOC views at the corresponding `/api/...` endpoints instead of hardcoded sample data.

This keeps your Anthropic API key safely server-side instead of exposed in browser JS.

---

## YARA Rules Included

30+ rules across 6 files, covering:
- **Ransomware**: Ryuk, LockBit, WannaCry, generic shadow-copy deletion, encryption API patterns
- **Process Injection**: classic injection, process hollowing, APC injection, reflective DLL injection
- **Persistence**: registry run keys, scheduled tasks, services, WMI event subscriptions, bootkits
- **Packers/Obfuscation**: UPX, MPRESS, PowerShell encoded commands, VBA macro obfuscation
- **C2 Communication**: HTTP C2 gates, DNS tunneling, Cobalt Strike beacons, Meterpreter, TOR
- **Infostealers**: browser credential theft, LSASS dumping, keyloggers, clipboard hijacking, crypto wallet theft

Add your own rules by dropping `.yar` files into `yara_rules/` and calling `POST /api/samples/{id}/rescan`, or restart the service to pick up new rules at boot.

---

## Production Hardening Checklist

Before deploying to a real law enforcement environment:

- [ ] Add JWT authentication + RBAC (User model is ready; auth routes not yet implemented)
- [ ] Enable MFA for analyst accounts
- [ ] Run file analysis inside an isolated sandbox/VM (this backend does *static* analysis only — files are never executed)
- [ ] Add rate limiting on upload endpoints
- [ ] Configure TLS termination (nginx/Caddy in front of FastAPI)
- [ ] Set up automated PostgreSQL backups
- [ ] Restrict `ALLOWED_ORIGINS` to your actual frontend domain
- [ ] Rotate `SECRET_KEY` and store API keys in a secrets manager (not `.env` in production)
- [ ] Add Volatility3 integration for memory forensics
- [ ] Add Cuckoo Sandbox / Any.Run integration for dynamic analysis
- [ ] Implement evidence retention policy + secure deletion
- [ ] Add request/response audit logging at the infrastructure level

---

## Environment Variables

See `.env.example` for the full list. Required for full functionality:

| Variable | Purpose | Required? |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `ANTHROPIC_API_KEY` | Powers CIPHER AI assistant | Yes (for AI chat) |
| `VIRUSTOTAL_API_KEY` | Hash reputation lookups | Optional (graceful fallback) |
| `ABUSEIPDB_API_KEY` | IP reputation lookups | Optional (graceful fallback) |

The platform works without VT/AbuseIPDB keys — those lookups are simply skipped, and risk scoring relies on YARA + PE static analysis instead.
