<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.0+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/nmap-Required-orange.svg" alt="nmap">
</p>

<h1 align="center">🔧 Pentool</h1>

<p align="center">
  <strong>Professional Reconnaissance & Network Scanning Toolkit</strong>
</p>

<p align="center">
  A polished security toolkit featuring a modern dark-themed web interface with<br>
  Chart.js visualizations and Three.js 3D topology. Supports both mock demo mode<br>
  and secured real scanning with nmap integration.
</p>

---

## ✨ Features

### Dual Operation Modes
- **Mock Mode** - Safe demo mode for development and presentations
- **Real Mode** - Actual nmap scans with full security controls

### Security Controls
- **Token Authentication** - Secure API access with bearer tokens
- **Network Whitelist** - Restrict scanning to authorized networks only
- **Audit Logging** - Complete activity tracking for compliance
- **Job Management** - Background execution with status tracking

### Modern Web Interface
- **Dark Theme UI** - Professional, eye-friendly design
- **Chart.js Integration** - Interactive data visualizations
- **Three.js Topology** - 3D network visualization
- **Real-time Updates** - Live scan progress and results

### Reporting
- **JSON Reports** - Structured, parseable output
- **SQLite Database** - Persistent job history
- **Export Options** - Download reports directly from UI

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- nmap (for real scans)
- Linux (Arch/BlackArch, Debian/Ubuntu, Kali)

### Installation

```bash
# Clone the repository
git clone https://github.com/BlackOussema/Pentool.git
cd Pentool/Pentool

# Install system dependencies
# Arch/BlackArch
sudo pacman -S nmap

# Debian/Ubuntu/Kali
sudo apt install -y nmap

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install flask python-nmap
```

### Running the Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start the server
python -m pentool.web.app

# Server runs at http://127.0.0.1:3000
```

---

## 📡 API Reference

### Mock Endpoints (No Authentication)

#### Mock Scan
```http
POST /api/scan
Content-Type: application/json

{
  "target": "127.0.0.1",
  "ports": "1-1024",
  "mode": "mock"
}
```

#### Mock Recon
```http
POST /api/recon
Content-Type: application/json

{
  "target": "127.0.0.1",
  "mode": "mock"
}
```

### Secured Endpoints (Token Required)

#### Real Network Scan
```http
POST /api/scan_network
X-PENTOOL-AUTH: your-secret-token
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "ports": "top",
  "async": true,
  "extra_args": "-sV"
}
```

Response:
```json
{
  "status": "submitted",
  "job_id": 1
}
```

#### Check Job Status
```http
GET /api/job/{job_id}
X-PENTOOL-AUTH: your-secret-token
```

#### List All Jobs
```http
GET /api/list_jobs
X-PENTOOL-AUTH: your-secret-token
```

#### Get Latest Report
```http
GET /api/report.json
```

#### List All Reports
```http
GET /api/list_reports
```

---

## ⚙️ Configuration

### Authentication Token

Edit `pentool/web/app.py` and replace the default token:

```python
VALID_TOKENS = {
    "your-strong-secret-token": {"user": "admin"}
}
```

### Network Whitelist

Configure allowed networks in `pentool/web/app.py`:

```python
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Localhost
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
    # Add your authorized networks here
]
```

---

## 📁 Project Structure

```
Pentool/
├── pentool/
│   ├── __init__.py
│   ├── web/
│   │   ├── __init__.py
│   │   └── app.py              # Flask API server
│   ├── web_static/
│   │   ├── index.html          # Web interface
│   │   └── *.json              # Generated reports
│   ├── recon/
│   │   ├── __init__.py
│   │   └── scanner.py          # Scanner utilities
│   ├── pentool.db              # SQLite job database
│   └── pentool_recon.log       # Audit log
└── README.md
```

---

## 🔒 Security Best Practices

### Before Production Use

1. **Change Default Token**
   ```python
   # Generate a strong token
   import secrets
   print(secrets.token_urlsafe(32))
   ```

2. **Restrict Network Binding**
   ```python
   # Bind to localhost only
   app.run(host="127.0.0.1", port=3000)
   ```

3. **Use Reverse Proxy**
   - Deploy behind nginx/Apache with HTTPS
   - Add rate limiting
   - Enable additional authentication

4. **Monitor Logs**
   ```bash
   tail -f pentool/pentool_recon.log
   ```

### Scanning Guidelines

- Start with light scans (`ports: "top"`)
- Avoid aggressive timing on production networks
- Always verify target authorization
- Review results before sharing

---

## 💻 Usage Examples

### Mock Scan (Development)
```bash
curl -X POST http://127.0.0.1:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","mode":"mock"}' | jq .
```

### Real Async Scan
```bash
# Submit scan job
curl -X POST http://127.0.0.1:3000/api/scan_network \
  -H "Content-Type: application/json" \
  -H "X-PENTOOL-AUTH: your-token" \
  -d '{"target":"192.168.1.0/24","ports":"top","async":true}' | jq .

# Check job status
curl -H "X-PENTOOL-AUTH: your-token" \
  http://127.0.0.1:3000/api/job/1 | jq .

# Download report
curl http://127.0.0.1:3000/api/report.json -o report.json
```

### Synchronous Scan
```bash
curl -X POST http://127.0.0.1:3000/api/scan_network \
  -H "Content-Type: application/json" \
  -H "X-PENTOOL-AUTH: your-token" \
  -d '{"target":"127.0.0.1","ports":"22,80,443","async":false}' | jq .
```

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| 404 at `/` | Check `STATIC_FOLDER` path and `index.html` exists |
| Real scan fails | Verify `nmap` and `python-nmap` are installed |
| 401 Unauthorized | Check `X-PENTOOL-AUTH` header and token |
| 403 Forbidden | Target is outside whitelist - update `ALLOWED_NETWORKS` |
| No reports | Run a scan first, check `web_static/` directory |

### Debug Commands
```bash
# Check logs
tail -n 200 pentool/pentool_recon.log

# List reports
ls -lh pentool/web_static/*.json

# Verify nmap
nmap --version

# Test Python nmap
python -c "import nmap; print(nmap.PortScanner())"
```

---

## 📊 Sample Report Output

```json
{
  "generated_at": "2024-01-15T10:30:00Z",
  "targets": [
    {
      "host": "192.168.1.1",
      "state": "up",
      "ports_scan": {
        "tcp": {
          "22": {
            "state": "open",
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.9"
          },
          "80": {
            "state": "open",
            "name": "http",
            "product": "nginx",
            "version": "1.24.0"
          }
        }
      }
    }
  ]
}
```

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.**

- Only scan networks and systems you own or have explicit written permission to test
- Unauthorized scanning is illegal and may result in criminal charges
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Ghariani Oussema**
- GitHub: [@BlackOussema](https://github.com/BlackOussema)
- Role: Cyber Security Researcher & Full-Stack Developer
- Location: Tunisia 🇹🇳

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
