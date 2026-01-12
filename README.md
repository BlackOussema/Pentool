# 🔧 Pentool: Professional Reconnaissance & Network Scanning Toolkit

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![nmap](https://img.shields.io/badge/nmap-Required-orange.svg)

## Overview

Pentool is a sophisticated security toolkit designed for professional reconnaissance and network scanning. It features a modern, dark-themed web interface with interactive Chart.js visualizations and Three.js 3D topology mapping. The tool supports both a safe mock demo mode and a secured real scanning mode with robust `nmap` integration.

This toolkit is ideal for cybersecurity professionals, penetration testers, and security researchers who require a powerful, yet user-friendly platform for network assessment and vulnerability identification.

## Features

### Dual Operation Modes
*   **Mock Mode**: A safe demonstration mode for development, presentations, and testing without performing actual network scans.
*   **Real Mode**: Executes actual `nmap` scans with full security controls, providing accurate and up-to-date network intelligence.

### Security Controls
*   **Token Authentication**: Secure API access is enforced using bearer tokens, ensuring only authorized users can initiate scans.
*   **Network Whitelist**: Restricts scanning to pre-defined, authorized networks, preventing accidental or unauthorized scans on external systems.
*   **Audit Logging**: Comprehensive activity tracking for all scan operations, crucial for compliance and post-incident analysis.
*   **Job Management**: Supports background execution of scan jobs with real-time status tracking, allowing for efficient handling of long-running tasks.

### Modern Web Interface
*   **Dark Theme UI**: A professional and eye-friendly dark-themed user interface enhances user experience during prolonged use.
*   **Chart.js Integration**: Interactive data visualizations powered by Chart.js provide clear insights into scan results and network statistics.
*   **Three.js Topology**: Offers a unique 3D network visualization, helping users understand network layouts and device relationships.
*   **Real-time Updates**: Live updates on scan progress and results keep users informed without manual refreshing.

### Reporting
*   **JSON Reports**: Generates structured, machine-readable JSON reports for easy integration with other tools and automated analysis.
*   **SQLite Database**: Maintains a persistent job history in an SQLite database, allowing users to review past scans and results.
*   **Export Options**: Provides options to download reports directly from the user interface for offline analysis and documentation.

## Quick Start

### Prerequisites
*   Python 3.10+
*   `nmap` (Network Mapper) - essential for real scanning functionalities.
*   Linux operating system (e.g., Arch/BlackArch, Debian/Ubuntu, Kali) is recommended for optimal compatibility with `nmap`.

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/BlackOussema/Pentool.git
    cd Pentool/Pentool
    ```

2.  **Install system dependencies**:
    *   **Arch/BlackArch**:
        ```bash
        sudo pacman -S nmap
        ```
    *   **Debian/Ubuntu/Kali**:
        ```bash
        sudo apt install -y nmap
        ```

3.  **Create a virtual environment (recommended)**:
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```

4.  **Install Python dependencies**:
    ```bash
    pip install flask python-nmap
    ```

### Running the Server

1.  **Activate virtual environment**:
    ```bash
    source venv/bin/activate
    ```

2.  **Start the server**:
    ```bash
    python -m pentool.web.app
    ```

    The server will typically run at `http://127.0.0.1:3000`.

## API Reference

### Mock Endpoints (No Authentication Required)

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

#### Mock Reconnaissance
```http
POST /api/recon
Content-Type: application/json

{
  "target": "127.0.0.1",
  "mode": "mock"
}
```

### Secured Endpoints (Authentication Token Required)

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

**Response**:
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

## Configuration

### Authentication Token

To secure your Pentool instance, you **must** change the default authentication token. Edit `pentool/web/app.py` and update the `VALID_TOKENS` dictionary:

```python
VALID_TOKENS = {
    "your-strong-secret-token": {"user": "admin"} # Replace with a strong, unique token
}
```

### Network Whitelist

Configure the allowed networks for scanning in `pentool/web/app.py` to prevent unauthorized scans. Add your authorized network ranges to the `ALLOWED_NETWORKS` list:

```python
import ipaddress

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Localhost
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
    # Add your authorized networks here, e.g., ipaddress.ip_network("192.168.1.0/24")
]
```

## Project Structure

```
Pentool/
├── pentool/
│   ├── __init__.py
│   ├── web/
│   │   ├── __init__.py
│   │   └── app.py              # Flask API server and web application logic
│   ├── web_static/
│   │   ├── index.html          # Main web interface file
│   │   └── *.json              # Directory for generated scan reports
│   ├── recon/
│   │   ├── __init__.py
│   │   └── scanner.py          # Core scanning utilities and nmap integration
│   ├── pentool.db              # SQLite database for job history and configurations
│   └── pentool_recon.log       # Audit log for all scanning activities
└── README.md                   # Project documentation (this file)
```

## Security Best Practices

### Before Production Use

1.  **Change Default Token**: Generate a strong, unique token for `X-PENTOOL-AUTH` using a secure method (e.g., `import secrets; print(secrets.token_urlsafe(32))`).
2.  **Restrict Network Binding**: For enhanced security, bind the Flask application to `localhost` only (`app.run(host="127.0.0.1", port=3000)`) and use a reverse proxy for external access.
3.  **Use Reverse Proxy**: Deploy Pentool behind a robust reverse proxy like Nginx or Apache. Configure HTTPS, add rate limiting, and consider additional authentication layers.
4.  **Monitor Logs**: Regularly monitor `pentool/pentool_recon.log` for any suspicious activities or unauthorized access attempts.

### Scanning Guidelines

*   **Start with Light Scans**: Begin with less intrusive scans (e.g., `ports: "top"`) to understand the target environment before escalating.
*   **Avoid Aggressive Timing**: Do not use aggressive timing options on production networks to prevent service disruption.
*   **Verify Authorization**: Always ensure you have explicit written authorization before scanning any network or system.
*   **Review Results**: Thoroughly review scan results before sharing or acting upon them.

## Usage Examples

### Mock Scan (Development/Testing)
```bash
curl -X POST http://127.0.0.1:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","mode":"mock"}' | jq .
```

### Real Asynchronous Scan
```bash
# Submit scan job
curl -X POST http://127.0.0.1:3000/api/scan_network \
  -H "Content-Type: application/json" \
  -H "X-PENTOOL-AUTH: your-token" \
  -d '{"target":"192.168.1.0/24","ports":"top","async":true}' | jq .

# Check job status (replace 1 with actual job_id)
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

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `404` at `/` | Verify `STATIC_FOLDER` path in `app.py` and ensure `index.html` exists in `web_static/` |
| Real scan fails | Confirm `nmap` and `python-nmap` are correctly installed and accessible |
| `401 Unauthorized` | Check the `X-PENTOOL-AUTH` header and ensure the token is valid and matches `VALID_TOKENS` |
| `403 Forbidden` | The target network might be outside the `ALLOWED_NETWORKS` whitelist. Update `ALLOWED_NETWORKS` in `app.py` |
| No reports generated | Ensure a scan has been successfully completed and check the `web_static/` directory for JSON files |

### Debug Commands
```bash
# Check Pentool logs
tail -n 200 pentool/pentool_recon.log

# List generated reports
ls -lh pentool/web_static/*.json

# Verify nmap installation
nmap --version

# Test Python nmap binding
python -c "import nmap; print(nmap.PortScanner())"
```

## Sample Report Output

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

## Legal Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

*   Only scan networks and systems for which you have explicit written permission from the owner.
*   Unauthorized scanning or access to computer systems is illegal and may result in severe legal consequences.
*   The authors and contributors are not responsible for any misuse or damage caused by this tool.
*   Always adhere to responsible disclosure practices when identifying vulnerabilities.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Author

**Ghariani Oussema**
*   GitHub: [@BlackOussema](https://github.com/BlackOussema)
*   Role: Cybersecurity Researcher & Full-Stack Developer
*   Location: Tunisia 🇹🇳

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
