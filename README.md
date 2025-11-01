**Pentool** — a professional local recon and scanning toolkit with a polished dark-themed web interface using Chart.js and Three.js. It supports a safe **Mock** demo mode for development or presentation purposes and a secured **Real** mode that performs actual `nmap` scans with token-based authentication, whitelist enforcement, background job execution, JSON report generation, and detailed audit logging. **Legal notice:** only scan systems you own or have explicit written authorization to test.

**Project structure:** the `Pentool/` directory contains the `pentool/` package with `web/` (Flask server), `web_static/` (frontend HTML, JS, and saved JSON reports), `recon/` (scanner helper scripts), `pentool.db` (SQLite job database), and `pentool_recon.log` (audit log).

**Requirements:** Linux (Arch/BlackArch or Debian/Ubuntu), Python 3.10+, `nmap` for real scans, and Python packages `Flask` and `python-nmap`.

**Installation:** install system `nmap` (`sudo pacman -S nmap` or `sudo apt install -y nmap`), then create and activate a virtual environment from the project root: `python -m venv pentool-env && source pentool-env/bin/activate`, followed by `pip install --upgrade pip && pip install flask python-nmap`.

**Running the server:** with the virtual environment active, run `python -m pentool.web.app` and open `http://127.0.0.1:5000/`. The UI provides interactive mock scan/recon buttons, charts, 3D topology visualization, logs, and report download options. Mock mode works without external dependencies.

**Configuration before real scans:** replace `VALID_TOKENS` in `pentool/web/app.py` with a strong secret token, and update `ALLOWED_NETWORKS` to include only CIDR ranges you are authorized to scan.

**Mock usage:** call `/api/scan` or `/api/recon` via the frontend or curl, e.g., `curl -X POST -H "Content-Type: application/json" -d '{"target":"127.0.0.1"}' http://127.0.0.1:5000/api/scan`.

**Real scan workflow (secured and restricted):** ensure `nmap` and `python-nmap` are installed, submit an asynchronous scan to `/api/scan_network` with the token header `X-PENTOOL-AUTH`, which returns a `job_id`. Query job status via `/api/job/<job_id>` and download the latest JSON report from `/api/report.json`.

**Outputs and logs:** reports are saved in `pentool/web_static/` (`scan_<target>_<timestamp>.json`), the audit log is `pentool/pentool_recon.log`, and jobs are stored in `pentool/pentool.db` (SQLite).

**Security and operational best practices:** immediately change the default token, bind Flask to `127.0.0.1` or use a protected reverse proxy, begin with light scans (e.g., `ports: "top"`), avoid aggressive timing options on production networks, monitor logs during scans, and optionally add rate limiting or stricter auth for multi-user deployments.

**Troubleshooting:** 404 at `/` indicates `STATIC_FOLDER` path issues or missing `index.html`; missing `nmap` or `python-nmap` causes real scan failures; 401 indicates invalid token; 403 indicates a target outside the whitelist. Check logs via `tail -n 200 pentool/pentool_recon.log` and reports via `ls -lh pentool/web_static/*.json`.

**Quick example commands:** mock scan: `curl -X POST -H "Content-Type: application/json" -d '{"target":"127.0.0.1"}' http://127.0.0.1:5000/api/scan | jq .`; submit real async scan: `curl -X POST http://127.0.0.1:5000/api/scan_network -H "Content-Type: application/json" -H "X-PENTOOL-AUTH: YOUR_TOKEN" -d '{"target":"127.0.0.1","ports":"top","async":true}' | jq .`; check job: `curl -H "X-PENTOOL-AUTH: YOUR_TOKEN" http://127.0.0.1:5000/api/job/<job_id> | jq .`; download latest report: `curl http://127.0.0.1:5000/api/report.json -o last_report.json`.

This version is concise, professional, and ready to be used as a single-file README for GitHub or local documentation.

by Ghariani Oussema TN 
                  Instagram✔️: mark.spongebob
