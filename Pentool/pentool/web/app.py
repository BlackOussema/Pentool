# pentool/web/app.py
import os
import json
import sqlite3
import logging
import ipaddress
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, send_from_directory, request, jsonify, abort

# Optional: requires `python-nmap` and system `nmap`
try:
    import nmap
except Exception:
    nmap = None  # handled later

# --- Paths ---
HERE = os.path.dirname(os.path.abspath(__file__))          # .../Pentool/pentool/web
STATIC_FOLDER = os.path.abspath(os.path.join(HERE, "..", "web_static"))
DB_FILE = os.path.abspath(os.path.join(HERE, "..", "pentool.db"))
LOG_FILE = os.path.abspath(os.path.join(HERE, "..", "pentool_recon.log"))
os.makedirs(STATIC_FOLDER, exist_ok=True)

# --- Flask app ---
app = Flask(__name__, static_folder=STATIC_FOLDER)
app.config['JSON_SORT_KEYS'] = False

# --- Logging (audit) ---
logger = logging.getLogger("pentool_recon")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(fh)

# --- Authentication tokens (replace/change before production) ---
VALID_TOKENS = {
    # change this token to something strong before using on real networks
    "dev-token-please-change": {"user": "admin"}
}

# --- Thread pool for background scans ---
EXECUTOR = ThreadPoolExecutor(max_workers=3)
JOBS = {}  # job_id -> {"status":..., "target":..., "ports":..., "file":..., "started":..., "finished":...}
JOBS_LOCK = threading.Lock()

# --- Whitelist networks (default: localhost + RFC1918) ---
# You may add extra CIDR ranges or IPs to ALLOWED_NETWORKS
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

def is_ip_in_allowed_networks(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for net in ALLOWED_NETWORKS:
        if ip in net:
            return True
    return False

def target_is_allowed(target):
    """
    Accepts:
      - single IPv4 address '192.168.1.10'
      - CIDR '192.168.1.0/24'
      - hostname that resolves to an allowed IP (best-effort, avoids DNS spoofing risk)
    """
    # If it's CIDR
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            # all addresses in net must be subset of ALLOWED_NETWORKS
            for allowed in ALLOWED_NETWORKS:
                if net.subnet_of(allowed):
                    return True
            return False
        # single IP?
        try:
            ip = ipaddress.ip_address(target)
            return is_ip_in_allowed_networks(target)
        except Exception:
            # not IP -> try resolve hostname to IP (best-effort)
            import socket
            try:
                infos = socket.getaddrinfo(target, None)
                for info in infos:
                    addr = info[4][0]
                    if is_ip_in_allowed_networks(addr):
                        return True
                return False
            except Exception:
                return False
    except Exception:
        return False

# --- DB (jobs) helper (sqlite) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        job_id INTEGER PRIMARY KEY,
        user TEXT,
        target TEXT,
        ports TEXT,
        status TEXT,
        report_file TEXT,
        started_at TEXT,
        finished_at TEXT
    )""")
    conn.commit()
    conn.close()

def insert_job(user, target, ports, status="pending"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO jobs(user,target,ports,status,started_at) VALUES (?,?,?,?,?)",
              (user, target, ports, status, datetime.utcnow().isoformat()+"Z"))
    job_id = c.lastrowid
    conn.commit(); conn.close()
    return job_id

def update_job(job_id, status, report_file=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if report_file:
        c.execute("UPDATE jobs SET status=?, report_file=?, finished_at=? WHERE job_id=?",
                  (status, report_file, datetime.utcnow().isoformat()+"Z", job_id))
    else:
        c.execute("UPDATE jobs SET status=? WHERE job_id=?", (status, job_id))
    conn.commit(); conn.close()

def list_jobs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT job_id,user,target,ports,status,report_file,started_at,finished_at FROM jobs ORDER BY job_id DESC")
    rows = c.fetchall()
    conn.close()
    keys = ["job_id","user","target","ports","status","report_file","started_at","finished_at"]
    return [dict(zip(keys,row)) for row in rows]

# initialize DB
init_db()

# --- Helpers ---
def require_token(fn):
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-PENTOOL-AUTH", "")
        if token not in VALID_TOKENS:
            return jsonify({"error":"Unauthorized - missing/invalid X-PENTOOL-AUTH header"}), 401
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def safe_nmap_scan(target, ports_arg="1-1024", extra_args=None):
    """
    Run nmap scan (synchronous). Returns dict report.
    Default options are conservative: -sS -Pn -T3 --top-ports 100 when ports_arg == 'top'
    """
    if nmap is None:
        raise RuntimeError("python-nmap is not installed (pip install python-nmap) or nmap missing")

    nm = nmap.PortScanner()
    # choose arguments
    if ports_arg == "top":
        args = "-sS -Pn -T3 --top-ports 100"
    else:
        args = f"-sS -Pn -T3 -p {ports_arg}"

    if extra_args:
        args = f"{args} {extra_args}"

    logger.info(f"Running nmap on {target} args: {args}")
    nm.scan(hosts=target, arguments=args)

    report = {"generated_at": datetime.utcnow().isoformat()+"Z", "targets": []}
    for host in nm.all_hosts():
        host_entry = {"host": host, "state": nm[host].state(), "ports_scan": {"tcp": {}}}
        tcp = nm[host].get("tcp", {})
        for port, info in tcp.items():
            host_entry["ports_scan"]["tcp"][str(port)] = {
                "state": info.get("state"),
                "name": info.get("name"),
                "product": info.get("product"),
                "version": info.get("version")
            }
        report["targets"].append(host_entry)
    return report

# --- Routes: serve static UI ---
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

# --- Mock endpoints (keep for UI) ---
@app.route("/api/scan", methods=["POST"])
def api_scan_mock():
    data = request.json or {}
    target = data.get("target","127.0.0.1")
    ports = data.get("ports","1-1024")
    mode = data.get("mode","mock")
    result = {
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "target": target,
        "ports": ports,
        "mode": mode,
        "open_ports": [22,80,443],
        "status": "success" if mode=="mock" else "permission_required"
    }
    return jsonify(result)

@app.route("/api/recon", methods=["POST"])
def api_recon_mock():
    data = request.json or {}
    target = data.get("target","127.0.0.1")
    mode = data.get("mode","mock")
    result = {
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "target": target,
        "mode": mode,
        "services": ["ssh","http","https"],
        "status": "success" if mode=="mock" else "permission_required"
    }
    return jsonify(result)

# --- Real scan endpoint (secured + whitelist + async support) ---
@app.route("/api/scan_network", methods=["POST"])
@require_token
def api_scan_network():
    """
    JSON body:
    {
      "target": "192.168.1.0/24" or "192.168.1.5",
      "ports": "1-1024" or "top",
      "async": true/false,
      "extra_args": "-sV"  # optional, for advanced users (can be blocked)
    }
    """
    if nmap is None:
        return jsonify({"error":"nmap/python-nmap not available on server"}), 500

    data = request.get_json(silent=True) or {}
    target = data.get("target")
    ports = data.get("ports","top")  # default to top ports
    async_job = data.get("async", True)
    extra_args = data.get("extra_args", "")

    if not target:
        return jsonify({"error":"target is required"}), 400

    # check whitelist
    if not target_is_allowed(target):
        logger.warning(f"Blocked scan attempt for disallowed target {target} by token")
        return jsonify({"error":"target not allowed by whitelist"}), 403

    user = VALID_TOKENS.get(request.headers.get("X-PENTOOL-AUTH"))["user"]

    # create job entry in DB
    job_id = insert_job(user, target, ports, status="pending")
    logger.info(f"Job {job_id} submitted by {user} target={target} ports={ports} async={async_job}")

    def run_and_store(jid, tgt, prts, args):
        try:
            update_job(jid, "running")
            report = safe_nmap_scan(tgt, prts, extra_args=args)
            fname = f"scan_{tgt.replace('/','_')}_{int(datetime.utcnow().timestamp())}.json"
            outpath = os.path.join(app.static_folder, fname)
            with open(outpath, "w") as fh:
                json.dump(report, fh, indent=2)
            update_job(jid, "done", report_file=fname)
            logger.info(f"Job {jid} finished, report {fname}")
        except Exception as e:
            logger.exception(f"Job {jid} failed: {e}")
            update_job(jid, "failed")

    if async_job:
        EXECUTOR.submit(run_and_store, job_id, target, ports, extra_args)
        return jsonify({"status":"submitted","job_id":job_id}), 202

    # synchronous execution (blocking) - not recommended for UI
    try:
        update_job(job_id, "running")
        report = safe_nmap_scan(target, ports, extra_args)
        fname = f"scan_{target.replace('/','_')}_{int(datetime.utcnow().timestamp())}.json"
        outpath = os.path.join(app.static_folder, fname)
        with open(outpath, "w") as fh:
            json.dump(report, fh, indent=2)
        update_job(job_id, "done", report_file=fname)
        logger.info(f"Synchronous job {job_id} finished")
        return jsonify({"status":"done","job_id":job_id,"report_file":fname,"report":report})
    except Exception as e:
        logger.exception("Synchronous scan failed")
        update_job(job_id, "failed")
        return jsonify({"error":"scan failed","detail":str(e)}), 500

# --- Job status endpoint (secured) ---
@app.route("/api/job/<int:job_id>")
@require_token
def api_job_status(job_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT job_id,user,target,ports,status,report_file,started_at,finished_at FROM jobs WHERE job_id=?", (job_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"job not found"}), 404
    keys = ["job_id","user","target","ports","status","report_file","started_at","finished_at"]
    return jsonify(dict(zip(keys,row)))

# --- List jobs (secured) ---
@app.route("/api/list_jobs")
@require_token
def api_list_jobs():
    return jsonify({"jobs": list_jobs()})

# --- Reports endpoints (public read) ---
@app.route("/api/report.json")
def api_report_latest():
    # return most recent 'scan_*.json' or recon_report.json if present
    files = sorted([f for f in os.listdir(app.static_folder) if f.endswith(".json")], reverse=True)
    if not files:
        return jsonify({"error":"no reports"}), 404
    return send_from_directory(app.static_folder, files[0])

@app.route("/api/list_reports")
def api_list_reports_public():
    files = sorted([f for f in os.listdir(app.static_folder) if f.endswith(".json")], reverse=True)
    return jsonify({"reports": files})

# --- Simple in-memory logs endpoints (keeps compatibility) ---
logs = []
@app.route("/api/log", methods=["GET","POST"])
def api_log():
    global logs
    if request.method == "POST":
        entry = (request.get_json(silent=True) or {}).get("entry","")
        logs.append(f"[{datetime.utcnow().isoformat()}Z] {entry}")
        logger.info(f"LOG: {entry}")
        return jsonify({"status":"ok"})
    return jsonify({"logs": logs})

@app.route("/api/log/clear", methods=["POST"])
def api_log_clear():
    global logs
    logs.clear()
    return jsonify({"status":"cleared"})

# --- Run ---
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3000, debug=False)
