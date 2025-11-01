import os
import json
from datetime import datetime

class ReconScanner:
    def __init__(self, targets=None, rate_limit=0.2):
        self.targets = targets or []
        self.rate_limit = rate_limit

    def run_recon(self, ports="1-1024"):
        """
        Run reconnaissance on the targets.
        This is currently a dummy implementation.
        """
        return {
            "targets": self.targets,
            "ports_scanned": ports,
            "generated_at": datetime.now().isoformat()
        }

    def save_report(self, report, filename=None):
        """
        Save the report as JSON.
        By default, saves to '../web_static/recon_report.json' relative to this file.
        """
        filename = filename or os.path.join("..", "web_static", "recon_report.json")
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), filename))

        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "w") as f:
            json.dump(report, f, indent=4)
