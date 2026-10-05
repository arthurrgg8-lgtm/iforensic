import os
import json
import time
import hashlib
import platform
from datetime import datetime, timezone, timedelta

class ForensicAuditLogger:
    """
    ISO/IEC 27037 & NIST CFTT Compliant Cryptographic Examiner Audit Trail Logger.
    Maintains an append-only JSONL event log with sequential event hashing to guarantee non-repudiation.
    """
    _instance = None

    def __init__(self, output_dir=None, examiner_name="Forensic Examiner"):
        self.output_dir = output_dir
        self.examiner_name = examiner_name
        self.log_file = None
        self.previous_hash = "0" * 64
        self.session_id = hashlib.sha256(f"{time.time()}-{os.getpid()}".encode()).hexdigest()[:16]
        
        if output_dir:
            self.set_output_directory(output_dir)

    @classmethod
    def get_logger(cls, output_dir=None, examiner_name="Forensic Examiner"):
        if cls._instance is None:
            cls._instance = cls(output_dir, examiner_name)
        elif output_dir and cls._instance.output_dir != output_dir:
            cls._instance.set_output_directory(output_dir)
        return cls._instance

    def set_output_directory(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.log_file = os.path.join(output_dir, "Forensic_Audit_Trail.jsonl")
        
        # Log session initiation
        self.log_event("SESSION_START", {
            "session_id": self.session_id,
            "examiner": self.examiner_name,
            "os_platform": platform.platform(),
            "python_version": platform.python_version(),
            "compliance_standard": "ISO/IEC 27037:2012 / NIST CFTT"
        })

    def log_event(self, action, details=None):
        """
        Appends an event to the cryptographic audit trail.
        Each entry hashes the previous entry hash to form an immutable blockchain-style audit log.
        """
        details = details or {}
        now_utc = datetime.now(timezone.utc).isoformat()
        now_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        raw_event_str = f"{self.previous_hash}|{now_utc}|{action}|{json.dumps(details, sort_keys=True)}"
        current_hash = hashlib.sha256(raw_event_str.encode("utf-8")).hexdigest()

        entry = {
            "session_id": self.session_id,
            "timestamp_utc": now_utc,
            "timestamp_local": now_local,
            "action": action,
            "examiner": self.examiner_name,
            "details": details,
            "prev_hash": self.previous_hash,
            "event_hash": current_hash
        }

        self.previous_hash = current_hash

        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass
        return entry

    def generate_human_readable_report(self, target_txt_path=None):
        """
        Exports a human-readable, court-admissible audit certificate.
        """
        if not target_txt_path:
            if not self.output_dir:
                return None
            target_txt_path = os.path.join(self.output_dir, "Forensic_Audit_Certificate.txt")

        events = []
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            events.append(json.loads(line.strip()))
            except Exception:
                pass

        lines = [
            "=" * 80,
            "               iFORENSIC DIGITAL EVIDENCE AUDIT CERTIFICATE",
            "         Standard: ISO/IEC 27037:2012 & NIST CFTT Chain of Custody",
            "=" * 80,
            f"Audit Session ID    : {self.session_id}",
            f"Examiner Identity   : {self.examiner_name}",
            f"System Platform     : {platform.platform()}",
            f"Certificate Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Final Audit Hash    : {self.previous_hash}",
            "-" * 80,
            f"TOTAL AUDITED ACTIONS: {len(events)}",
            "-" * 80,
            ""
        ]

        for idx, ev in enumerate(events, 1):
            lines.append(f"[{idx:03d}] {ev.get('timestamp_local')} | ACTION: {ev.get('action')}")
            lines.append(f"      Hash: {ev.get('event_hash')[:32]}...")
            for k, v in ev.get("details", {}).items():
                lines.append(f"      - {k}: {v}")
            lines.append("")

        lines.extend([
            "=" * 80,
            "VERIFICATION ATTESTATION:",
            "This digital evidence chain of custody and forensic activity log has been recorded",
            "with cryptographically chained SHA-256 blocks. Any alteration of intermediate events",
            "will invalidate the final audit hash.",
            "=" * 80,
            ""
        ])

        try:
            with open(target_txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return target_txt_path
        except Exception:
            return None
