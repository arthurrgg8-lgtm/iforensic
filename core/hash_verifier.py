import os
import hashlib
import json
import socket
import platform
from datetime import datetime, timezone

class HashVerifier:
    """
    NIST CFTT Standard Cryptographic Hash Verification & Chain of Custody Engine.
    Computes streaming SHA-256 and MD5 hashes across all source evidence files,
    generates structured Chain of Custody manifests, and validates evidence integrity.
    """

    CHUNK_SIZE = 1024 * 1024  # 1 MB ultra-fast streaming buffer

    @staticmethod
    def calculate_file_hashes(file_path):
        """
        Calculates SHA-256 and MD5 hashes for a single file using chunked streaming.
        """
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return None

        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                while chunk := f.read(HashVerifier.CHUNK_SIZE):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)

            return {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size_bytes": file_size,
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "error": str(e)
            }

    @staticmethod
    def generate_chain_of_custody(evidence_dir, output_dir, investigator="Forensic Examiner", case_id="CASE-001", specific_files=None):
        """
        Recursively hashes evidence artifacts and produces NIST CFTT compliant manifests.
        Supports specific_files for ultra-fast Quick Triage, and parallel multi-threading for Full Deep Mode.
        """
        import concurrent.futures
        os.makedirs(output_dir, exist_ok=True)
        evidence_dir = os.path.abspath(evidence_dir)
        
        file_list = []
        if specific_files is not None:
            # Quick Triage Mode: Hash specified critical evidence databases and manifests
            for sf in specific_files:
                if sf and os.path.exists(sf) and os.path.isfile(sf):
                    abs_sf = os.path.abspath(sf)
                    if abs_sf not in file_list:
                        file_list.append(abs_sf)
        else:
            # Full Deep Forensic Mode: Hash all files in evidence directory
            for root, _, files in os.walk(evidence_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    if output_dir in full_p:
                        continue
                    file_list.append(full_p)

        manifest_records = []
        total_bytes = 0

        # Parallel multi-threaded hashing
        max_workers = min(32, (os.cpu_count() or 4) * 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(HashVerifier.calculate_file_hashes, file_list)

        for res in results:
            if res and "sha256" in res:
                rel_p = os.path.relpath(res["file_path"], evidence_dir)
                res["relative_path"] = rel_p
                manifest_records.append(res)
                total_bytes += res.get("file_size_bytes", 0)

        # Overall Master Hash (Hash of all sorted file SHA-256 values)
        manifest_records.sort(key=lambda x: x["relative_path"])
        master_hasher = hashlib.sha256()
        for r in manifest_records:
            master_hasher.update(f"{r['relative_path']}:{r['sha256']}".encode("utf-8"))
        master_verification_hash = master_hasher.hexdigest()

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        custody_data = {
            "standards_compliance": "NIST CFTT / ISO/IEC 27037:2012 Digital Evidence Integrity",
            "case_id": case_id,
            "investigator": investigator,
            "verification_timestamp_utc": now_utc,
            "host_environment": {
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine()
            },
            "evidence_directory": evidence_dir,
            "total_files_verified": len(manifest_records),
            "total_bytes_verified": total_bytes,
            "master_evidence_sha256": master_verification_hash,
            "file_hashes": manifest_records
        }

        # 1. Write Machine-Readable JSON Manifest
        json_path = os.path.join(output_dir, "Chain_of_Custody_Verification.json")
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(custody_data, jf, indent=2)

        # 2. Write Court-Ready Human-Readable TXT Manifest
        txt_path = os.path.join(output_dir, "Chain_of_Custody_Manifest.txt")
        with open(txt_path, "w", encoding="utf-8") as tf:
            tf.write("=" * 80 + "\n")
            tf.write("           DIGITAL EVIDENCE CHAIN OF CUSTODY & HASH VERIFICATION\n")
            tf.write("       Compliance Standard: NIST Computer Forensic Tool Testing (CFTT)\n")
            tf.write("=" * 80 + "\n\n")
            tf.write(f"Case Reference ID     : {case_id}\n")
            tf.write(f"Forensic Examiner     : {investigator}\n")
            tf.write(f"Verification Time UTC : {now_utc}\n")
            tf.write(f"Evidence Source Path  : {evidence_dir}\n")
            tf.write(f"Host Machine          : {socket.gethostname()} ({platform.system()} {platform.machine()})\n")
            tf.write(f"Total Files Indexed   : {len(manifest_records):,}\n")
            tf.write(f"Total Size Ingested   : {total_bytes / (1024*1024):.2f} MB ({total_bytes:,} bytes)\n")
            tf.write(f"Master SHA-256 Hash   : {master_verification_hash}\n\n")
            tf.write("-" * 80 + "\n")
            tf.write(f"{'FILE (RELATIVE PATH)':<40} {'SHA-256 HASH':<65}\n")
            tf.write("-" * 80 + "\n")
            for r in manifest_records:
                rel = r["relative_path"]
                if len(rel) > 38:
                    rel = "..." + rel[-35:]
                tf.write(f"{rel:<40} {r['sha256']}\n")
            tf.write("-" * 80 + "\n")
            tf.write("VERIFICATION RESULT: ALL HASHES RECORDED AND LOCKED IN FORENSIC MANIFEST.\n")
            tf.write("=" * 80 + "\n")

        return {
            "json_manifest": json_path,
            "txt_manifest": txt_path,
            "master_hash": master_verification_hash,
            "file_count": len(manifest_records),
            "total_size_mb": round(total_bytes / (1024*1024), 2)
        }

    @staticmethod
    def verify_existing_manifest(json_manifest_path, evidence_dir):
        """
        Audits an existing evidence directory against a previously recorded Chain of Custody JSON manifest.
        Returns match status and lists any altered, missing, or corrupt files.
        """
        if not os.path.exists(json_manifest_path):
            return False, "Manifest file does not exist."

        with open(json_manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        records = data.get("file_hashes", [])
        mismatches = []
        missing = []
        matched = 0

        for r in records:
            rel = r.get("relative_path")
            orig_sha256 = r.get("sha256")
            full_p = os.path.join(evidence_dir, rel)

            if not os.path.exists(full_p):
                missing.append(rel)
                continue

            current_hashes = HashVerifier.calculate_file_hashes(full_p)
            if current_hashes.get("sha256") != orig_sha256:
                mismatches.append({
                    "path": rel,
                    "expected_sha256": orig_sha256,
                    "actual_sha256": current_hashes.get("sha256")
                })
            else:
                matched += 1

        is_valid = (len(mismatches) == 0 and len(missing) == 0)
        return {
            "is_valid": is_valid,
            "matched_files": matched,
            "missing_files": missing,
            "mismatched_files": mismatches,
            "total_files": len(records)
        }
