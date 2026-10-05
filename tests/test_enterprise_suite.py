import os
import tempfile
import sqlite3
import json
import unittest

from core.audit_logger import ForensicAuditLogger
from core.sqlite_freelist_carver import SQLiteFreelistCarver
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, apple_to_iso, parse_any_time
from core.db_utils import connect_readonly_sqlite
from core.hash_verifier import HashVerifier
from exporters.docx_report import DocxReportExporter
from exporters.html_dashboard import HTMLDashboardExporter
from exporters.plain_text_tree_exporter import PlainTextTreeExporter
from exporters.bulk_data_exporter import BulkDataExporter

class TestEnterpriseForensicSuite(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_dir = self.tmp_dir.name

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_01_audit_logger_chain_of_custody(self):
        logger = ForensicAuditLogger(self.test_dir, examiner_name="Senior DFIR Specialist")
        e1 = logger.log_event("DEVICE_DETECTED", {"device": "iPhone 15 Pro", "ios": "18.1"})
        e2 = logger.log_event("EVIDENCE_INGESTED", {"file_count": 1420})
        
        self.assertEqual(e2["prev_hash"], e1["event_hash"])
        cert_path = logger.generate_human_readable_report()
        self.assertTrue(os.path.exists(cert_path))
        with open(cert_path, "r") as f:
            content = f.read()
            self.assertIn("ISO/IEC 27037:2012", content)
            self.assertIn("Senior DFIR Specialist", content)

    def test_02_sqlite_freelist_carver(self):
        test_db = os.path.join(self.test_dir, "test_evidence.db")
        conn = sqlite3.connect(test_db)
        conn.execute("CREATE TABLE chats (id INTEGER PRIMARY KEY, msg TEXT)")
        conn.execute("INSERT INTO chats VALUES (1, 'Active Secret Chat')")
        conn.execute("INSERT INTO chats VALUES (2, 'Call me at +9779800000000 regarding USD 5000 bank OTP')")
        conn.commit()
        # Delete row 2 to move to unallocated / freelist
        conn.execute("DELETE FROM chats WHERE id = 2")
        conn.commit()
        conn.close()

        carved = SQLiteFreelistCarver.carve_deleted_records(test_db, min_length=4)
        self.assertIsInstance(carved, list)
        
        # Test classifier
        self.assertEqual(SQLiteFreelistCarver._classify_fragment("+1234567890"), "Phone Number")
        self.assertEqual(SQLiteFreelistCarver._classify_fragment("investigator@dfir.org"), "Email Address")
        self.assertEqual(SQLiteFreelistCarver._classify_fragment("https://github.com"), "URL / Link")
        self.assertEqual(SQLiteFreelistCarver._classify_fragment("Bank OTP is 482910"), "Financial / Credential Fragment")

    def test_03_bulk_data_exporter_and_case_uco(self):
        mock_data = {
            "messages": [{"timestamp_local": "2026-10-05 12:00:00", "sender": "+1234", "recipient": "+5678", "text": "Forensic testing", "direction": "Incoming"}],
            "calls": [{"timestamp_local": "2026-10-05 12:01:00", "contact_name": "Alice", "number": "+1234", "status": "Answered", "duration": 120, "duration_formatted": "2m"}],
            "contacts": [{"first_name": "Alice", "last_name": "Smith", "phone_numbers": ["+1234"], "email_addresses": ["alice@example.com"]}],
            "notes": [{"title": "Secrets", "folder": "Work", "snippet": "Password123"}],
            "financial": [{"timestamp_local": "2026-10-05 12:02:00", "entity": "Bank", "type": "Debit", "amount": "$500", "summary": "Wire Transfer"}],
            "whatsapp": [{"timestamp_local": "2026-10-05 12:03:00", "sender": "Alice", "text": "Confirmed", "chat_name": "Group 1"}],
            "keychain": {"all_decrypted_records": [{"type": "Wi-Fi", "service": "HomeNet", "account": "HomeNet", "decrypted_password": "Pass"}]},
            "deleted_carved_records": [{"database_name": "sms.db", "page_number": 2, "category": "Phone Number", "carved_text": "+1234567890"}],
            "timeline": [{"timestamp_local": "2026-10-05 12:00:00", "event_type": "Message", "summary": "Forensic testing"}]
        }
        meta = {"product_type": "iPhone 15,2", "product_version": "18.1", "serial_number": "DNQX12345", "udid": "00008110-00184DC63CD3801E"}

        exporter = BulkDataExporter(self.test_dir, mock_data, meta)
        res = exporter.export_all()
        self.assertEqual(res["status"], "Success")
        
        # Verify CSVs
        csv_dir = exporter.export_folder
        self.assertTrue(os.path.exists(os.path.join(csv_dir, "messages.csv")))
        self.assertTrue(os.path.exists(os.path.join(csv_dir, "calls.csv")))
        self.assertTrue(os.path.exists(os.path.join(csv_dir, "financial_ledger.csv")))
        self.assertTrue(os.path.exists(os.path.join(csv_dir, "deleted_carved_fragments.csv")))

        # Verify CASE / UCO JSON-LD
        uco_path = os.path.join(csv_dir, "case_uco_evidence_graph.jsonld")
        self.assertTrue(os.path.exists(uco_path))
        with open(uco_path, "r", encoding="utf-8") as f:
            uco_json = json.load(f)
            self.assertIn("@context", uco_json)
            self.assertIn("@graph", uco_json)

    def test_04_html_and_docx_exporters(self):
        mock_data = {
            "messages": [{"timestamp_local": "2026-10-05 12:00:00", "sender": "+1234", "recipient": "+5678", "text": "Test Msg", "dir": "Incoming"}],
            "calls": [{"timestamp_local": "2026-10-05 12:01:00", "contact_name": "Bob", "number": "+5678", "status": "Missed", "dur": "0s", "provider": "Cellular"}],
            "notes": [{"title": "Note 1", "folder": "Notes", "modified_local": "2026-10-05", "content": "Note Content"}],
            "financial": [{"timestamp_local": "2026-10-05 12:02:00", "entity": "PayPal", "type": "Credit", "amount": "$100", "summary": "Received"}],
            "photos": [{"filename": "IMG_0001.JPG", "has_gps": True, "latitude": 27.7172, "longitude": 85.3240, "timestamp_local": "2026-10-05 12:00:00"}],
            "deleted_carved_records": [{"database_name": "sms.db", "page_number": 4, "category": "Deleted Text", "carved_text": "Meeting at 5PM"}],
            "keychain": {"all_decrypted_records": []},
            "custody_manifest": {"master_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        }
        meta = {"device_name": "Suspect iPhone", "product_type": "iPhone 14 Pro", "product_version": "17.4"}

        # HTML Dashboard
        html_exp = HTMLDashboardExporter(
            metadata=meta,
            messages=mock_data["messages"],
            calls=mock_data["calls"],
            notes=mock_data["notes"],
            financial=mock_data["financial"],
            photos=mock_data["photos"],
            deleted_carved_records=mock_data["deleted_carved_records"],
            custody_manifest=mock_data["custody_manifest"]
        )
        html_out = os.path.join(self.test_dir, "dashboard.html")
        html_exp.generate(html_out)
        self.assertTrue(os.path.exists(html_out))
        with open(html_out, "r") as f:
            html_text = f.read()
            self.assertIn("Geospatial Intelligence Map", html_text)
            self.assertIn("Freelist Deleted Data", html_text)

        # DOCX Report
        docx_exp = DocxReportExporter(
            metadata=meta,
            messages=mock_data["messages"],
            calls=mock_data["calls"],
            notes=mock_data["notes"],
            financial=mock_data["financial"],
            photos=mock_data["photos"],
            deleted_carved_records=mock_data["deleted_carved_records"],
            custody_manifest=mock_data["custody_manifest"]
        )
        docx_out = os.path.join(self.test_dir, "report.docx")
        docx_exp.generate(docx_out)
        self.assertTrue(os.path.exists(docx_out))

if __name__ == "__main__":
    unittest.main()
