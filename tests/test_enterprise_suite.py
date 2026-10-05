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

        # Test WAL Frame Carving
        wal_file = test_db + "-wal"
        with open(wal_file, "wb") as wf:
            import struct
            # Write 32-byte WAL Header: Magic 0x377f0682, fileFormat 3007000, page_sz 4096
            wf.write(struct.pack(">IIIIIIII", 0x377f0682, 3007000, 4096, 1, 0, 0, 0, 0))
            # Write Frame 1 Header: Page 1, db_size 1, salt1 0, salt2 0, checksum1 0, checksum2 0
            wf.write(struct.pack(">IIIIII", 1, 1, 0, 0, 0, 0))
            # Frame Payload
            payload = b"Uncommitted wire transfer to +18005550199 for $20,000 USD".ljust(4096, b"\x00")
            wf.write(payload)

        wal_carved = SQLiteFreelistCarver.carve_deleted_records(test_db, min_length=4)
        wal_texts = [c["carved_text"] for c in wal_carved]
        self.assertTrue(any("Uncommitted wire transfer" in t for t in wal_texts))

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

    def test_05_calls_parser_and_frequency_analytics(self):
        from parsers.calls_parser import CallsParser, format_duration, format_duration_hms
        
        # Test duration formatters
        self.assertEqual(format_duration(0), "0s (Unanswered)")
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(125), "2m 05s")
        self.assertEqual(format_duration(3665), "1h 01m 05s")
        self.assertEqual(format_duration_hms(125), "00:02:05")

        # Create mock CallHistory database
        db_path = os.path.join(self.test_dir, "CallHistory.storedata")
        conn = sqlite3.connect(db_path)
        conn.execute("""
        CREATE TABLE ZCALLRECORD (
            Z_PK INTEGER PRIMARY KEY,
            ZADDRESS TEXT,
            ZDURATION REAL,
            ZDATE REAL,
            ZORIGINATED INTEGER,
            ZCALLTYPE INTEGER,
            ZSERVICE_PROVIDER TEXT,
            ZLOCATION TEXT,
            ZANSWERED INTEGER,
            ZNAME TEXT
        )
        """)
        # Insert test calls (date in Cocoa format: seconds since 2001-01-01)
        # e.g., 700000000 -> 2023-03-09
        conn.execute("INSERT INTO ZCALLRECORD VALUES (1, '+9779841659861', 120.0, 700000000.0, 0, 1, 'Telephony', 'Kathmandu', 1, 'Target Subject')")
        conn.execute("INSERT INTO ZCALLRECORD VALUES (2, '+9779841659861', 0.0, 700010000.0, 0, 3, 'Telephony', 'Kathmandu', 0, 'Target Subject')")
        conn.execute("INSERT INTO ZCALLRECORD VALUES (3, '+9779841659861', 240.0, 700020000.0, 1, 2, 'Telephony', 'Kathmandu', 1, 'Target Subject')")
        conn.execute("INSERT INTO ZCALLRECORD VALUES (4, '+12025550199', 45.0, 700030000.0, 1, 2, 'Telephony', 'Washington DC', 1, 'Associate A')")
        conn.commit()
        conn.close()

        parser = CallsParser(db_path)
        calls = parser.parse()
        self.assertEqual(len(calls), 4)

        analytics = parser.get_frequency_analytics()
        self.assertEqual(analytics["total_calls"], 4)
        self.assertEqual(analytics["total_incoming"], 1)
        self.assertEqual(analytics["total_outgoing"], 2)
        self.assertEqual(analytics["total_missed"], 1)
        self.assertEqual(analytics["total_duration_seconds"], 405.0)

        # Frequent contacts ranking
        top_contact = analytics["frequent_contacts"][0]
        self.assertEqual(top_contact["contact_name"], "Target Subject")
        self.assertEqual(top_contact["total_calls"], 3)
        self.assertEqual(top_contact["incoming_count"], 1)
        self.assertEqual(top_contact["outgoing_count"], 1)
        self.assertEqual(top_contact["missed_count"], 1)
        self.assertEqual(top_contact["total_duration_seconds"], 360.0)

    def test_06_device_profile_and_plain_text_tree(self):
        meta = {
            "device_name": "Senior Security iPhone",
            "model_friendly_name": "iPhone 15 Pro",
            "product_type": "iPhone16,1",
            "product_version": "17.5.1",
            "build_version": "21F90",
            "serial_number": "DNPZ80ABC123",
            "udid": "00008110-001234567890ABCD",
            "imei": "353000112233445",
            "imei2": "353000112233446",
            "ecid": "0x123456789",
            "iccid": "8901260000000000000",
            "wifi_mac": "A0:B1:C2:D3:E4:F5",
            "is_encrypted": True
        }

        mock_calls = [
            {
                "record_id": 1,
                "timestamp_local": "2026-03-09 14:00:00",
                "timestamp_utc": "2026-03-09 08:15:00 UTC",
                "direction": "INCOMING",
                "status": "Incoming (Answered)",
                "contact_name": "Boss",
                "number": "+9779800000000",
                "duration_seconds": 120,
                "duration_formatted": "2m 00s",
                "duration_hms": "00:02:00",
                "service_provider": "Telephony",
                "location": "Kathmandu"
            }
        ]

        exporter = PlainTextTreeExporter(self.test_dir, extracted_data={"calls": mock_calls}, metadata=meta)
        root = exporter.export_all()
        self.assertTrue(os.path.exists(root))

        # Check Device profile folder and files
        dev_profile = os.path.join(root, "00_Device_and_System_Profile", "device_hardware_profile.txt")
        self.assertTrue(os.path.exists(dev_profile))
        with open(dev_profile, "r") as f:
            dev_text = f.read()
            self.assertIn("iPhone 15 Pro", dev_text)
            self.assertIn("353000112233445", dev_text)
            self.assertIn("DNPZ80ABC123", dev_text)

        # Check Call History and Frequency Analysis files
        call_freq = os.path.join(root, "02_Calls_and_Voicemails", "call_frequency_analysis.txt")
        self.assertTrue(os.path.exists(call_freq))
        with open(call_freq, "r") as f:
            call_text = f.read()
            self.assertIn("TELEPHONY & CALL COMMUNICATION FREQUENCY ANALYSIS", call_text)
            self.assertIn("Boss", call_text)

        call_csv = os.path.join(root, "02_Calls_and_Voicemails", "call_history.csv")
        self.assertTrue(os.path.exists(call_csv))

if __name__ == "__main__":
    unittest.main()
