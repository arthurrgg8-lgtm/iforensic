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

        # Plain Text Tree Export
        plain_exp = PlainTextTreeExporter(
            output_base_dir=self.test_dir,
            extracted_data=mock_data,
            metadata=meta
        )
        plain_root = plain_exp.export_all()
        self.assertTrue(os.path.exists(plain_root))
        self.assertTrue(os.path.exists(os.path.join(plain_root, "00_CASE_METADATA_AND_SUMMARY.txt")))

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

        mock_carved = [
            {
                "database_name": "Messages (sms.db)",
                "source_type": "Freelist Page",
                "page_number": 4,
                "byte_offset": 16384,
                "category": "Financial / Credential Fragment",
                "carved_text": "OTP 992810 for transfer of USD 5000"
            }
        ]

        exporter = PlainTextTreeExporter(
            self.test_dir,
            extracted_data={"calls": mock_calls, "deleted_carved_records": mock_carved},
            metadata=meta
        )
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

        # Check 13_Carved_Deleted_Fragments
        carved_txt = os.path.join(root, "13_Carved_Deleted_Fragments", "deleted_carved_fragments.txt")
        self.assertTrue(os.path.exists(carved_txt))
        with open(carved_txt, "r") as f:
            c_text = f.read()
            self.assertIn("SQLITE FREELIST", c_text)
            self.assertIn("OTP 992810", c_text)

        carved_csv = os.path.join(root, "13_Carved_Deleted_Fragments", "deleted_carved_records.csv")
        self.assertTrue(os.path.exists(carved_csv))

    def test_07_universal_datetime_parser(self):
        from core.time_utils import to_datetime, format_datetime_utc, format_datetime_local, parse_any_time
        import datetime

        # 1. Cocoa nanoseconds (~7.4e17 ns) from iOS 16/17/18 sms.db
        cocoa_ns = 749382910000000000
        dt = to_datetime(cocoa_ns)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)

        # 2. Unix milliseconds (~1.7e12 ms)
        unix_ms = 1715000000000
        dt_ms = to_datetime(unix_ms)
        self.assertIsNotNone(dt_ms)
        self.assertEqual(dt_ms.year, 2024)

        # 3. ISO string
        iso_str = "2026-10-05T14:30:00Z"
        dt_iso = to_datetime(iso_str)
        self.assertIsNotNone(dt_iso)
        self.assertEqual(dt_iso.year, 2026)

        # 4. parse_any_time returns valid UTC and Local strings
        utc_s, loc_s = parse_any_time(cocoa_ns)
        self.assertIn("2024", utc_s)
        self.assertIn("UTC", utc_s)

    def test_08_financial_parser_with_notes(self):
        from parsers.financial_parser import FinancialParser

        mock_msgs = [
            {"sender": "NabilBank", "text": "Your A/C has been debited by NPR 15,000.00 for payment.", "timestamp_local": "2026-10-05 10:00:00"}
        ]
        mock_notes = [
            {"title": "Swiss Account Ledger", "snippet": "Bank wire USD 50,000 to IBAN CH9300001", "full_content": "Bank wire USD 50,000 to IBAN CH9300001 for investment.", "modified_local": "2026-10-05 11:00:00", "tags": ["Financial/Banking"]}
        ]

        fin = FinancialParser(messages=mock_msgs, notes=mock_notes).parse()
        self.assertEqual(len(fin), 2)
        sources = [f["source"] for f in fin]
        self.assertIn("SMS / iMessage", sources)
        self.assertIn("Apple Notes", sources)

    def test_09_timeline_engine_universal_ingestion(self):
        from core.timeline import TimelineEngine
        import datetime
        from datetime import timezone

        te = TimelineEngine()
        te.ingest_sms([{"text": "Hello", "raw_datetime": datetime.datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc), "timestamp_local": "2026-10-05 15:45:00"}])
        te.ingest_whatsapp([{"text": "Meeting at 2pm", "raw_datetime": datetime.datetime(2026, 10, 5, 11, 0, tzinfo=timezone.utc), "timestamp_local": "2026-10-05 16:45:00", "app_variant": "WhatsApp"}])
        te.ingest_financial([{"type": "Debit", "amount": "$100", "raw_datetime": datetime.datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc), "timestamp_local": "2026-10-05 17:45:00"}])

        timeline = te.build_timeline()
        self.assertEqual(len(timeline), 3)
        # Check chronological order
        self.assertEqual(timeline[0]["type"], "MESSAGE")
        self.assertEqual(timeline[1]["type"], "CHAT")
        self.assertEqual(timeline[2]["type"], "FINANCIAL")

    def test_10_contacts_and_voicemail_schema_resilience(self):
        from parsers.contacts_parser import ContactsParser
        from parsers.recordings_parser import RecordingsParser

        # Test Contacts without DisplayName column
        ab_db = os.path.join(self.test_dir, "ab_test.db")
        conn = sqlite3.connect(ab_db)
        conn.execute("CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Organization TEXT, JobTitle TEXT, Note TEXT)")
        conn.execute("INSERT INTO ABPerson VALUES (1, 'John', 'Doe', 'Apple', 'Engineer', 'VIP Contact')")
        conn.commit()
        conn.close()

        cp = ContactsParser(ab_db)
        contacts = cp.parse()
        self.assertEqual(len(contacts), 1)
        self.assertEqual(contacts[0]["name"], "John Doe")

    def test_11_manifest_resolver_positional_normalization(self):
        from core.manifest_resolver import ManifestResolver
        import hashlib

        # Create mock backup structure
        backup_path = os.path.join(self.test_dir, "mock_backup")
        os.makedirs(backup_path, exist_ok=True)

        # Create a mock sms.db with HomeDomain-Library/SMS/sms.db SHA1
        sha1_sms = hashlib.sha1("HomeDomain-Library/SMS/sms.db".encode("utf-8")).hexdigest()
        sms_file_path = os.path.join(backup_path, sha1_sms)
        with open(sms_file_path, "wb") as f:
            f.write(b"SQLite format 3\x00" + b"\x00" * 4080)

        resolver = ManifestResolver(backup_path, deep_fingerprint=False)
        # Test positional resolution: find_file("sms.db")
        resolved = resolver.find_file("sms.db")
        self.assertIsNotNone(resolved)
        self.assertTrue(os.path.exists(resolved))

        # Test positional resolution: find_file("Library/SMS/sms.db")
        resolved_rel = resolver.find_file("Library/SMS/sms.db")
        self.assertIsNotNone(resolved_rel)

    def test_12_photos_parser_and_metadata(self):
        from parsers.photos_parser import PhotosParser

        photos_db = os.path.join(self.test_dir, "photos_test.sqlite")
        conn = sqlite3.connect(photos_db)
        conn.execute("""
            CREATE TABLE ZGENERICASSET (
                Z_PK INTEGER PRIMARY KEY,
                ZFILENAME TEXT,
                ZDIRECTORY TEXT,
                ZDATECREATED REAL,
                ZMODIFICATIONDATE REAL,
                ZLATITUDE REAL,
                ZLONGITUDE REAL,
                ZALTITUDE REAL,
                ZDURATION REAL,
                ZFAVORITE INTEGER,
                ZHIDDEN INTEGER,
                ZTRASHEDSTATE INTEGER,
                ZKIND INTEGER,
                ZWIDTH INTEGER,
                ZHEIGHT INTEGER,
                ZUUID TEXT
            )
        """)
        conn.execute("""
            INSERT INTO ZGENERICASSET VALUES (
                1, 'EVIDENCE_VIDEO.MOV', 'DCIM/100APPLE', 700000000.0, 700010000.0,
                27.717245, 85.323961, 1400.5, 124.5,
                1, 0, 0, 1, 1920, 1080, 'UUID-1234-VIDEO'
            )
        """)
        conn.commit()
        conn.close()

        parser = PhotosParser(photos_db)
        photos = parser.parse()
        self.assertEqual(len(photos), 1)

        p = photos[0]
        self.assertEqual(p["filename"], "EVIDENCE_VIDEO.MOV")
        self.assertEqual(p["media_type"], "Video (Recorded / Saved)")
        self.assertTrue(p["has_gps"])
        self.assertEqual(p["resolution"], "1920x1080")
        self.assertIn("google.com/maps", p["google_maps_url"])
        self.assertEqual(p["duration_seconds"], 124.5)

        summary = parser.get_summary()
        self.assertEqual(summary["total_media_items"], 1)
        self.assertEqual(summary["total_videos"], 1)
        self.assertEqual(summary["total_geotagged"], 1)

    def test_13_recordings_parser_and_audio_tree_export(self):
        from parsers.recordings_parser import RecordingsParser
        from core.manifest_resolver import ManifestResolver
        from exporters.plain_text_tree_exporter import PlainTextTreeExporter
        import hashlib

        # Create mock backup with Manifest.db containing an audio file
        backup_p = os.path.join(self.test_dir, "audio_backup")
        os.makedirs(backup_p, exist_ok=True)

        manifest_path = os.path.join(backup_p, "Manifest.db")
        m_conn = sqlite3.connect(manifest_path)
        m_conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")

        file_id = hashlib.sha1("MediaDomain-Media/Recordings/interview.m4a".encode()).hexdigest()
        m_conn.execute("INSERT INTO Files VALUES (?, ?, ?, 1, NULL)", (file_id, "MediaDomain", "Media/Recordings/interview.m4a"))
        m_conn.commit()
        m_conn.close()

        # Create dummy m4a file in backup directory
        audio_file_p = os.path.join(backup_p, file_id)
        with open(audio_file_p, "wb") as f:
            f.write(b"M4A_AUDIO_DATA_FOR_FORENSIC_TEST" * 50)

        resolver = ManifestResolver(backup_p, deep_fingerprint=False)
        rec_parser = RecordingsParser(manifest_resolver=resolver)
        results = rec_parser.parse()

        self.assertGreaterEqual(results["total_audio_artifacts"], 1)
        carved = results["carved_audio_files"]
        self.assertTrue(any(a["filename"] == "interview.m4a" for a in carved))

        # Test PlainTextTreeExporter export of audio
        mock_data = {
            "recordings": {
                "voice_memos": [{"title": "Confidential Memo", "duration_seconds": 45, "timestamp_local": "2026-03-09 10:00:00", "file_rel_path": "memo.m4a"}],
                "voicemails": [{"sender": "+1234567890", "duration_seconds": 30, "transcription": "Please call back immediately", "timestamp_local": "2026-03-09 10:30:00"}],
                "carved_audio_files": carved
            }
        }
        exporter = PlainTextTreeExporter(self.test_dir, extracted_data=mock_data, manifest_resolver=resolver)
        root = exporter.export_all()

        audio_folder = os.path.join(root, "05_Audio_Recordings_and_Voice_Memos")
        self.assertTrue(os.path.exists(audio_folder))
        self.assertTrue(os.path.exists(os.path.join(audio_folder, "voice_memos_index.txt")))
        self.assertTrue(os.path.exists(os.path.join(audio_folder, "voicemail_transcriptions.txt")))
        self.assertTrue(os.path.exists(os.path.join(audio_folder, "master_audio_inventory.txt")))
        self.assertTrue(os.path.exists(os.path.join(audio_folder, "audio_files")))

    def test_14_notes_parser_dynamic_schema(self):
        from parsers.notes_parser import NotesParser

        # Create mock NoteStore with legacy column names (ZTITLE instead of ZTITLE1, ZMODIFICATIONDATE instead of ZMODIFICATIONDATE1)
        notes_db = os.path.join(self.test_dir, "notes_legacy.sqlite")
        conn = sqlite3.connect(notes_db)
        conn.execute("""
            CREATE TABLE ZICCLOUDSYNCINGOBJECT (
                Z_PK INTEGER PRIMARY KEY,
                ZTITLE TEXT,
                ZSNIPPET TEXT,
                ZCREATIONDATE REAL,
                ZMODIFICATIONDATE REAL,
                ZMARKEDFORDELETION INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (
                1, 'Banking Secrets Note', 'eSewa PIN is 4829', 700000000.0, 700005000.0, 0
            )
        """)
        conn.commit()
        conn.close()

        parser = NotesParser(notes_db)
        notes = parser.parse()
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["title"], "Banking Secrets Note")
        self.assertEqual(notes[0]["snippet"], "eSewa PIN is 4829")

    def test_15_universal_apps_parser_alias(self):
        from parsers.universal_apps_parser import UniversalAppEngine

        engine = UniversalAppEngine(manifest_resolver=None)
        res = engine.parse()
        self.assertIn("messages", res)
        self.assertIn("app_counts", res)

    def test_16_unified_forensic_engine(self):
        from core.unified_engine import UnifiedForensicEngine

        # Create simulated backup dir
        backup_dir = os.path.join(self.test_dir, "mock_backup")
        out_dir = os.path.join(self.test_dir, "mock_output")
        os.makedirs(backup_dir, exist_ok=True)

        # Create Manifest.db
        m_db = os.path.join(backup_dir, "Manifest.db")
        conn = sqlite3.connect(m_db)
        conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        conn.commit()
        conn.close()

        engine = UnifiedForensicEngine(backup_dir, out_dir)
        data = engine.run()

        self.assertIsInstance(data, dict)
        self.assertIn("messages", data)
        self.assertIn("whatsapp", data)
        self.assertIn("photos", data)
        self.assertIn("keychain", data)
        self.assertTrue(os.path.exists(out_dir))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "01_Extracted_Plain_Evidence")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "Structured_CSV_and_SIEM_Exports")))

    def test_17_tiktok_and_facebook_messenger_extraction(self):
        import plistlib
        from parsers.enterprise_apps_parser import EnterpriseAppsParser
        from exporters.plain_text_tree_exporter import PlainTextTreeExporter
        from unittest.mock import MagicMock

        # Create mock SQLite databases
        tt_db_path = os.path.join(self.test_dir, "AwemeIM.db")
        conn = sqlite3.connect(tt_db_path)
        conn.execute("""
            CREATE TABLE TTKIMContactBaseUserV14 (
                uid TEXT PRIMARY KEY,
                customID TEXT,
                nickname TEXT,
                signature TEXT,
                followerCount INTEGER,
                followingCount INTEGER,
                isBlocked INTEGER,
                lastUpdatedTime REAL
            )
        """)
        conn.execute("""
            INSERT INTO TTKIMContactBaseUserV14 VALUES (
                '6541493000240152581', 'anudit1.5', 'Anudit Khatri', 'DFIR Specialist', 1200, 45, 0, 1740712851601.0
            )
        """)
        conn.execute("CREATE TABLE AwemeShareRecords (rid TEXT, loginUserID TEXT, recentShareTimestamp REAL)")
        conn.execute("INSERT INTO AwemeShareRecords VALUES ('1', '6541493000240152581', 1740712851601.0)")
        conn.execute("CREATE TABLE TTKIMContactAccessFrequencyModelV1 (uid TEXT, accessCount INTEGER, lastAccessDate REAL)")
        conn.execute("INSERT INTO TTKIMContactAccessFrequencyModelV1 VALUES ('6541493000240152581', 88, 1758249678727.0)")
        conn.commit()
        conn.close()

        # Create mock Messenger push database
        msgr_db_path = os.path.join(self.test_dir, "FOAPushInfraNotificationStorage_v1_MSGR_100014961630245.sqlite")
        conn = sqlite3.connect(msgr_db_path)
        conn.execute("""
            CREATE TABLE foa_pi_notification_threads (
                THREAD_ID TEXT,
                THREAD_TIMESTAMP_MS INTEGER,
                IRIS_SEQ_ID INTEGER,
                IRIS_ENQUEUE_TIMESTAMP_MS INTEGER
            )
        """)
        conn.execute("INSERT INTO foa_pi_notification_threads VALUES ('3648139475239865', 1791253965488, 1811, 1791253967015)")
        conn.commit()
        conn.close()

        # Create mock Facebook session plist
        fb_plist_path = os.path.join(self.test_dir, "FBPreferencesKit_100014961630245.session.plist")
        with open(fb_plist_path, "wb") as f:
            plistlib.dump({
                "kFbIgXpostingDestinationSettingNameKey": "aainatrialnp",
                "FBNotificationLastSyncTime": "2026-10-06 15:17:11.000000"
            }, f)

        # Mock resolver
        mock_resolver = MagicMock()
        mock_resolver.find_all_files.side_effect = lambda **kwargs: [tt_db_path] if "AwemeIM" in str(kwargs) or "musical" in str(kwargs) else []
        mock_resolver.file_map = {
            ("AppDomain-com.zhiliaoapp.musically", "Documents/AwemeIM.db"): tt_db_path,
            ("AppDomainGroup-group.com.facebook.Messenger", "FOAPushInfraNotificationStorage_v1_MSGR_100014961630245.sqlite"): msgr_db_path,
            ("AppDomain-com.facebook.Facebook", "Library/Preferences/FBPreferencesKit_100014961630245.session.plist"): fb_plist_path
        }

        parser = EnterpriseAppsParser(manifest_resolver=mock_resolver)
        res = parser.parse()

        self.assertEqual(len(res["tiktok_contacts"]), 1)
        self.assertEqual(res["tiktok_contacts"][0]["handle"], "anudit1.5")
        self.assertEqual(res["tiktok_contacts"][0]["access_count"], 88)
        self.assertTrue(res["tiktok_contacts"][0]["is_owner"])
        self.assertEqual(res["tiktok_owner"]["handle"], "anudit1.5")

        self.assertEqual(len(res["messenger_accounts"]), 1)
        self.assertEqual(res["messenger_accounts"][0]["account_fbid"], "100014961630245")
        self.assertEqual(res["messenger_accounts"][0]["linked_instagram_user"], "aainatrialnp")

        self.assertEqual(len(res["messenger_threads"]), 1)
        self.assertEqual(res["messenger_threads"][0]["thread_id"], "3648139475239865")

        # Test exporter writes dedicated plain text and CSV files
        out_export_dir = os.path.join(self.test_dir, "test_export_tp")
        exporter = PlainTextTreeExporter(out_export_dir, {"enterprise_apps": res}, {})
        exporter.export_all()

        tp_dir = os.path.join(out_export_dir, "01_Extracted_Plain_Evidence", "07_Third_Party_and_Social_Apps")
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "tiktok_user_profiles_and_contacts.txt")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "tiktok_user_profiles_and_contacts.csv")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "facebook_accounts_and_linked_profiles.txt")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "facebook_messenger_notification_threads.txt")))

        with open(os.path.join(tp_dir, "tiktok_user_profiles_and_contacts.txt"), "r", encoding="utf-8") as f:
            tt_txt = f.read()
            self.assertIn("@anudit1.5", tt_txt)
            self.assertIn("Anudit Khatri", tt_txt)

    def test_18_snapchat_and_social_media_attachments(self):
        from parsers.enterprise_apps_parser import EnterpriseAppsParser
        from exporters.plain_text_tree_exporter import PlainTextTreeExporter
        from unittest.mock import MagicMock

        # 1. Mock Snapchat arroyo.db & scdb.sqlite
        snap_arroyo_path = os.path.join(self.test_dir, "arroyo.db")
        conn = sqlite3.connect(snap_arroyo_path)
        conn.execute("""
            CREATE TABLE conversation_message (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT,
                sender_id TEXT,
                message_content TEXT,
                creation_timestamp INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO conversation_message VALUES (
                'MSG-SNAP-001', 'CONV-1234', 'khatri_anudit', 'Meet me at the cyber lab at 5pm', 1700000000
            )
        """)
        conn.commit()
        conn.close()

        snap_scdb_path = os.path.join(self.test_dir, "scdb.sqlite")
        conn = sqlite3.connect(snap_scdb_path)
        conn.execute("""
            CREATE TABLE Friend (
                userId TEXT PRIMARY KEY,
                username TEXT,
                displayName TEXT,
                score INTEGER,
                streak INTEGER,
                addedTimestamp INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO Friend VALUES (
                'USER-999', 'anudit_snap', 'Anudit Khatri', 1250, 42, 1690000000
            )
        """)
        conn.commit()
        conn.close()

        # 2. Mock social media attachments
        wa_img = os.path.join(self.test_dir, "PHOTO_WHATSAPP_001.JPG")
        with open(wa_img, "wb") as f:
            f.write(b"\xFF\xD8\xFF\xE0" + b"EVIDENCE_IMAGE" * 100)

        snap_vid = os.path.join(self.test_dir, "SNAP_SAVED_VIDEO.MP4")
        with open(snap_vid, "wb") as f:
            f.write(b"\x00\x00\x00\x18ftypmp42" + b"EVIDENCE_VIDEO" * 100)

        mock_resolver = MagicMock()
        mock_resolver.find_all_files.side_effect = lambda **kwargs: (
            [snap_arroyo_path] if "arroyo" in str(kwargs) or "picaboo" in str(kwargs) else (
                [snap_scdb_path] if "scdb" in str(kwargs) else []
            )
        )
        mock_resolver.file_map = {
            ("AppDomain-com.toyopagroup.picaboo", "Documents/arroyo.db"): snap_arroyo_path,
            ("AppDomain-com.toyopagroup.picaboo", "Documents/scdb.sqlite"): snap_scdb_path,
            ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "Message/Media/PHOTO_WHATSAPP_001.JPG"): wa_img,
            ("AppDomain-com.toyopagroup.picaboo", "Documents/gallery/SNAP_SAVED_VIDEO.MP4"): snap_vid,
        }

        parser = EnterpriseAppsParser(manifest_resolver=mock_resolver)
        res = parser.parse()

        self.assertEqual(len(res["snapchat"]), 1)
        self.assertEqual(res["snapchat"][0]["sender"], "khatri_anudit")
        self.assertEqual(res["snapchat"][0]["text"], "Meet me at the cyber lab at 5pm")

        self.assertEqual(len(res["snapchat_friends"]), 1)
        self.assertEqual(res["snapchat_friends"][0]["username"], "anudit_snap")
        self.assertEqual(res["snapchat_friends"][0]["streak"], 42)

        self.assertEqual(len(res["social_media_attachments"]), 2)
        apps = set(a["app"] for a in res["social_media_attachments"])
        self.assertIn("WhatsApp", apps)
        self.assertIn("Snapchat", apps)

        # Export test
        out_dir = os.path.join(self.test_dir, "test_snap_export")
        exporter = PlainTextTreeExporter(out_dir, {"enterprise_apps": res}, {})
        exporter.export_all()

        tp_dir = os.path.join(out_dir, "01_Extracted_Plain_Evidence", "07_Third_Party_and_Social_Apps")
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "snapchat_messages.txt")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "snapchat_friends.txt")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "social_media_attachments_inventory.txt")))
        self.assertTrue(os.path.exists(os.path.join(tp_dir, "social_media_attachments_inventory.csv")))

        # Check carved media file
        media_carved_dir = os.path.join(tp_dir, "social_media_media_files")
        self.assertTrue(os.path.exists(media_carved_dir))

if __name__ == "__main__":
    unittest.main()

