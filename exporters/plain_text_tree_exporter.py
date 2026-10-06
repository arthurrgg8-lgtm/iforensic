import os
import csv
import json
import shutil
from datetime import datetime

class PlainTextTreeExporter:
    """
    Exports all carved, decrypted, and extracted forensic data into
    human-readable plain text (.txt), spreadsheets (.csv), and structured (.json)
    files organized into intuitive, self-contained directories.
    """

    def __init__(self, output_base_dir, extracted_data, metadata=None, manifest_resolver=None):
        self.output_base_dir = os.path.abspath(output_base_dir)
        self.extracted_data = extracted_data or {}
        self.metadata = metadata or {}
        self.manifest_resolver = manifest_resolver
        self.resolver = manifest_resolver
        self.root_export_dir = os.path.join(self.output_base_dir, "01_Extracted_Plain_Evidence")

    def export_all(self):
        """
        Executes complete plain-text and structured hierarchical folder export.
        Returns root export directory path.
        """
        os.makedirs(self.root_export_dir, exist_ok=True)

        self._export_device_profile()
        self._export_messages()
        self._export_calls_and_voicemails()
        self._export_contacts()
        self._export_notes_and_passwords()
        self._export_audio_and_recordings()
        self._export_keychain_and_keys()
        self._export_enterprise_apps()
        self._export_whatsapp()
        self._export_photos_and_videos()
        self._export_web_and_activity()
        self._export_timeline()
        self._export_decrypted_databases()
        self._export_deleted_carved_records()
        self._export_case_overview()

        return self.root_export_dir

    def _export_device_profile(self):
        folder = os.path.join(self.root_export_dir, "00_Device_and_System_Profile")
        os.makedirs(folder, exist_ok=True)

        meta = self.metadata or {}
        # 1. Plain Text Device Info
        with open(os.path.join(folder, "device_hardware_profile.txt"), "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("               APPLE iOS DEVICE HARDWARE & SYSTEM IDENTITY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Device Name               : {meta.get('device_name', 'Unknown')}\n")
            f.write(f"Marketing Model Name      : {meta.get('model_friendly_name') or meta.get('display_name', 'iPhone')}\n")
            f.write(f"Hardware Model Identifier : {meta.get('product_type', 'iPhone')}\n")
            f.write(f"iOS Operating System      : iOS {meta.get('product_version', 'N/A')}\n")
            f.write(f"OS Build Number           : {meta.get('build_version', 'Unknown')}\n")
            f.write(f"Hardware Serial Number    : {meta.get('serial_number', 'N/A')}\n")
            f.write(f"Unique Device ID (UDID)   : {meta.get('udid', 'N/A')}\n")
            f.write(f"Unique Chip ID (ECID)     : {meta.get('ecid', 'N/A')}\n")
            f.write(f"Primary Cellular IMEI     : {meta.get('imei', 'N/A')}\n")
            if meta.get('imei2') and meta.get('imei2') != 'N/A':
                f.write(f"Secondary Cellular IMEI   : {meta.get('imei2')}\n")
            f.write(f"Mobile Equipment ID (MEID): {meta.get('meid', 'N/A')}\n")
            f.write(f"SIM Card ICCID            : {meta.get('iccid', 'N/A')}\n")
            f.write(f"Subscriber IMSI           : {meta.get('imsi', 'N/A')}\n")
            f.write(f"Assigned Phone Number     : {meta.get('phone_number', 'N/A')}\n")
            f.write(f"Wi-Fi MAC Address         : {meta.get('wifi_mac', 'N/A')}\n")
            f.write(f"Bluetooth MAC Address     : {meta.get('bluetooth_mac', 'N/A')}\n")
            f.write(f"Device Time Zone          : {meta.get('time_zone', 'N/A')}\n")
            f.write(f"Target Type               : {meta.get('target_type', 'Device')}\n")
            f.write(f"Last Backup Date & Time   : {meta.get('last_backup_date', 'N/A')}\n")
            f.write(f"Backup Encryption State   : {'Hardware Encrypted (AES-256)' if meta.get('is_encrypted') else 'Unencrypted Logical'}\n")
            if meta.get('backup_uuid') and meta.get('backup_uuid') != 'N/A':
                f.write(f"Backup Container UUID     : {meta.get('backup_uuid')}\n")
            if meta.get('installed_apps_count'):
                f.write(f"Installed Applications    : {meta.get('installed_apps_count')} applications\n")
            f.write("\n" + "=" * 80 + "\n")

        # 2. JSON Export
        with open(os.path.join(folder, "device_metadata.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False, default=str)

        # 3. CSV Export
        with open(os.path.join(folder, "device_metadata.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Property", "Value"])
            for k, v in meta.items():
                writer.writerow([k, str(v)])

    def _export_case_overview(self):
        meta_txt = os.path.join(self.root_export_dir, "00_CASE_METADATA_AND_SUMMARY.txt")
        with open(meta_txt, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("      iForensic — EXTRACTED DIGITAL EVIDENCE & INTELLIGENCE OVERVIEW\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Extraction Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("[DEVICE & HARDWARE PROFILE]\n")
            f.write(f"• Device Name          : {self.metadata.get('device_name', 'Unknown')}\n")
            f.write(f"• Friendly Model       : {self.metadata.get('model_friendly_name') or self.metadata.get('display_name', 'iPhone')}\n")
            f.write(f"• Hardware Model ID    : {self.metadata.get('product_type', 'iPhone')}\n")
            f.write(f"• iOS Version          : {self.metadata.get('product_version', 'N/A')} (Build {self.metadata.get('build_version', 'Unknown')})\n")
            f.write(f"• Serial Number        : {self.metadata.get('serial_number', 'N/A')}\n")
            f.write(f"• Unique Device ID     : {self.metadata.get('udid', 'N/A')}\n")
            f.write(f"• Unique Chip ID (ECID): {self.metadata.get('ecid', 'N/A')}\n")
            f.write(f"• Primary IMEI         : {self.metadata.get('imei', 'N/A')}\n")
            if self.metadata.get('imei2') and self.metadata.get('imei2') != 'N/A':
                f.write(f"• Secondary IMEI (SIM2): {self.metadata.get('imei2')}\n")
            f.write(f"• MEID                 : {self.metadata.get('meid', 'N/A')}\n")
            f.write(f"• SIM Card (ICCID)     : {self.metadata.get('iccid', 'N/A')}\n")
            f.write(f"• Subscriber ID (IMSI) : {self.metadata.get('imsi', 'N/A')}\n")
            f.write(f"• Assigned Phone Number: {self.metadata.get('phone_number', 'N/A')}\n")
            f.write(f"• Wi-Fi MAC Address    : {self.metadata.get('wifi_mac', 'N/A')}\n")
            f.write(f"• Bluetooth MAC        : {self.metadata.get('bluetooth_mac', 'N/A')}\n")
            f.write(f"• Device Time Zone     : {self.metadata.get('time_zone', 'N/A')}\n")
            f.write(f"• Backup Timestamp     : {self.metadata.get('last_backup_date', 'N/A')}\n")
            f.write(f"• Encryption Status    : {'Encrypted Backup (AES-256 Unwrapped)' if self.metadata.get('is_encrypted') else 'Unencrypted Plaintext'}\n")
            if self.metadata.get('backup_uuid') and self.metadata.get('backup_uuid') != 'N/A':
                f.write(f"• Backup UUID          : {self.metadata.get('backup_uuid')}\n")
            f.write("\n")

            f.write("-" * 80 + "\n")
            f.write("                     CARVED ARTIFACT RECORD TOTALS\n")
            f.write("-" * 80 + "\n")
            f.write(f"• Messages (SMS / iMessage)       : {len(self.extracted_data.get('messages', [])):,} records\n")
            f.write(f"• Call Logs & Telemetry          : {len(self.extracted_data.get('calls', [])):,} records\n")
            f.write(f"• Contacts & Directory            : {len(self.extracted_data.get('contacts', [])):,} records\n")
            f.write(f"• Apple Notes & Credentials       : {len(self.extracted_data.get('notes', [])):,} notes\n")
            f.write(f"• Financial Transactions & OTPs   : {len(self.extracted_data.get('financial', [])):,} ledger entries\n")
            f.write(f"• WhatsApp Chats & Groups         : {len(self.extracted_data.get('whatsapp', [])):,} messages\n")
            ent_dict = self.extracted_data.get("enterprise_apps", {})
            tt_cnt = len(ent_dict.get("tiktok_contacts", []))
            tt_fb_cnt = len(ent_dict.get("tiktok_feedback", []))
            fb_accts = len(ent_dict.get("messenger_accounts", []))
            fb_thrds = len(ent_dict.get("messenger_threads", []))
            ig_cnt = len(ent_dict.get("instagram", []))
            f.write(f"• TikTok Profiles & Contacts      : {tt_cnt:,} profiles ({tt_fb_cnt:,} activity logs)\n")
            f.write(f"• Facebook Messenger & Meta       : {fb_accts:,} accounts ({fb_thrds:,} active threads)\n")
            f.write(f"• Instagram Direct & Socials      : {ig_cnt:,} direct threads / messages\n")
            ent_total = ent_dict.get("total_enterprise_records", 0)
            f.write(f"• Total Third-Party App Records   : {ent_total:,} records\n")
            photo_total = len(self.extracted_data.get("photos", []))
            f.write(f"• Camera Roll Photos & Videos     : {photo_total:,} media assets\n")
            kc_total = len(self.extracted_data.get("keychain", {}).get("all_decrypted_records", []))
            f.write(f"• Decrypted Keychain & Keys       : {kc_total:,} carved credentials\n")
            deleted_total = len(self.extracted_data.get("deleted_carved_records", []))
            f.write(f"• Freelist Carved Deleted Records : {deleted_total:,} fragments\n")

    def _export_messages(self):
        msgs = self.extracted_data.get("messages", [])
        if not msgs:
            return

        import re
        folder = os.path.join(self.root_export_dir, "01_Messages_SMS_iMessage")
        os.makedirs(folder, exist_ok=True)

        fin_patterns = [
            r'(?i)(debited|credited|transferred|withdrawn|deposited|paid|received|txn|transaction|balance|npr|inr|usd|eur|gbp|a/c|acct|otp|esewa|khalti|wise|remit|upi)',
            r'(?i)(rs\.?\s*[\d,]+(\.\d{2})?|npr\s*[\d,]+|inr\s*[\d,]+|\$\s*[\d,]+)',
            r'(?i)(otp\s*(is|:)?\s*\d{4,8}|code\s*(is|:)?\s*\d{4,8}|verification\s*code\s*\d{4,8})'
        ]
        fin_sms = []

        # 1. Plain Text Transcript (with inline bank & OTP detection)
        with open(os.path.join(folder, "messages_chat_transcript.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== SMS & iMessage Transcript ({len(msgs):,} Messages) ===\n\n")
            for m in msgs:
                ts = m.get("timestamp_local", "N/A")
                sender = m.get("sender", "Unknown")
                recip = m.get("recipient", "N/A")
                direction = m.get("direction", "Unknown")
                svc = m.get("service", "SMS")
                text = m.get("text", "").strip()

                is_fin = any(re.search(p, text) for p in fin_patterns)
                tag = " [BANK/OTP ALERT]" if is_fin else ""
                if is_fin:
                    fin_sms.append(m)

                f.write(f"[{ts}] [{direction}] [{svc}]{tag} Sender: {sender} -> Recipient: {recip}\n")
                f.write(f"Body: {text}\n")
                f.write("-" * 60 + "\n")

        # 2. Tabular CSV
        with open(os.path.join(folder, "messages_database.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Recipient", "Direction", "Service", "Is_Financial_OTP", "Message_Text"])
            for m in msgs:
                text = m.get("text", "")
                is_fin = any(re.search(p, text) for p in fin_patterns)
                writer.writerow([
                    m.get("timestamp_local"),
                    m.get("timestamp_utc"),
                    m.get("sender"),
                    m.get("recipient"),
                    m.get("direction"),
                    m.get("service"),
                    "YES (Bank/OTP)" if is_fin else "No",
                    text
                ])

        # 3. Financial & Banking SMS Sub-Report
        if fin_sms:
            with open(os.path.join(folder, "financial_and_otp_sms.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Extracted Financial, Banking & Security OTP SMS ({len(fin_sms):,} Records) ===\n\n")
                for fm in fin_sms:
                    f.write(f"[{fm.get('timestamp_local')}] From: {fm.get('sender')} -> {fm.get('recipient')}\n")
                    f.write(f"Alert: {fm.get('text')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "financial_and_otp_sms.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Bank_or_Sender", "Recipient", "Message_Content"])
                for fm in fin_sms:
                    w.writerow([fm.get("timestamp_local"), fm.get("timestamp_utc"), fm.get("sender"), fm.get("recipient"), fm.get("text")])

        # 4. JSON Dump
        with open(os.path.join(folder, "messages_records.json"), "w", encoding="utf-8") as f:
            json.dump(msgs, f, indent=2, ensure_ascii=False, default=str)

    def _export_calls_and_voicemails(self):
        calls = self.extracted_data.get("calls", [])
        recs = self.extracted_data.get("recordings", {})
        voicemails = recs.get("voicemails", [])

        if not calls and not voicemails:
            return

        folder = os.path.join(self.root_export_dir, "02_Calls_and_Voicemails")
        os.makedirs(folder, exist_ok=True)

        # 1. Call History Text Summary
        if calls:
            from parsers.calls_parser import CallsParser
            calls_parser_instance = CallsParser(None)
            calls_parser_instance.calls = calls
            analytics = calls_parser_instance.get_frequency_analytics()

            with open(os.path.join(folder, "call_history_summary.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Call History & Voice Telemetry ({len(calls):,} Calls) ===\n\n")
                for c in calls:
                    ts = c.get("timestamp_local", "N/A")
                    name = c.get("contact_name", "Unknown")
                    num = c.get("number", "Unknown")
                    direction = c.get("direction", "UNKNOWN")
                    status = c.get("status", "N/A")
                    dur = c.get("duration_formatted", "0s (Unanswered)")
                    prov = c.get("service_provider", "Cellular")
                    loc = f" | Location: {c.get('location')}" if c.get('location') else ""
                    f.write(f"[{ts}] [{direction}] {status} | Contact: {name} ({num}) | Duration: {dur} ({c.get('duration_seconds', 0)}s) | Provider: {prov}{loc}\n")

            # 2. Call Frequency Analysis Report
            with open(os.path.join(folder, "call_frequency_analysis.txt"), "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("         TELEPHONY & CALL COMMUNICATION FREQUENCY ANALYSIS\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Total Call Events Recorded : {analytics.get('total_calls', 0):,}\n")
                f.write(f"• Inbound Calls (Answered) : {analytics.get('total_incoming', 0):,}\n")
                f.write(f"• Outbound Calls           : {analytics.get('total_outgoing', 0):,}\n")
                f.write(f"• Missed / Unanswered      : {analytics.get('total_missed', 0):,}\n")
                f.write(f"• Cumulative Talk Time     : {analytics.get('total_duration_formatted', '0s')} ({analytics.get('total_duration_hms', '00:00:00')})\n")
                f.write(f"  ↳ Inbound Duration       : {analytics.get('inbound_duration_formatted', '0s')}\n")
                f.write(f"  ↳ Outbound Duration      : {analytics.get('outbound_duration_formatted', '0s')}\n")
                f.write(f"• Average Call Duration    : {analytics.get('average_duration_formatted', '0s')}\n\n")

                f.write("-" * 80 + "\n")
                f.write("           TOP FREQUENT COMMUNICATION PARTNERS (RANKED)\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Rank':<5} {'Contact / Phone Number':<30} {'Total':<8} {'In/Out/Missed':<18} {'Talk Time':<14} {'Last Contact Date':<20}\n")
                f.write("-" * 80 + "\n")

                for idx, fc in enumerate(analytics.get("frequent_contacts", []), start=1):
                    actor = fc.get("display_actor", "Unknown")[:28]
                    tot = fc.get("total_calls", 0)
                    ratio = fc.get("ratio_summary", "")
                    tt = fc.get("total_duration_formatted", "0s")
                    last_c = fc.get("last_call_local", "N/A")
                    f.write(f"#{idx:<4} {actor:<30} {tot:<8} {ratio:<18} {tt:<14} {last_c:<20}\n")

                if analytics.get("peak_hours"):
                    f.write("\n" + "-" * 80 + "\n")
                    f.write("                   PEAK CALLING ACTIVITY HOURS (UTC/LOCAL)\n")
                    f.write("-" * 80 + "\n")
                    for hr, cnt in analytics["peak_hours"]:
                        f.write(f"• {hr:02d}:00 - {hr:02d}:59 : {cnt:,} calls\n")

                if analytics.get("peak_weekdays"):
                    f.write("\n" + "-" * 80 + "\n")
                    f.write("                 CALL ACTIVITY BY DAY OF THE WEEK\n")
                    f.write("-" * 80 + "\n")
                    for day, cnt in analytics["peak_weekdays"]:
                        f.write(f"• {day:<10} : {cnt:,} calls\n")

            # 3. Call History CSV
            with open(os.path.join(folder, "call_history.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Record_ID", "Timestamp_Local", "Timestamp_UTC", "Direction", "Call_Status", "Contact_Name", "Phone_Number", "Duration_Formatted", "Duration_Seconds", "Duration_HMS", "Provider", "Location"])
                for c in calls:
                    writer.writerow([
                        c.get("record_id", ""),
                        c.get("timestamp_local"),
                        c.get("timestamp_utc"),
                        c.get("direction"),
                        c.get("status"),
                        c.get("contact_name"),
                        c.get("number"),
                        c.get("duration_formatted"),
                        c.get("duration_seconds"),
                        c.get("duration_hms"),
                        c.get("service_provider"),
                        c.get("location", "")
                    ])

            # 4. Call Frequency Summary CSV
            with open(os.path.join(folder, "call_frequency_summary.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Rank", "Contact_Name", "Phone_Number", "Total_Calls", "Incoming_Count", "Outgoing_Count", "Missed_Count", "Ratio_Summary", "Total_Duration_Formatted", "Total_Duration_Seconds", "Total_Duration_HMS", "Avg_Duration_Formatted", "First_Call_Local", "Last_Call_Local"])
                for idx, fc in enumerate(analytics.get("frequent_contacts", []), start=1):
                    writer.writerow([
                        idx,
                        fc.get("contact_name"),
                        fc.get("number"),
                        fc.get("total_calls"),
                        fc.get("incoming_count"),
                        fc.get("outgoing_count"),
                        fc.get("missed_count"),
                        fc.get("ratio_summary"),
                        fc.get("total_duration_formatted"),
                        fc.get("total_duration_seconds"),
                        fc.get("total_duration_hms"),
                        fc.get("avg_duration_formatted"),
                        fc.get("first_call_local"),
                        fc.get("last_call_local")
                    ])

            with open(os.path.join(folder, "call_records.json"), "w", encoding="utf-8") as f:
                json.dump(calls, f, indent=2, ensure_ascii=False, default=str)

        # 3. Voicemails & Transcripts
        if voicemails:
            with open(os.path.join(folder, "voicemail_transcripts.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Carved Voicemails & Audio Transcriptions ({len(voicemails):,} Records) ===\n\n")
                for v in voicemails:
                    ts = v.get("timestamp_local", "N/A")
                    sender = v.get("sender", "Unknown")
                    dur = v.get("duration_formatted", "00:00")
                    transcript = v.get("transcription", "No transcription available")
                    f.write(f"[{ts}] From: {sender} | Duration: {dur}\n")
                    f.write(f"Transcription: {transcript}\n")
                    f.write("-" * 60 + "\n")

    def _export_contacts(self):
        contacts = self.extracted_data.get("contacts", [])
        if not contacts:
            return

        folder = os.path.join(self.root_export_dir, "03_Contacts_and_Identities")
        os.makedirs(folder, exist_ok=True)

        # 1. Plain Text Directory
        with open(os.path.join(folder, "contacts_directory.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== Unified Contacts Directory ({len(contacts):,} Contacts) ===\n\n")
            for c in contacts:
                name = c.get("name", "Unnamed Contact")
                phone_list = c.get("phone_numbers") or ([c["phone"]] if c.get("phone") else [])
                email_list = c.get("emails") or ([c["email"]] if c.get("email") else [])
                nums = ", ".join(phone_list) or "None"
                emails = ", ".join(email_list) or "None"
                org = c.get("organization") or ""
                job = c.get("job_title") or ""
                tc = c.get("truecaller_match") or ""
                note = c.get("note") or c.get("notes") or ""
                
                f.write(f"Name         : {name}\n")
                f.write(f"Phone Numbers: {nums}\n")
                f.write(f"Emails       : {emails}\n")
                if org or job: f.write(f"Work / Job   : {job} at {org}\n")
                if tc: f.write(f"Truecaller   : {tc}\n")
                if note: f.write(f"Note         : {note}\n")
                f.write("-" * 60 + "\n")

        # 2. CSV
        with open(os.path.join(folder, "contacts_directory.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Contact_Name", "Phone_Numbers", "Emails", "Organization", "Job_Title", "Truecaller_Match", "Notes"])
            for c in contacts:
                phone_list = c.get("phone_numbers") or ([c["phone"]] if c.get("phone") else [])
                email_list = c.get("emails") or ([c["email"]] if c.get("email") else [])
                writer.writerow([
                    c.get("name"),
                    "; ".join(phone_list),
                    "; ".join(email_list),
                    c.get("organization"),
                    c.get("job_title"),
                    c.get("truecaller_match"),
                    c.get("note") or c.get("notes")
                ])

        with open(os.path.join(folder, "contacts_records.json"), "w", encoding="utf-8") as f:
            json.dump(contacts, f, indent=2, ensure_ascii=False, default=str)

    def _export_notes_and_passwords(self):
        notes = self.extracted_data.get("notes", [])
        if not notes:
            return

        folder = os.path.join(self.root_export_dir, "04_Notes_and_Passwords")
        indiv_folder = os.path.join(folder, "individual_notes_plain")
        os.makedirs(indiv_folder, exist_ok=True)

        # 1. Summary Index Text
        with open(os.path.join(folder, "notes_summary_index.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== Apple Notes & Stored Credentials Index ({len(notes):,} Notes) ===\n\n")
            for idx, n in enumerate(notes, 1):
                title = n.get("title", f"Untitled Note {idx}")
                mod = n.get("modified_local", "N/A")
                fold = n.get("folder", "Notes")
                snip = n.get("snippet", "")
                f.write(f"[{idx:02d}] {title}\n")
                f.write(f"     Folder: {fold} | Modified: {mod}\n")
                f.write(f"     Preview: {snip[:120]}...\n\n")

        # 2. Individual Note Files (.txt for every note!)
        for idx, n in enumerate(notes, 1):
            raw_title = n.get("title", f"Note_{idx}")
            clean_title = "".join(c if c.isalnum() or c in (" ", "_", "-") else "_" for c in raw_title).strip()
            clean_title = clean_title[:40] or f"Note_{idx}"
            fname = f"{idx:02d}_{clean_title}.txt"
            
            with open(os.path.join(indiv_folder, fname), "w", encoding="utf-8") as nf:
                nf.write(f"Title   : {n.get('title')}\n")
                nf.write(f"Folder  : {n.get('folder', 'Notes')}\n")
                nf.write(f"Modified: {n.get('modified_local', 'N/A')}\n")
                nf.write(f"Created : {n.get('created_local', 'N/A')}\n")
                nf.write("=" * 60 + "\n\n")
                nf.write(n.get("full_content", n.get("snippet", "")))
                nf.write("\n")

        # 3. Tabular CSV Export
        with open(os.path.join(folder, "notes_database.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Index", "Title", "Folder", "Created_Local", "Modified_Local", "Is_Recently_Deleted", "Tags", "Full_Content"])
            for idx, n in enumerate(notes, 1):
                writer.writerow([
                    idx,
                    n.get("title"),
                    n.get("folder"),
                    n.get("created_local"),
                    n.get("modified_local"),
                    n.get("is_deleted", False),
                    "; ".join(n.get("tags", [])),
                    n.get("full_content", n.get("snippet", ""))
                ])

        with open(os.path.join(folder, "notes_records.json"), "w", encoding="utf-8") as f:
            json.dump(notes, f, indent=2, ensure_ascii=False, default=str)

    def _export_audio_and_recordings(self):
        rec_data = self.extracted_data.get("recordings", {})
        voice_memos = rec_data.get("voice_memos", [])
        voicemails = rec_data.get("voicemails", [])
        carved_audio = rec_data.get("carved_audio_files", [])

        if not voice_memos and not voicemails and not carved_audio:
            return

        folder = os.path.join(self.root_export_dir, "05_Audio_Recordings_and_Voice_Memos")
        raw_audio_dir = os.path.join(folder, "audio_files")
        os.makedirs(raw_audio_dir, exist_ok=True)

        # 1. Voice Memos Catalog & Transcripts
        if voice_memos:
            with open(os.path.join(folder, "voice_memos_index.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Apple Voice Memos & Recordings ({len(voice_memos):,} Records) ===\n\n")
                for vm in voice_memos:
                    ts = vm.get("timestamp_local", "N/A")
                    title = vm.get("title", "Voice Memo")
                    dur = vm.get("duration_seconds", 0)
                    rel_p = vm.get("file_rel_path", "")
                    del_tag = " [DELETED]" if vm.get("deleted") else ""
                    f.write(f"[{ts}]{del_tag} Title: {title} | Duration: {dur}s\n")
                    if rel_p:
                        f.write(f"Source File: {rel_p}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "voice_memos_database.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Title", "Duration_Seconds", "File_Path", "Is_Deleted"])
                for vm in voice_memos:
                    writer.writerow([
                        vm.get("timestamp_local"),
                        vm.get("timestamp_utc"),
                        vm.get("title"),
                        vm.get("duration_seconds"),
                        vm.get("file_rel_path"),
                        vm.get("deleted", False)
                    ])

        # 2. Voicemail Transcripts & Metadata
        if voicemails:
            with open(os.path.join(folder, "voicemail_transcriptions.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Voicemails & Audio Transcriptions ({len(voicemails):,} Voicemails) ===\n\n")
                for v in voicemails:
                    ts = v.get("timestamp_local", "N/A")
                    caller = v.get("caller_name") or v.get("sender", "Unknown")
                    dur = v.get("duration_seconds", 0)
                    trans = v.get("transcription", "[No transcription available]")
                    f.write(f"[{ts}] From: {caller} | Duration: {dur}s\n")
                    f.write(f"Transcript: {trans}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "voicemails_database.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Caller", "Duration_Seconds", "Transcription", "Is_Trashed"])
                for v in voicemails:
                    writer.writerow([
                        v.get("timestamp_local"),
                        v.get("timestamp_utc"),
                        v.get("caller_name") or v.get("sender"),
                        v.get("duration_seconds"),
                        v.get("transcription"),
                        v.get("is_trashed", False)
                    ])

        # 3. Carved Audio Files Copying & Master Audio Inventory
        master_audio_list = []
        for idx, af in enumerate(carved_audio, 1):
            src_p = af.get("path")
            fname = af.get("filename") or f"audio_{idx}{af.get('extension', '.m4a')}"
            clean_name = f"{idx:03d}_{os.path.basename(fname)}"
            dest_p = os.path.join(raw_audio_dir, clean_name)

            if src_p and os.path.exists(src_p):
                try:
                    if not os.path.exists(dest_p):
                        shutil.copy2(src_p, dest_p)
                except Exception:
                    pass

            master_audio_list.append({
                "index": idx,
                "filename": fname,
                "category": af.get("category", "Audio File"),
                "extension": af.get("extension", ""),
                "size_kb": af.get("size_kb", 0),
                "relative_path": af.get("relative_path", ""),
                "exported_file": clean_name if os.path.exists(dest_p) else "Not Exported"
            })

        if master_audio_list:
            with open(os.path.join(folder, "master_audio_inventory.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Master Carved Audio Files & Voice Notes Inventory ({len(master_audio_list):,} Audio Files) ===\n\n")
                for a in master_audio_list:
                    f.write(f"[{a['index']:03d}] {a['filename']} ({a['size_kb']} KB) | Type: {a['category']}\n")
                    f.write(f"      Original Path: {a['relative_path']}\n")
                    f.write(f"      Exported File: audio_files/{a['exported_file']}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "master_audio_inventory.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Index", "Filename", "Category", "Extension", "Size_KB", "Original_Relative_Path", "Exported_File"])
                for a in master_audio_list:
                    writer.writerow([a["index"], a["filename"], a["category"], a["extension"], a["size_kb"], a["relative_path"], a["exported_file"]])

        with open(os.path.join(folder, "audio_evidence_records.json"), "w", encoding="utf-8") as f:
            json.dump({
                "voice_memos": voice_memos,
                "voicemails": voicemails,
                "carved_audio_files": master_audio_list
            }, f, indent=2, ensure_ascii=False, default=str)

    def _export_keychain_and_keys(self):
        kc = self.extracted_data.get("keychain", {})
        all_recs = kc.get("all_decrypted_records", [])
        if not all_recs:
            all_recs = (kc.get("web_credentials", []) + kc.get("wifi_networks", []) +
                        kc.get("app_tokens_and_keys", []) + kc.get("crypto_keys", []))

        if not all_recs:
            return

        folder = os.path.join(self.root_export_dir, "06_Decrypted_Keychain_and_Keys")
        os.makedirs(folder, exist_ok=True)

        wifi_list = kc.get("wifi_networks", [])
        web_creds = kc.get("web_credentials", [])
        app_keys = kc.get("app_tokens_and_keys", [])
        crypto_keys = kc.get("crypto_keys", [])

        # 1. Wi-Fi Passwords Plain Text
        if wifi_list:
            with open(os.path.join(folder, "wifi_passwords_and_networks.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Carved Wi-Fi Networks & Passphrases ({len(wifi_list):,} Access Points) ===\n\n")
                for w in wifi_list:
                    acct = w.get("account", "Wi-Fi Network")
                    val = w.get("decrypted_value", "N/A")
                    pclass = w.get("protection_class", "N/A")
                    f.write(f"Access Point / SSID : {acct}\n")
                    f.write(f"Decrypted Password  : {val}\n")
                    f.write(f"Protection Class    : {pclass}\n")
                    f.write("-" * 60 + "\n")

        # 2. Web & Cloud Logins Plain Text
        real_web_creds = [
            wc for wc in web_creds
            if ((wc.get("url") and wc.get("url") != "N/A" and "http" in str(wc.get("url", ""))) or
                (wc.get("account") and wc.get("account") not in ("Unknown User", "System Account", "", "N/A"))) and
               (wc.get("decrypted_password") and not str(wc.get("decrypted_password")).startswith("["))
        ]
        if real_web_creds:
            with open(os.path.join(folder, "saved_web_logins_and_passwords.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Saved Safari Web & Cloud Credentials ({len(real_web_creds):,} Logins) ===\n\n")
                for wc in real_web_creds:
                    url = wc.get("url") or wc.get("server", "Web Portal")
                    acct = wc.get("account", "Unknown User")
                    pwd = wc.get("decrypted_password", "N/A")
                    pclass = wc.get("protection_class", "N/A")
                    f.write(f"URL / Portal       : {url}\n")
                    f.write(f"Account / Username : {acct}\n")
                    f.write(f"Password / Secret  : {pwd}\n")
                    f.write(f"Protection Class   : {pclass}\n")
                    f.write("-" * 60 + "\n")

        # 3. App Database Cipher Keys Plain Text
        if app_keys:
            with open(os.path.join(folder, "app_database_cipher_keys.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Application Database Encryption Keys & Token Secrets ({len(app_keys):,} Keys) ===\n\n")
                for ak in app_keys:
                    agrp = ak.get("access_group", "N/A")
                    svce = ak.get("service") or ak.get("account", "Database Key")
                    val = ak.get("decrypted_value", "N/A")
                    f.write(f"Target App / Group : {agrp}\n")
                    f.write(f"Key Identifier     : {svce}\n")
                    f.write(f"Cryptographic Key  : {val}\n")
                    f.write("-" * 60 + "\n")

        # 4. Master Cryptographic Key Ring Plain Text
        if crypto_keys:
            with open(os.path.join(folder, "cryptographic_key_ring.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Hardware & Cryptographic Key Ring ({len(crypto_keys):,} Keys) ===\n\n")
                for ck in crypto_keys:
                    labl = ck.get("label", "Crypto Key")
                    ktype = ck.get("key_type", "AES Key")
                    bits = ck.get("bit_size", "256")
                    val = ck.get("decrypted_key_payload", "N/A")
                    f.write(f"Key Label   : {labl}\n")
                    f.write(f"Type / Size : {ktype} ({bits} bits)\n")
                    f.write(f"Key Payload : {val}\n")
                    f.write("-" * 60 + "\n")

        # 5. Full Tabular CSV Export
        with open(os.path.join(folder, "keychain_credentials.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Index", "Type", "Service_URL", "Account", "Decrypted_Password_or_Key", "Protection_Class"])
            for idx, r in enumerate(all_recs, 1):
                writer.writerow([
                    idx,
                    r.get("type", "Credential"),
                    r.get("service") or r.get("url", ""),
                    r.get("account", ""),
                    r.get("decrypted_password") or r.get("decrypted_value", ""),
                    r.get("protection_class", "")
                ])

        # 6. Full JSON Dump
        with open(os.path.join(folder, "Keychain_Decrypted_Secrets.json"), "w", encoding="utf-8") as f:
            json.dump(kc, f, indent=2, ensure_ascii=False, default=str)

        # 6. Cryptographic KeyBag Manifest
        if self.manifest_resolver and self.manifest_resolver.crypto_engine:
            self.manifest_resolver.crypto_engine.export_keybag_manifest(
                os.path.join(folder, "Cryptographic_KeyBag_Manifest.txt")
            )
            self.manifest_resolver.crypto_engine.export_keybag_manifest(
                os.path.join(self.output_base_dir, "Cryptographic_KeyBag_Manifest.txt")
            )

    def _export_financial_ledger(self):
        fin = self.extracted_data.get("financial", [])
        if not fin:
            return

        folder = os.path.join(self.root_export_dir, "06_Financial_Ledger_and_OTPs")
        os.makedirs(folder, exist_ok=True)

        # 1. Plain Text Ledger Summary
        with open(os.path.join(folder, "financial_ledger_summary.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== Financial Transactions & Movement Ledger ({len(fin):,} Events) ===\n\n")
            for item in fin:
                ts = item.get("timestamp_local", "N/A")
                entity = item.get("entity", "Bank / Financial Service")
                ttype = item.get("type", "Transaction")
                amt = item.get("amount", "N/A")
                summary = item.get("summary", "").strip()
                f.write(f"[{ts}] [{ttype.upper()}] {entity} | Amount: {amt}\n")
                f.write(f"Details: {summary}\n")
                f.write("-" * 60 + "\n")

        # 2. CSV
        with open(os.path.join(folder, "financial_transactions.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp_Local", "Entity", "Transaction_Type", "Amount", "Summary_Details"])
            for item in fin:
                writer.writerow([
                    item.get("timestamp_local"),
                    item.get("entity"),
                    item.get("type"),
                    item.get("amount"),
                    item.get("summary")
                ])

        # 3. Filtered Bank OTPs & Security Codes Plain Text
        otps = [item for item in fin if "otp" in item.get("type", "").lower() or "otp" in item.get("summary", "").lower() or "code" in item.get("summary", "").lower()]
        if otps:
            with open(os.path.join(folder, "bank_otps_and_alerts.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Carved Bank OTPs, 2FA Codes & Security Alerts ({len(otps):,} Codes) ===\n\n")
                for o in otps:
                    ts = o.get("timestamp_local", "N/A")
                    entity = o.get("entity", "Bank")
                    summary = o.get("summary", "")
                    f.write(f"[{ts}] {entity}: {summary}\n")

        with open(os.path.join(folder, "financial_records.json"), "w", encoding="utf-8") as f:
            json.dump(fin, f, indent=2, ensure_ascii=False, default=str)

    def _export_enterprise_apps(self):
        ent = self.extracted_data.get("enterprise_apps", {})
        tt_contacts = ent.get("tiktok_contacts", [])
        tt_feedback = ent.get("tiktok_feedback", [])
        tt_freq = ent.get("tiktok_frequent", [])
        fb_accounts = ent.get("messenger_accounts", [])
        msgr_threads = ent.get("messenger_threads", [])
        messenger = ent.get("messenger", [])
        snap = ent.get("snapchat", [])
        snap_friends = ent.get("snapchat_friends", [])
        attachments = ent.get("social_media_attachments", [])
        tg = ent.get("telegram", [])
        viber = ent.get("viber", [])
        viber_calls = ent.get("viber_calls", [])
        signal = ent.get("signal", [])
        insta = ent.get("instagram", [])
        teams = ent.get("teams", [])
        discord = ent.get("discord", [])
        skype = ent.get("skype", [])
        line = ent.get("line", [])
        wechat = ent.get("wechat", [])
        proton = ent.get("protonmail", [])
        generic = ent.get("generic_apps", [])

        if not any([tt_contacts, tt_feedback, fb_accounts, msgr_threads, messenger, snap, snap_friends, attachments, tg, viber, viber_calls, signal, insta, teams, discord, skype, line, wechat, proton, generic]):
            return

        folder = os.path.join(self.root_export_dir, "07_Third_Party_and_Social_Apps")
        os.makedirs(folder, exist_ok=True)

        # 1. TikTok Profiles & Contacts Directory
        if tt_contacts:
            owner = ent.get("tiktok_owner", {})
            with open(os.path.join(folder, "tiktok_user_profiles_and_contacts.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== TikTok (Aweme) Discovered Contacts & Profiles ({len(tt_contacts):,} Profiles) ===\n\n")
                if owner:
                    f.write("*" * 60 + "\n")
                    f.write("*** IDENTIFIED ACCOUNT OWNER / DEVICE USER ***\n")
                    f.write(f"Username / Handle : @{owner.get('handle', 'N/A')}\n")
                    f.write(f"Display Name      : {owner.get('nickname', 'N/A')}\n")
                    f.write(f"User ID (UID)     : {owner.get('uid', 'N/A')}\n")
                    f.write(f"Followers Count   : {owner.get('follower_count', 'N/A')}\n")
                    f.write(f"Following Count   : {owner.get('following_count', 'N/A')}\n")
                    f.write(f"Bio / Signature   : {owner.get('bio', 'None')}\n")
                    if owner.get("avatar_urls"):
                        f.write(f"Profile CDN URL   : {owner['avatar_urls'][0]}\n")
                    f.write("*" * 60 + "\n\n")

                f.write("=== CONTACTS & CONNECTED PROFILES DIRECTORY ===\n\n")
                for c in tt_contacts:
                    h = f"@{c.get('handle')}" if c.get('handle') else "No Handle"
                    nick = c.get('nickname') or "Unknown"
                    fc = f" | Followers: {c['follower_count']:,}" if c.get('follower_count') is not None else ""
                    fing = f" | Following: {c['following_count']:,}" if c.get('following_count') is not None else ""
                    acc = f" | Interactions: {c['access_count']:,}" if c.get('access_count') else ""
                    f.write(f"• [{c.get('uid')}] {h} ({nick}){fc}{fing}{acc}\n")
                    if c.get('bio'):
                        f.write(f"  Bio: {c['bio']}\n")
                    if c.get('last_access_local') and c['last_access_local'] != "N/A":
                        f.write(f"  Last Profile Access: {c['last_access_local']}\n")
                    if c.get('last_updated_local') and c['last_updated_local'] != "N/A":
                        f.write(f"  Record Updated: {c['last_updated_local']}\n")
                    if c.get('avatar_urls'):
                        f.write(f"  Avatar CDN: {c['avatar_urls'][0]}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "tiktok_user_profiles_and_contacts.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["UID", "Is_Account_Owner", "Username_Handle", "Display_Name", "Followers_Count", "Following_Count", "Interaction_Count", "Last_Access_Time", "Record_Updated_Time", "Bio_Signature", "Avatar_CDN_URL"])
                for c in tt_contacts:
                    av = c['avatar_urls'][0] if c.get('avatar_urls') else ""
                    w.writerow([
                        c.get("uid"),
                        "YES (Owner)" if c.get("is_owner") else "No",
                        c.get("handle"),
                        c.get("nickname"),
                        c.get("follower_count"),
                        c.get("following_count"),
                        c.get("access_count", 0),
                        c.get("last_access_local", "N/A"),
                        c.get("last_updated_local", "N/A"),
                        c.get("bio", ""),
                        av
                    ])

        # 2. TikTok Activity & Feedback Logs
        if tt_feedback:
            with open(os.path.join(folder, "tiktok_activity_and_feedback.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== TikTok Activity & User Action Feedback Logs ({len(tt_feedback):,} Events) ===\n\n")
                for fb in tt_feedback:
                    f.write(f"[{fb.get('timestamp_local')}] Type: {fb.get('type')} | Label: {fb.get('label')} | Code: {fb.get('code')}\n")
                    f.write(f"Payload: {fb.get('message')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "tiktok_activity_and_feedback.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Type", "Label", "Result_Code", "Payload_Message"])
                for fb in tt_feedback:
                    w.writerow([fb.get("timestamp_local"), fb.get("timestamp_utc"), fb.get("type"), fb.get("label"), fb.get("code"), fb.get("message")])

        # 3. TikTok Frequent User Interactions
        if tt_freq:
            with open(os.path.join(folder, "tiktok_frequent_interactions.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Account_Owner_UID", "Target_User_UID", "Target_Handle", "Target_Display_Name"])
                for fr in tt_freq:
                    w.writerow([fr.get("account_uid"), fr.get("target_uid"), fr.get("target_handle"), fr.get("target_name")])

        # 4. Facebook Accounts & Linked Instagram Profiles
        if fb_accounts:
            with open(os.path.join(folder, "facebook_accounts_and_linked_profiles.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Active Facebook & Meta Account Profiles ({len(fb_accounts):,} Accounts) ===\n\n")
                for a in fb_accounts:
                    f.write(f"Facebook User ID (FBID) : {a.get('account_fbid')}\n")
                    f.write(f"Profile URL             : {a.get('profile_url')}\n")
                    f.write(f"Linked Instagram Handle : @{a.get('linked_instagram_user')}\n")
                    if a.get('linked_instagram_pic') and a['linked_instagram_pic'] != "N/A":
                        f.write(f"Linked Instagram Avatar : {a.get('linked_instagram_pic')}\n")
                    f.write(f"Last Notification Sync  : {a.get('last_sync')}\n")
                    f.write(f"Search Bootstrap Refresh: {a.get('last_search_refresh')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "facebook_accounts_and_linked_profiles.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Account_FBID", "Profile_URL", "Linked_Instagram_Handle", "Linked_Instagram_Avatar_URL", "Last_Notification_Sync", "Search_Refresh_Time"])
                for a in fb_accounts:
                    w.writerow([a.get("account_fbid"), a.get("profile_url"), a.get("linked_instagram_user"), a.get("linked_instagram_pic"), a.get("last_sync"), a.get("last_search_refresh")])

        # 5. Facebook Messenger Notification Threads
        if msgr_threads:
            with open(os.path.join(folder, "facebook_messenger_notification_threads.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Facebook Messenger Push Notification Threads ({len(msgr_threads):,} Threads) ===\n\n")
                for t in msgr_threads:
                    f.write(f"[{t.get('timestamp_local')}] Account FBID: {t.get('account_fbid')} | Thread ID: {t.get('thread_id')}\n")
                    f.write(f"Enqueue Time: {t.get('enqueue_timestamp_local')} | Iris Sequence: {t.get('iris_seq_id')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "facebook_messenger_notification_threads.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Account_FBID", "Thread_ID", "Iris_Sequence_ID", "Enqueue_Timestamp_Local"])
                for t in msgr_threads:
                    w.writerow([t.get("timestamp_local"), t.get("timestamp_utc"), t.get("account_fbid"), t.get("thread_id"), t.get("iris_seq_id"), t.get("enqueue_timestamp_local")])

        # 6. Legacy/Lightspeed Messenger Messages (if any)
        if messenger:
            with open(os.path.join(folder, "facebook_messenger_chats.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Facebook Messenger ({len(messenger):,} Messages) ===\n\n")
                for m in messenger:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Chat: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")
            with open(os.path.join(folder, "facebook_messenger_messages.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Chat_Name", "Text"])
                for m in messenger:
                    w.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("sender"), m.get("chat_name"), m.get("text")])

        if tg:
            with open(os.path.join(folder, "telegram_chats.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Telegram Messenger ({len(tg):,} Messages) ===\n\n")
                for m in tg:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Chat: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")
            with open(os.path.join(folder, "telegram_messages.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Chat_Name", "Text"])
                for m in tg:
                    w.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("sender"), m.get("chat_name"), m.get("text")])

        if viber:
            with open(os.path.join(folder, "viber_chats.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Rakuten Viber ({len(viber):,} Messages) ===\n\n")
                for m in viber:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Chat: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")
            with open(os.path.join(folder, "viber_messages.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Chat_Name", "Text"])
                for m in viber:
                    w.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("sender"), m.get("chat_name"), m.get("text")])

        if viber_calls:
            with open(os.path.join(folder, "viber_call_logs.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Rakuten Viber VoIP Calls ({len(viber_calls):,} Calls) ===\n\n")
                for c in viber_calls:
                    f.write(f"[{c.get('timestamp_local')}] Contact: {c.get('contact_name')} ({c.get('number')}) | Duration: {c.get('duration_seconds')}s | Type: {c.get('call_type')}\n")

        if insta:
            with open(os.path.join(folder, "instagram_direct_chats.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Instagram Direct ({len(insta):,} Messages) ===\n\n")
                for m in insta:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Thread: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")

        if teams:
            with open(os.path.join(folder, "teams_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Microsoft Teams ({len(teams):,} Messages) ===\n\n")
                for m in teams:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Channel: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")

        if signal:
            with open(os.path.join(folder, "signal_profiles.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Signal User Profiles & Metadata ({len(signal):,} Records) ===\n\n")
                for s in signal:
                    f.write(f"Name: {s.get('name')} | Phone: {s.get('phone')} | ID: {s.get('id')}\n")

        if discord:
            with open(os.path.join(folder, "discord_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Discord ({len(discord):,} Messages) ===\n\n")
                for m in discord:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Channel: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")

        if skype:
            with open(os.path.join(folder, "skype_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Skype ({len(skype):,} Messages) ===\n\n")
                for m in skype:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')} | Convo: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")

        if line:
            with open(os.path.join(folder, "line_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Line ({len(line):,} Messages) ===\n\n")
                for m in line:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')}: {m.get('text')}\n")

        if wechat:
            with open(os.path.join(folder, "wechat_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== WeChat ({len(wechat):,} Messages) ===\n\n")
                for m in wechat:
                    f.write(f"[{m.get('timestamp_local')}] Sender: {m.get('sender')}: {m.get('text')}\n")

        if proton:
            with open(os.path.join(folder, "protonmail_records.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== ProtonMail Cached Mailbox Headers ({len(proton):,} Records) ===\n\n")
                for p in proton:
                    f.write(f"[{p.get('timestamp_local')}] From: {p.get('sender')} -> To: {p.get('recipient')}\n")
                    f.write(f"Subject: {p.get('subject')}\n")
                    f.write("-" * 60 + "\n")

        if generic:
            with open(os.path.join(folder, "generic_discovered_apps_chats.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Generic Discovered App Chats ({len(generic):,} Messages) ===\n\n")
                for m in generic:
                    f.write(f"[{m.get('timestamp_local')}] App: {m.get('app')} | Sender: {m.get('sender')} | Chat: {m.get('chat_name')}\n")
                    f.write(f"Text: {m.get('text')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "generic_discovered_apps_messages.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "App_Name", "Sender", "Chat_Name", "Message_Text"])
                for m in generic:
                    w.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("app"), m.get("sender"), m.get("chat_name"), m.get("text")])

        # 16. Snapchat Friends and Messages
        if snap_friends:
            with open(os.path.join(folder, "snapchat_friends.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Snapchat Discovered Friends & Contacts ({len(snap_friends):,} Friends) ===\n\n")
                for sf in snap_friends:
                    f.write(f"User ID      : {sf.get('user_id')}\n")
                    f.write(f"Username     : @{sf.get('username')}\n")
                    f.write(f"Display Name : {sf.get('display_name')}\n")
                    f.write(f"Score / Streak: {sf.get('score')} / {sf.get('streak')}\n")
                    f.write(f"Added Time   : {sf.get('added_timestamp_local')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "snapchat_friends.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["User_ID", "Username", "Display_Name", "Score", "Streak", "Added_Timestamp_Local", "Added_Timestamp_UTC"])
                for sf in snap_friends:
                    w.writerow([sf.get("user_id"), sf.get("username"), sf.get("display_name"), sf.get("score"), sf.get("streak"), sf.get("added_timestamp_local"), sf.get("added_timestamp_utc")])

        if snap:
            with open(os.path.join(folder, "snapchat_messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Snapchat Messages & Direct Snaps ({len(snap):,} Messages) ===\n\n")
                for sm in snap:
                    f.write(f"[{sm.get('timestamp_local')}] Sender: {sm.get('sender')} | Conversation: {sm.get('chat_name')}\n")
                    f.write(f"Text: {sm.get('text')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "snapchat_messages.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Conversation_ID", "Text"])
                for sm in snap:
                    w.writerow([sm.get("timestamp_local"), sm.get("timestamp_utc"), sm.get("sender"), sm.get("chat_name"), sm.get("text")])

        # 17. Social Media Media Attachments & Files Carving
        if attachments:
            media_out_dir = os.path.join(folder, "social_media_media_files")
            os.makedirs(media_out_dir, exist_ok=True)

            with open(os.path.join(folder, "social_media_attachments_inventory.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Social Media Attachments & Media Files Inventory ({len(attachments):,} Files) ===\n\n")
                for att in attachments:
                    f.write(f"[{att.get('app')}] Type: {att.get('media_type')} | File: {att.get('filename')} ({att.get('size_kb')} KB)\n")
                    f.write(f"  Domain: {att.get('domain')}\n")
                    f.write(f"  Relative Path: {att.get('relative_path')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "social_media_attachments_inventory.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Application", "Media_Type", "Filename", "Extension", "Size_KB", "Domain", "Relative_Path"])
                for att in attachments:
                    w.writerow([att.get("app"), att.get("media_type"), att.get("filename"), att.get("extension"), att.get("size_kb"), att.get("domain"), att.get("relative_path")])

            # Copy actual media files organized by application (up to 500 files for safety)
            for idx, att in enumerate(attachments[:500], 1):
                src_p = att.get("path")
                if src_p and os.path.exists(src_p):
                    app_folder = os.path.join(media_out_dir, att.get("app", "Other").replace(" ", "_").lower())
                    os.makedirs(app_folder, exist_ok=True)
                    dest_file = os.path.join(app_folder, f"{idx:03d}_{att.get('filename')}")
                    try:
                        if not os.path.exists(dest_file):
                            shutil.copy2(src_p, dest_file)
                    except Exception:
                        pass

        with open(os.path.join(folder, "third_party_apps_summary.json"), "w", encoding="utf-8") as f:
            json.dump(ent, f, indent=2, ensure_ascii=False, default=str)

    def _export_whatsapp(self):
        wa = self.extracted_data.get("whatsapp", [])
        if not wa:
            return

        folder = os.path.join(self.root_export_dir, "08_WhatsApp_Chats")
        os.makedirs(folder, exist_ok=True)

        variants = set(m.get("app_variant", "WhatsApp") for m in wa)
        has_dual = len(variants) > 1

        title_str = f"=== WhatsApp Multi-App Chats (Standard & Business: {len(wa):,} Messages) ===" if has_dual else f"=== WhatsApp Chat Log ({len(wa):,} Messages) ==="

        with open(os.path.join(folder, "whatsapp_chat_log.txt"), "w", encoding="utf-8") as f:
            f.write(f"{title_str}\n\n")
            for m in wa:
                ts = m.get("timestamp_local", "N/A")
                sender = m.get("sender", "Unknown")
                recip = m.get("recipient", "N/A")
                direction = m.get("direction", "Unknown")
                chat_name = m.get("chat_name", "Chat")
                var_tag = f" [{m.get('app_variant')}]" if has_dual else ""
                del_tag = " [DELETED MESSAGE]" if m.get("is_deleted") else ""
                text = m.get("text", "")
                f.write(f"[{ts}]{var_tag}{del_tag} [{direction}] [{chat_name}] {sender} -> {recip}:\n")
                f.write(f"{text}\n")
                f.write("-" * 60 + "\n")

        with open(os.path.join(folder, "whatsapp_messages.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if has_dual:
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "App_Variant", "Chat_Name", "Sender", "Recipient", "Direction", "Is_Deleted", "Text"])
                for m in wa:
                    writer.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("app_variant"), m.get("chat_name"), m.get("sender"), m.get("recipient"), m.get("direction"), m.get("is_deleted", False), m.get("text")])
            else:
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Chat_Name", "Sender", "Recipient", "Direction", "Is_Deleted", "Text"])
                for m in wa:
                    writer.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("chat_name"), m.get("sender"), m.get("recipient"), m.get("direction"), m.get("is_deleted", False), m.get("text")])

        with open(os.path.join(folder, "whatsapp_records.json"), "w", encoding="utf-8") as f:
            json.dump(wa, f, indent=2, ensure_ascii=False, default=str)

    def _export_photos_and_videos(self):
        photos = self.extracted_data.get("photos", [])
        if not photos:
            return

        folder = os.path.join(self.root_export_dir, "09_Photos_Videos_and_Geolocation")
        os.makedirs(folder, exist_ok=True)

        from parsers.photos_parser import PhotosParser
        pp = PhotosParser(None)
        pp.photos = photos
        summary = pp.get_summary()

        # 1. Plain Text Inventory & Catalog
        with open(os.path.join(folder, "photos_and_videos_inventory.txt"), "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("        CAMERA ROLL PHOTOS, VIDEOS & GEOLOCATION INTELLIGENCE\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total Carved Media Assets : {summary.get('total_media_items', len(photos)):,}\n")
            f.write(f"• Total Photos / Images   : {summary.get('total_photos', 0):,}\n")
            f.write(f"• Total Videos & Screencast: {summary.get('total_videos', 0):,}\n")
            f.write(f"• Geotagged Media (GPS)   : {summary.get('total_geotagged', 0):,} items\n")
            f.write(f"• In 'Recently Deleted'   : {summary.get('total_trashed', 0):,} items\n")
            f.write(f"• In 'Hidden' Album       : {summary.get('total_hidden', 0):,} items\n")
            f.write(f"• Favorited Items         : {summary.get('total_favorites', 0):,} items\n\n")

            f.write("-" * 80 + "\n")
            f.write("                       CHRONOLOGICAL MEDIA LOG\n")
            f.write("-" * 80 + "\n")
            for p in photos:
                ts = p.get("timestamp_created_local") or p.get("timestamp_local", "N/A")
                m_type = p.get("media_type", "Photo")
                fname = p.get("filename", "Unknown")
                res = p.get("resolution", "N/A")
                dur = f" | Dur: {p.get('duration_formatted')}" if p.get("duration_seconds", 0) > 0 else ""
                trash = " [RECENTLY DELETED / TRASHED]" if p.get("is_trashed") else ""
                hid = " [HIDDEN ALBUM]" if p.get("is_hidden") else ""
                gps = f" | GPS: {p.get('latitude')}, {p.get('longitude')} -> {p.get('google_maps_url')}" if p.get("has_gps") else ""
                f.write(f"[{ts}] [{m_type}] {fname} ({res}){dur}{trash}{hid}{gps}\n")

        # 2. Geolocation GPS Points Report
        geo_photos = [p for p in photos if p.get("has_gps")]
        if geo_photos:
            with open(os.path.join(folder, "geolocation_gps_points.txt"), "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"     GEOSPATIAL INTELLIGENCE & GPS COORDINATES ({len(geo_photos):,} Geotagged Media)\n")
                f.write("=" * 80 + "\n\n")
                for p in geo_photos:
                    ts = p.get("timestamp_created_local") or p.get("timestamp_local", "N/A")
                    fname = p.get("filename", "Unknown")
                    lat = p.get("latitude")
                    lon = p.get("longitude")
                    alt = f" | Alt: {p.get('altitude')}m" if p.get("altitude") is not None else ""
                    maps = p.get("google_maps_url", "")
                    f.write(f"[{ts}] File: {fname} | Coordinates: {lat}, {lon}{alt}\n")
                    f.write(f"Google Maps Link: {maps}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "geolocated_points.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Filename", "Timestamp_Local", "Timestamp_UTC", "Latitude", "Longitude", "Altitude", "Google_Maps_URL", "OpenStreetMap_URL"])
                for p in geo_photos:
                    writer.writerow([
                        p.get("filename"),
                        p.get("timestamp_created_local") or p.get("timestamp_local"),
                        p.get("timestamp_created_utc") or p.get("timestamp_utc"),
                        p.get("latitude"),
                        p.get("longitude"),
                        p.get("altitude"),
                        p.get("google_maps_url"),
                        p.get("osm_maps_url")
                    ])

        # 3. Complete Media CSV
        with open(os.path.join(folder, "photos_and_videos.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Asset_ID", "Filename", "Directory", "Relative_Path", "Media_Type", "Timestamp_Created_Local", "Timestamp_Created_UTC", "Timestamp_Modified_Local", "Resolution", "Duration_Formatted", "Duration_Seconds", "Latitude", "Longitude", "Altitude", "Google_Maps_URL", "Is_Favorite", "Is_Hidden", "Is_Trashed_Recently_Deleted"])
            for p in photos:
                writer.writerow([
                    p.get("asset_id", ""),
                    p.get("filename", ""),
                    p.get("directory", ""),
                    p.get("relative_path", ""),
                    p.get("media_type", "Photo"),
                    p.get("timestamp_created_local") or p.get("timestamp_local", "N/A"),
                    p.get("timestamp_created_utc") or p.get("timestamp_utc", "N/A"),
                    p.get("timestamp_modified_local", "N/A"),
                    p.get("resolution", "N/A"),
                    p.get("duration_formatted", "N/A"),
                    p.get("duration_seconds", 0),
                    p.get("latitude", ""),
                    p.get("longitude", ""),
                    p.get("altitude", ""),
                    p.get("google_maps_url", ""),
                    p.get("is_favorite", False),
                    p.get("is_hidden", False),
                    p.get("is_trashed", False)
                ])

        # 4. JSON Dump
        with open(os.path.join(folder, "photos_and_videos_records.json"), "w", encoding="utf-8") as f:
            json.dump(photos, f, indent=2, ensure_ascii=False, default=str)

        # 5. Carve / Copy Camera Roll Media Files (Photos, Videos, Screencasts)
        raw_photos_dir = os.path.join(folder, "carved_camera_roll_media")
        resolver = self.manifest_resolver or self.resolver
        if resolver:
            os.makedirs(raw_photos_dir, exist_ok=True)
            for idx, p in enumerate(photos[:500], 1):
                fname = p.get("filename")
                if not fname:
                    continue
                real_p = resolver.find_file(filename=fname) or resolver.find_file(domain="CameraRollDomain", relative_path=f"Media/{p.get('relative_path')}")
                if real_p and os.path.exists(real_p):
                    clean_dst = os.path.join(raw_photos_dir, f"{idx:04d}_{fname}")
                    try:
                        if not os.path.exists(clean_dst):
                            shutil.copy2(real_p, clean_dst)
                    except Exception:
                        pass

    def _export_web_and_activity(self):
        safari = self.extracted_data.get("safari", [])
        usage = self.extracted_data.get("app_usage", [])

        if not safari and not usage:
            return

        folder = os.path.join(self.root_export_dir, "10_Web_History_and_Activity")
        os.makedirs(folder, exist_ok=True)

        if safari:
            with open(os.path.join(folder, "safari_browsing_history.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== Safari Browsing History ({len(safari):,} Visited URLs) ===\n\n")
                for s in safari:
                    f.write(f"[{s.get('timestamp_local')}] Title: {s.get('title')}\n")
                    f.write(f"URL: {s.get('url')}\n")
                    f.write("-" * 60 + "\n")

            with open(os.path.join(folder, "safari_browsing_history.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Page_Title", "Visited_URL", "Visit_Count"])
                for s in safari:
                    writer.writerow([s.get("timestamp_local"), s.get("title"), s.get("url"), s.get("visit_count")])

        if usage:
            with open(os.path.join(folder, "app_network_data_usage.json"), "w", encoding="utf-8") as f:
                json.dump(usage, f, indent=2, ensure_ascii=False, default=str)

    def _export_timeline(self):
        timeline = self.extracted_data.get("timeline", [])
        if not timeline:
            return

        folder = os.path.join(self.root_export_dir, "11_Master_Forensic_Timeline")
        os.makedirs(folder, exist_ok=True)

        # 1. Plain Text Super-Timeline
        with open(os.path.join(folder, "master_chronological_timeline.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== Master Forensic Chronological Timeline ({len(timeline):,} Total Events) ===\n\n")
            for ev in timeline:
                ts = ev.get("timestamp_local", "N/A")
                ev_type = ev.get("type", "EVENT").upper()
                actor = ev.get("actor", "System")
                summary = ev.get("summary", "")
                f.write(f"[{ts}] [{ev_type:<10}] {actor} : {summary}\n")

        # 2. Master Timeline CSV
        with open(os.path.join(folder, "master_chronological_timeline.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp_Local", "Event_Type", "Actor", "Summary", "Source_Artifact"])
            for ev in timeline:
                writer.writerow([
                    ev.get("timestamp_local"),
                    ev.get("type"),
                    ev.get("actor"),
                    ev.get("summary"),
                    ev.get("source")
                ])

        with open(os.path.join(folder, "master_chronological_timeline.json"), "w", encoding="utf-8") as f:
            json.dump(timeline, f, indent=2, ensure_ascii=False, default=str)

    def _export_deleted_carved_records(self):
        carved = self.extracted_data.get("deleted_carved_records", [])
        if not carved:
            return

        folder = os.path.join(self.root_export_dir, "13_Carved_Deleted_Fragments")
        os.makedirs(folder, exist_ok=True)

        # 1. Plain Text Summary and Record Catalog
        with open(os.path.join(folder, "deleted_carved_fragments.txt"), "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("        SQLITE FREELIST, UNALLOCATED SPACE & WAL BUFFER DELETED DATA\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total Carved Fragments Extracted : {len(carved):,}\n\n")

            # Grouping by category
            categories = {}
            for c in carved:
                cat = c.get("category", "Deleted Chat / Note Text")
                categories[cat] = categories.get(cat, 0) + 1

            f.write("Fragment Breakdown by Classification:\n")
            for cat, cnt in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  • {cat:<32} : {cnt:,} records\n")
            f.write("\n" + "-" * 80 + "\n")
            f.write("                   DETAILED CARVED EVIDENCE LOG\n")
            f.write("-" * 80 + "\n\n")

            for idx, c in enumerate(carved, 1):
                db_name = c.get("database_name", "SQLite Database")
                src_type = c.get("source_type", "Freelist / Unallocated")
                page_no = c.get("page_number", "N/A")
                offset = c.get("byte_offset", 0)
                category = c.get("category", "Deleted Record")
                text = c.get("carved_text", "").strip()

                offset_str = f"0x{offset:06X}" if isinstance(offset, int) else str(offset)
                f.write(f"[{idx:04d}] [{db_name}] [{src_type} | Page: {page_no} | Byte Offset: {offset_str}] [{category}]\n")
                f.write(f"Extracted String: {text}\n")
                f.write("-" * 60 + "\n")

        # 2. Spreadsheet CSV
        with open(os.path.join(folder, "deleted_carved_records.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Index", "Database_Name", "Source_Type", "Page_Number", "Byte_Offset_Hex", "Byte_Offset_Dec", "Category", "Carved_Text"])
            for idx, c in enumerate(carved, 1):
                offset = c.get("byte_offset", 0)
                writer.writerow([
                    idx,
                    c.get("database_name", "Unknown"),
                    c.get("source_type", "Unallocated"),
                    c.get("page_number", ""),
                    f"0x{offset:06X}" if isinstance(offset, int) else str(offset),
                    offset,
                    c.get("category", "Deleted Record"),
                    c.get("carved_text", "")
                ])

        # 3. JSON Structured Dump
        with open(os.path.join(folder, "deleted_carved_records.json"), "w", encoding="utf-8") as f:
            json.dump(carved, f, indent=2, ensure_ascii=False, default=str)

    def _export_decrypted_databases(self):
        """
        Copies any decrypted SQLite database files from staging into a dedicated folder
        so investigators have raw, unencrypted .db files ready for SQL inspection.
        """
        if not self.resolver:
            return

        staging_dir = os.path.join(self.resolver.backup_dir, "decrypted_staging")
        if not os.path.exists(staging_dir):
            return

        db_folder = os.path.join(self.root_export_dir, "12_Raw_Decrypted_SQLite_Databases")
        os.makedirs(db_folder, exist_ok=True)

        try:
            for f in os.listdir(staging_dir):
                full_src = os.path.join(staging_dir, f)
                if os.path.isfile(full_src):
                    dest_p = os.path.join(db_folder, f)
                    if not os.path.exists(dest_p):
                        shutil.copy2(full_src, dest_p)
        except Exception:
            pass
