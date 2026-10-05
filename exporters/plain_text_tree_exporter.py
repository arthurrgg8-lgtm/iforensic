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
        self._export_keychain_and_keys()
        self._export_financial_ledger()
        self._export_enterprise_apps()
        self._export_whatsapp()
        self._export_photos_and_videos()
        self._export_web_and_activity()
        self._export_timeline()
        self._export_decrypted_databases()
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
            f.write(f"• WhatsApp Chats                  : {len(self.extracted_data.get('whatsapp', [])):,} messages\n")
            ent_total = self.extracted_data.get("enterprise_apps", {}).get("total_enterprise_records", 0)
            f.write(f"• Enterprise Apps (TG/Teams/etc)  : {ent_total:,} records\n")
            kc_total = len(self.extracted_data.get("keychain", {}).get("all_decrypted_records", []))
            f.write(f"• Decrypted Keychain & Keys       : {kc_total:,} carved credentials\n")
    def _export_messages(self):
        msgs = self.extracted_data.get("messages", [])
        if not msgs:
            return

        folder = os.path.join(self.root_export_dir, "01_Messages_SMS_iMessage")
        os.makedirs(folder, exist_ok=True)

        # 1. Plain Text Transcript
        with open(os.path.join(folder, "messages_chat_transcript.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== SMS & iMessage Transcript ({len(msgs):,} Messages) ===\n\n")
            for m in msgs:
                ts = m.get("timestamp_local", "N/A")
                sender = m.get("sender", "Unknown")
                recip = m.get("recipient", "N/A")
                direction = m.get("direction", "Unknown")
                svc = m.get("service", "SMS")
                text = m.get("text", "").strip()
                f.write(f"[{ts}] [{direction}] [{svc}] Sender: {sender} -> Recipient: {recip}\n")
                f.write(f"Body: {text}\n")
                f.write("-" * 60 + "\n")

        # 2. Tabular CSV
        with open(os.path.join(folder, "messages_database.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Recipient", "Direction", "Service", "Message_Text"])
            for m in msgs:
                writer.writerow([
                    m.get("timestamp_local"),
                    m.get("timestamp_utc"),
                    m.get("sender"),
                    m.get("recipient"),
                    m.get("direction"),
                    m.get("service"),
                    m.get("text")
                ])

        # 3. JSON Dump
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

        with open(os.path.join(folder, "notes_records.json"), "w", encoding="utf-8") as f:
            json.dump(notes, f, indent=2, ensure_ascii=False, default=str)

    def _export_keychain_and_keys(self):
        kc = self.extracted_data.get("keychain", {})
        all_recs = kc.get("all_decrypted_records", [])
        if not all_recs:
            all_recs = (kc.get("web_credentials", []) + kc.get("wifi_networks", []) +
                        kc.get("app_tokens_and_keys", []) + kc.get("crypto_keys", []))

        if not all_recs:
            return

        folder = os.path.join(self.root_export_dir, "05_Decrypted_Keychain_and_Keys")
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

        # 5. Full JSON Dump
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
        messenger = ent.get("messenger", [])
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

        if not any([messenger, tg, viber, viber_calls, signal, insta, teams, discord, skype, line, wechat, proton, generic]):
            return

        folder = os.path.join(self.root_export_dir, "07_Third_Party_and_Social_Apps")
        os.makedirs(folder, exist_ok=True)

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

        with open(os.path.join(folder, "third_party_apps_summary.json"), "w", encoding="utf-8") as f:
            json.dump(ent, f, indent=2, ensure_ascii=False, default=str)

    def _export_whatsapp(self):
        wa = self.extracted_data.get("whatsapp", [])
        if not wa:
            return

        folder = os.path.join(self.root_export_dir, "08_WhatsApp_Chats")
        os.makedirs(folder, exist_ok=True)

        with open(os.path.join(folder, "whatsapp_chat_log.txt"), "w", encoding="utf-8") as f:
            f.write(f"=== WhatsApp Chat Log ({len(wa):,} Messages) ===\n\n")
            for m in wa:
                ts = m.get("timestamp_local", "N/A")
                sender = m.get("sender", "Unknown")
                text = m.get("text", "")
                f.write(f"[{ts}] {sender}: {text}\n")
                f.write("-" * 60 + "\n")

        with open(os.path.join(folder, "whatsapp_messages.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Recipient", "Direction", "Text"])
            for m in wa:
                writer.writerow([m.get("timestamp_local"), m.get("timestamp_utc"), m.get("sender"), m.get("recipient"), m.get("direction"), m.get("text")])

        with open(os.path.join(folder, "whatsapp_records.json"), "w", encoding="utf-8") as f:
            json.dump(wa, f, indent=2, ensure_ascii=False, default=str)

    def _export_photos_and_videos(self):
        photos = self.extracted_data.get("photos", [])
        if not photos:
            return

        folder = os.path.join(self.root_export_dir, "08_Photos_Videos_and_Geolocation")
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

    def _export_web_and_activity(self):
        safari = self.extracted_data.get("safari", [])
        usage = self.extracted_data.get("app_usage", [])

        if not safari and not usage:
            return

        folder = os.path.join(self.root_export_dir, "09_Web_History_and_Activity")
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

        folder = os.path.join(self.root_export_dir, "10_Master_Forensic_Timeline")
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

        db_folder = os.path.join(self.root_export_dir, "11_Decrypted_SQLite_Databases")
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
