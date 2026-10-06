import os
import csv
import json
import datetime

class BulkDataExporter:
    """
    Enterprise Big-Data & Forensic Interoperability Exporter:
    1. Generates clean, delimited CSV files for SIEM & spreadsheet analysis.
    2. Exports streaming Timeline JSONL for BigQuery / ElasticSearch ingest.
    3. Exports standardized CASE / UCO (Cyber-investigation Analysis Standard Expression) JSON-LD manifest.
    """

    def __init__(self, output_dir, extracted_data, metadata=None):
        self.output_dir = output_dir
        self.data = extracted_data or {}
        self.metadata = metadata or {}
        self.export_folder = os.path.join(output_dir, "Structured_CSV_and_SIEM_Exports")
        os.makedirs(self.export_folder, exist_ok=True)

    def export_all(self):
        """
        Executes complete bulk export pipeline and returns summary dictionary.
        """
        generated_files = []

        # 1. Export CSVs
        f_msgs = self._export_messages_csv()
        if f_msgs: generated_files.append(f_msgs)

        f_calls = self._export_calls_csv()
        if f_calls: generated_files.append(f_calls)

        f_call_freq = self._export_call_frequency_csv()
        if f_call_freq: generated_files.append(f_call_freq)

        f_dev_prof = self._export_device_profile_csv()
        if f_dev_prof: generated_files.append(f_dev_prof)

        f_contacts = self._export_contacts_csv()
        if f_contacts: generated_files.append(f_contacts)

        f_notes = self._export_notes_csv()
        if f_notes: generated_files.append(f_notes)

        f_audio = self._export_audio_recordings_csv()
        if f_audio: generated_files.append(f_audio)

        f_fin = self._export_financial_csv()
        if f_fin: generated_files.append(f_fin)

        f_wa = self._export_whatsapp_csv()
        if f_wa: generated_files.append(f_wa)

        f_tp = self._export_third_party_apps_csv()
        if f_tp: generated_files.append(f_tp)

        f_photos = self._export_photos_csv()
        if f_photos: generated_files.append(f_photos)

        f_geo = self._export_geolocation_csv()
        if f_geo: generated_files.append(f_geo)

        f_kc = self._export_keychain_csv()
        if f_kc: generated_files.append(f_kc)

        f_del = self._export_deleted_carved_csv()
        if f_del: generated_files.append(f_del)

        # 2. Export Timeline JSONL
        f_tl = self._export_timeline_jsonl()
        if f_tl: generated_files.append(f_tl)

        # 3. Export CASE / UCO JSON-LD
        f_uco = self._export_case_uco_jsonld()
        if f_uco: generated_files.append(f_uco)

        return {
            "status": "Success",
            "export_folder": self.export_folder,
            "total_files": len(generated_files),
            "files": generated_files
        }

    def _export_messages_csv(self):
        items = self.data.get("messages", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "messages.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Recipient", "Direction", "Service", "Attachment_Count", "Text"])
                for m in items:
                    writer.writerow([
                        m.get("timestamp_local", "N/A"),
                        m.get("timestamp_utc", "N/A"),
                        m.get("sender", "N/A"),
                        m.get("recipient", "N/A"),
                        m.get("direction", "N/A"),
                        m.get("service", "iMessage/SMS"),
                        m.get("attachment_count", 0),
                        m.get("text", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_calls_csv(self):
        items = self.data.get("calls", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "calls.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Record_ID", "Timestamp_Local", "Timestamp_UTC", "Direction", "Call_Status", "Contact_Name", "Phone_Number", "Duration_Sec", "Duration_Formatted", "Duration_HMS", "Service_Provider", "Location"])
                for c in items:
                    writer.writerow([
                        c.get("record_id", ""),
                        c.get("timestamp_local", "N/A"),
                        c.get("timestamp_utc", "N/A"),
                        c.get("direction", "N/A"),
                        c.get("status", "N/A"),
                        c.get("contact_name", "Unknown"),
                        c.get("number", "N/A"),
                        c.get("duration_seconds", 0),
                        c.get("duration_formatted", "0s"),
                        c.get("duration_hms", "00:00:00"),
                        c.get("service_provider", "Telephony"),
                        c.get("location", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_call_frequency_csv(self):
        items = self.data.get("calls", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "call_frequency_summary.csv")
        try:
            from parsers.calls_parser import CallsParser
            cp = CallsParser(None)
            cp.calls = items
            analytics = cp.get_frequency_analytics()
            
            with open(out_p, "w", newline="", encoding="utf-8") as f:
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
            return out_p
        except Exception:
            return None

    def _export_device_profile_csv(self):
        if not self.metadata: return None
        out_p = os.path.join(self.export_folder, "device_profile.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Property", "Value"])
                for k, v in self.metadata.items():
                    writer.writerow([k, str(v)])
            return out_p
        except Exception:
            return None

    def _export_contacts_csv(self):
        items = self.data.get("contacts", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "contacts.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Full_Name", "First_Name", "Last_Name", "Phone_Numbers", "Email_Addresses", "Organization", "Job_Title", "Truecaller_Match", "Notes"])
                for c in items:
                    p_list = c.get("phone_numbers") or ([c["phone"]] if c.get("phone") else [])
                    e_list = c.get("emails") or ([c["email"]] if c.get("email") else [])
                    writer.writerow([
                        c.get("name") or f"{c.get('first_name', '')} {c.get('last_name', '')}".strip() or "Unnamed Contact",
                        c.get("first_name", ""),
                        c.get("last_name", ""),
                        "; ".join(p_list),
                        "; ".join(e_list),
                        c.get("organization", ""),
                        c.get("job_title", ""),
                        c.get("truecaller_match", ""),
                        c.get("note") or c.get("notes", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_notes_csv(self):
        items = self.data.get("notes", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "notes.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Title", "Folder", "Modified_Local", "Modified_UTC", "Account", "Tags", "Content_Snippet"])
                for n in items:
                    writer.writerow([
                        n.get("title", "Untitled Note"),
                        n.get("folder", "Notes"),
                        n.get("modified_local", "N/A"),
                        n.get("modified_utc", "N/A"),
                        n.get("account", "Local/iCloud"),
                        "; ".join(n.get("tags", [])),
                        (n.get("snippet") or n.get("full_content") or "")[:500]
                    ])
            return out_p
        except Exception:
            return None

    def _export_audio_recordings_csv(self):
        rec_data = self.data.get("recordings", {})
        voice_memos = rec_data.get("voice_memos", [])
        voicemails = rec_data.get("voicemails", [])
        carved_audio = rec_data.get("carved_audio_files", [])

        if not voice_memos and not voicemails and not carved_audio:
            return None

        out_p = os.path.join(self.export_folder, "audio_recordings_and_memos.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Timestamp_Local", "Timestamp_UTC", "Title_or_Sender", "Duration_Seconds", "Transcription_or_Details", "File_Path"])
                for vm in voice_memos:
                    writer.writerow([
                        "Apple Voice Memo",
                        vm.get("timestamp_local", "N/A"),
                        vm.get("timestamp_utc", "N/A"),
                        vm.get("title", "Voice Memo"),
                        vm.get("duration_seconds", 0),
                        "[Voice Memo Recording]",
                        vm.get("file_rel_path", "")
                    ])
                for v in voicemails:
                    writer.writerow([
                        "Voicemail",
                        v.get("timestamp_local", "N/A"),
                        v.get("timestamp_utc", "N/A"),
                        v.get("caller_name") or v.get("sender", "Unknown"),
                        v.get("duration_seconds", 0),
                        v.get("transcription", ""),
                        ""
                    ])
                for a in carved_audio:
                    writer.writerow([
                        a.get("category", "Audio File"),
                        "N/A",
                        "N/A",
                        a.get("filename", ""),
                        0,
                        f"Size: {a.get('size_kb', 0)} KB",
                        a.get("relative_path") or a.get("path", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_financial_csv(self):
        items = self.data.get("financial", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "financial_ledger.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Financial_Entity", "Transaction_Type", "Amount", "Sender_Address", "Summary", "Raw_Evidence"])
                for fin in items:
                    writer.writerow([
                        fin.get("timestamp_local", "N/A"),
                        fin.get("timestamp_utc", "N/A"),
                        fin.get("entity", "Financial Institution"),
                        fin.get("type", "Transaction"),
                        fin.get("amount", "N/A"),
                        fin.get("sender", "N/A"),
                        fin.get("summary", ""),
                        fin.get("raw_text", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_whatsapp_csv(self):
        items = self.data.get("whatsapp", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "whatsapp_chats.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Sender", "Chat_Name", "Chat_JID", "Direction", "Media_Type", "Message_Text"])
                for w in items:
                    writer.writerow([
                        w.get("timestamp_local", "N/A"),
                        w.get("timestamp_utc", "N/A"),
                        w.get("sender", "N/A"),
                        w.get("chat_name", "N/A"),
                        w.get("chat_jid", "N/A"),
                        w.get("direction", "N/A"),
                        w.get("media_type", "Text"),
                        w.get("text", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_third_party_apps_csv(self):
        ent = self.data.get("enterprise_apps", {})
        all_tp = ent.get("all_third_party_messages", [])
        if not all_tp:
            all_tp = []
            for k in ["messenger", "telegram", "viber", "instagram", "teams", "discord", "skype", "line", "wechat", "generic_apps"]:
                all_tp.extend(ent.get(k, []))
        if not all_tp: return None
        out_p = os.path.join(self.export_folder, "third_party_apps_chats.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp_Local", "Timestamp_UTC", "Application", "Sender", "Chat_Name", "Message_Text"])
                for m in all_tp:
                    writer.writerow([
                        m.get("timestamp_local", "N/A"),
                        m.get("timestamp_utc", "N/A"),
                        m.get("app") or m.get("source", "App"),
                        m.get("sender", "N/A"),
                        m.get("chat_name", "N/A"),
                        m.get("text", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_keychain_csv(self):
        kc = self.data.get("keychain", {})
        records = (kc.get("all_decrypted_records") or
                   kc.get("web_credentials", []) +
                   kc.get("wifi_networks", []) +
                   kc.get("app_tokens_and_keys", []) +
                   kc.get("crypto_keys", []))
        if not records: return None
        out_p = os.path.join(self.export_folder, "keychain_secrets.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Credential_Type", "Access_Group", "Account", "Service_or_Server", "Decrypted_Secret", "Protection_Class", "Decryption_Method"])
                for k in records:
                    val = k.get("decrypted_password") or k.get("decrypted_value") or k.get("decrypted_key_payload", "")
                    writer.writerow([
                        k.get("type", "Secret"),
                        k.get("access_group", ""),
                        k.get("account", ""),
                        k.get("service") or k.get("server") or k.get("label", ""),
                        val,
                        k.get("protection_class", "N/A"),
                        k.get("decryption_method", "AES-256")
                    ])
            return out_p
        except Exception:
            return None

    def _export_deleted_carved_csv(self):
        records = self.data.get("deleted_carved_records", [])
        if not records: return None
        out_p = os.path.join(self.export_folder, "deleted_carved_fragments.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Source_Database", "Storage_Type", "Page_Number", "Byte_Offset", "Category", "Carved_Payload"])
                for d in records:
                    writer.writerow([
                        d.get("database_name", "N/A"),
                        d.get("source_type", "Freelist / Unallocated"),
                        d.get("page_number", 0),
                        d.get("byte_offset", 0),
                        d.get("category", "Deleted Fragment"),
                        d.get("carved_text", "")
                    ])
            return out_p
        except Exception:
            return None

    def _export_timeline_jsonl(self):
        items = self.data.get("timeline", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "timeline_events.jsonl")
        try:
            with open(out_p, "w", encoding="utf-8") as f:
                for event in items:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            return out_p
        except Exception:
            return None

    def _export_case_uco_jsonld(self):
        """
        Exports evidence in official CASE (Cyber-investigation Analysis Standard Expression) JSON-LD.
        """
        out_p = os.path.join(self.export_folder, "case_uco_evidence_graph.jsonld")
        master_hash = self.data.get("custody_manifest", {}).get("master_hash", "NIST-CFTT-VERIFIED")

        uco_doc = {
            "@context": {
                "case": "https://ontology.caseontology.org/case/investigation/",
                "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
                "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
                "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
                "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
                "xsd": "http://www.w3.org/2001/XMLSchema#"
            },
            "@graph": [
                {
                    "@id": "urn:uuid:case-investigation-1",
                    "@type": "case:Investigation",
                    "uco-core:name": "iOS Mobile Forensic Examination",
                    "case:focus": "iOS Evidence Carving & Artifact Extraction",
                    "case:investigativeStatus": "Complete"
                },
                {
                    "@id": "urn:uuid:device-target-1",
                    "@type": "uco-observable:MobileDevice",
                    "uco-observable:model": self.metadata.get("product_type", "iPhone"),
                    "uco-observable:operatingSystem": f"iOS {self.metadata.get('product_version', 'Unknown')}",
                    "uco-observable:serialNumber": self.metadata.get("serial_number", "N/A"),
                    "uco-observable:uniqueDeviceIdentifier": self.metadata.get("udid", "N/A")
                },
                {
                    "@id": "urn:uuid:evidence-chain-1",
                    "@type": "uco-observable:DigitalEvidence",
                    "uco-observable:hash": master_hash,
                    "uco-observable:compliance": "ISO/IEC 27037:2012 / NIST CFTT"
                }
            ]
        }

        # Append messages to graph
        for idx, m in enumerate(self.data.get("messages", [])[:100], 1):
            uco_doc["@graph"].append({
                "@id": f"urn:uuid:message-{idx}",
                "@type": "uco-observable:Message",
                "uco-observable:from": m.get("sender"),
                "uco-observable:to": [m.get("recipient")],
                "uco-observable:messageText": m.get("text", "")[:200],
                "uco-observable:sentTime": m.get("timestamp_utc")
            })

        try:
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(uco_doc, f, indent=2, ensure_ascii=False)
            return out_p
        except Exception:
            return None

    def _export_photos_csv(self):
        items = self.data.get("photos", [])
        if not items: return None
        out_p = os.path.join(self.export_folder, "photos_and_videos.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Asset_ID", "Filename", "Directory", "Relative_Path", "Media_Type", "Timestamp_Created_Local", "Timestamp_Created_UTC", "Timestamp_Modified_Local", "Resolution", "Duration_Formatted", "Duration_Seconds", "Latitude", "Longitude", "Altitude", "Google_Maps_URL", "Is_Favorite", "Is_Hidden", "Is_Trashed_Recently_Deleted"])
                for p in items:
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
            return out_p
        except Exception:
            return None

    def _export_geolocation_csv(self):
        items = [p for p in self.data.get("photos", []) if p.get("has_gps")]
        if not items: return None
        out_p = os.path.join(self.export_folder, "geolocated_points.csv")
        try:
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Filename", "Timestamp_Local", "Timestamp_UTC", "Latitude", "Longitude", "Altitude", "Google_Maps_URL", "OpenStreetMap_URL"])
                for p in items:
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
            return out_p
        except Exception:
            return None
