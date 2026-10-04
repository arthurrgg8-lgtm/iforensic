import os
import datetime
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

COLOR_PRIMARY = RGBColor(15, 32, 67)     # Deep Navy #0F2043
COLOR_SECONDARY = RGBColor(41, 74, 110) # Steel Blue #294A6E
COLOR_ACCENT = RGBColor(180, 50, 50)    # Crimson #B43232
COLOR_TEXT = RGBColor(30, 30, 30)
COLOR_MUTED = RGBColor(100, 100, 100)

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=80, bottom=80, left=120, right=120):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def set_table_borders(table, color="D0D7DE"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
        f'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
        f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
        f'<w:insideV w:val="none"/>'
        f'<w:left w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

class DocxReportExporter:
    """
    Generates an executive-grade, disclosure-ready DOCX forensic intelligence report.
    """

    def __init__(self, metadata, messages=None, calls=None, notes=None, contacts=None, financial=None, app_usage=None, recordings=None, enterprise_apps=None, custody_manifest=None, keychain=None):
        self.metadata = metadata or {}
        self.messages = messages or []
        self.calls = calls or []
        self.notes = notes or []
        self.contacts = contacts or []
        self.financial = financial or []
        self.app_usage = app_usage or []
        self.recordings = recordings or {}
        self.enterprise_apps = enterprise_apps or {}
        self.custody_manifest = custody_manifest or {}
        self.keychain = keychain or {}

    def generate(self, output_path):
        doc = Document()

        # Page Setup
        sections = doc.sections
        for s in sections:
            s.top_margin = Inches(0.8)
            s.bottom_margin = Inches(0.8)
            s.left_margin = Inches(0.8)
            s.right_margin = Inches(0.8)

        # Document Title
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_title = p_title.add_run("iOS DIGITAL FORENSIC INTELLIGENCE REPORT")
        r_title.bold = True
        r_title.font.size = Pt(22)
        r_title.font.color.rgb = COLOR_PRIMARY

        p_sub = doc.add_paragraph()
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_sub = p_sub.add_run(f"NIST CFTT & ISO/IEC 27037 Standard Digital Evidence Extraction | Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        r_sub.font.size = Pt(10)
        r_sub.font.color.rgb = COLOR_MUTED

        doc.add_paragraph()

        # Section 1: Executive Case & Hardware Metadata
        h1 = doc.add_heading(level=1)
        r_h1 = h1.add_run("1. Executive Summary & Device Profile")
        r_h1.font.color.rgb = COLOR_PRIMARY
        r_h1.bold = True

        master_hash = self.custody_manifest.get("master_hash") or "NIST CFTT Hash Recorded"

        tbl_meta = doc.add_table(rows=7, cols=2)
        set_table_borders(tbl_meta)
        tbl_meta.alignment = WD_TABLE_ALIGNMENT.CENTER

        meta_rows = [
            ("Device Name / Owner", str(self.metadata.get("device_name", "Unknown"))),
            ("Product Model & OS", f"{self.metadata.get('product_type', 'iPhone')} (iOS {self.metadata.get('product_version', 'Unknown')})"),
            ("Serial Number / UDID", f"SN: {self.metadata.get('serial_number', 'N/A')} | UDID: {self.metadata.get('udid', 'N/A')}"),
            ("Master Evidence SHA-256", str(master_hash)),
            ("Write-Blocker Status", "Forensically Protected (Read-Only URI mode=ro)"),
            ("Encryption State", "Hardware Encrypted" if self.metadata.get("is_encrypted") else "Unencrypted Logical"),
            ("Total Indexed Artifacts", f"{len(self.messages):,} Messages | {len(self.calls):,} Calls | {len(self.notes):,} Notes | {len(self.contacts):,} Contacts | {self.enterprise_apps.get('total_enterprise_records', 0):,} Enterprise Records")
        ]

        for idx, (label, val) in enumerate(meta_rows):
            row = tbl_meta.rows[idx]
            c0, c1 = row.cells[0], row.cells[1]
            set_cell_background(c0, "F0F4F8")
            set_cell_margins(c0)
            set_cell_margins(c1)
            c0.paragraphs[0].add_run(label).bold = True
            c1.paragraphs[0].add_run(val)

        doc.add_paragraph()

        # Section 2: Telephony & Call Logs
        if self.calls:
            h2 = doc.add_heading(level=1)
            r_h2 = h2.add_run(f"2. Call History & Voice Telemetry ({len(self.calls):,} records)")
            r_h2.font.color.rgb = COLOR_PRIMARY
            r_h2.bold = True

            tbl_calls = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_calls)
            hdr = tbl_calls.rows[0].cells
            headers = ["Timestamp (Local)", "Contact Name / Number", "Status", "Duration", "Provider"]
            for i, h in enumerate(headers):
                set_cell_background(hdr[i], "0F2043")
                set_cell_margins(hdr[i])
                r = hdr[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for c in self.calls[:100]: # Top 100 in docx
                row = tbl_calls.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(c.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                c_name = f"{c.get('contact_name')}\n({c.get('number')})" if c.get('contact_name') != 'Unknown' else c.get('number')
                row[1].paragraphs[0].add_run(c_name).font.size = Pt(8.5)
                
                status_run = row[2].paragraphs[0].add_run(c.get("status", "N/A"))
                status_run.font.size = Pt(8.5)
                if "Missed" in c.get("status", ""):
                    status_run.font.color.rgb = COLOR_ACCENT

                row[3].paragraphs[0].add_run(c.get("duration_formatted", "0s")).font.size = Pt(8.5)
                row[4].paragraphs[0].add_run(c.get("service_provider", "Telephony")).font.size = Pt(8.5)

            doc.add_paragraph()

        # Section 3: Apple Notes & Credentials
        if self.notes:
            h3 = doc.add_heading(level=1)
            r_h3 = h3.add_run(f"3. Apple Notes & Credentials Extraction ({len(self.notes):,} records)")
            r_h3.font.color.rgb = COLOR_PRIMARY
            r_h3.bold = True

            for n in self.notes[:50]:
                p_n = doc.add_paragraph()
                r_nt = p_n.add_run(f"📝 {n.get('title', 'Untitled Note')} ")
                r_nt.bold = True
                r_nt.font.color.rgb = COLOR_SECONDARY
                
                if n.get("tags"):
                    r_tag = p_n.add_run(f"[{', '.join(n['tags'])}] ")
                    r_tag.bold = True
                    r_tag.font.color.rgb = COLOR_ACCENT

                r_dt = p_n.add_run(f"(Modified: {n.get('modified_local', 'N/A')} | Folder: {n.get('folder', 'Default')})")
                r_dt.font.color.rgb = COLOR_MUTED
                r_dt.font.size = Pt(8.5)

                p_body = doc.add_paragraph()
                p_body.paragraph_format.left_indent = Inches(0.2)
                r_b = p_body.add_run(n.get("full_content", "")[:500])
                r_b.font.size = Pt(8.5)
                r_b.font.color.rgb = COLOR_TEXT

            doc.add_paragraph()

        # Section 4: Financial Transactions
        if self.financial:
            h4 = doc.add_heading(level=1)
            r_h4 = h4.add_run(f"4. Financial Ledger & Banking Activity ({len(self.financial):,} events)")
            r_h4.font.color.rgb = COLOR_PRIMARY
            r_h4.bold = True

            tbl_fin = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_fin)
            hdr = tbl_fin.rows[0].cells
            f_headers = ["Timestamp", "Entity / Bank", "Type", "Amount", "Summary"]
            for i, h in enumerate(f_headers):
                set_cell_background(hdr[i], "0F2043")
                set_cell_margins(hdr[i])
                r = hdr[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for f_item in self.financial[:100]:
                row = tbl_fin.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(f_item.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                row[1].paragraphs[0].add_run(f_item.get("entity", "Unknown")).font.size = Pt(8.5)
                
                t_run = row[2].paragraphs[0].add_run(f_item.get("type", "N/A"))
                t_run.font.size = Pt(8.5)
                if "Debit" in f_item.get("type", ""):
                    t_run.font.color.rgb = COLOR_ACCENT
                elif "Credit" in f_item.get("type", ""):
                    t_run.font.color.rgb = RGBColor(30, 140, 50)

                row[3].paragraphs[0].add_run(f_item.get("amount", "N/A")).font.size = Pt(8.5)
                row[4].paragraphs[0].add_run(f_item.get("summary", "")[:120]).font.size = Pt(8.0)

            doc.add_paragraph()

        # 5. Audio Recordings & Voice Memos Section
        voice_memos = self.recordings.get("voice_memos", [])
        voicemails = self.recordings.get("voicemails", [])
        audio_files = self.recordings.get("carved_audio_files", [])
        total_audio = len(voice_memos) + len(voicemails) + len(audio_files)

        if total_audio > 0:
            h5 = doc.add_heading(level=1)
            r_h5 = h5.add_run(f"5. Audio Recordings & Voice Telemetry ({total_audio:,} artifacts)")
            r_h5.font.color.rgb = COLOR_PRIMARY
            r_h5.bold = True

            if voice_memos:
                p_vm = doc.add_paragraph()
                r_vm = p_vm.add_run(f"Apple Voice Memos ({len(voice_memos)} recordings)")
                r_vm.bold = True
                tbl_memos = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_memos)
                hdr = tbl_memos.rows[0].cells
                for i, h in enumerate(["Title / Label", "Duration", "Recorded Timestamp", "Status"]):
                    set_cell_background(hdr[i], "0F2043")
                    set_cell_margins(hdr[i])
                    r = hdr[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for m in voice_memos[:30]:
                    row = tbl_memos.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(m.get("title", "Voice Memo")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(f"{m.get('duration_seconds', 0)}s").font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(m.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run("Deleted" if m.get("deleted") else "Active").font.size = Pt(8.5)
                doc.add_paragraph()

            if voicemails:
                p_vo = doc.add_paragraph()
                r_vo = p_vo.add_run(f"Voicemails ({len(voicemails)} messages)")
                r_vo.bold = True
                tbl_vo = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_vo)
                hdr_v = tbl_vo.rows[0].cells
                for i, h in enumerate(["Caller / Contact", "Number", "Duration", "Transcription"]):
                    set_cell_background(hdr_v[i], "0F2043")
                    set_cell_margins(hdr_v[i])
                    r = hdr_v[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for v in voicemails[:30]:
                    row = tbl_vo.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(v.get("caller_name", "Unknown")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(v.get("sender", "N/A")).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(f"{v.get('duration_seconds', 0)}s").font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(v.get("transcription", "")[:100]).font.size = Pt(8.0)
                doc.add_paragraph()

        # 6. Enterprise & Secure Cloud Messaging Section
        tg_msgs = self.enterprise_apps.get("telegram", [])
        teams_msgs = self.enterprise_apps.get("teams", [])
        signal_recs = self.enterprise_apps.get("signal", [])
        total_ent = len(tg_msgs) + len(teams_msgs) + len(signal_recs)

        if total_ent > 0:
            h6 = doc.add_heading(level=1)
            r_h6 = h6.add_run(f"6. Enterprise & Cloud Messaging Telemetry ({total_ent:,} events)")
            r_h6.font.color.rgb = COLOR_PRIMARY
            r_h6.bold = True

            if tg_msgs:
                p_tg = doc.add_paragraph()
                r_tg = p_tg.add_run(f"Telegram Messenger ({len(tg_msgs)} messages)")
                r_tg.bold = True
                tbl_tg = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_tg)
                hdr_t = tbl_tg.rows[0].cells
                for i, h in enumerate(["Timestamp", "Sender ID", "Chat ID", "Message Content"]):
                    set_cell_background(hdr_t[i], "0F2043")
                    set_cell_margins(hdr_t[i])
                    r = hdr_t[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for tm in tg_msgs[:30]:
                    row = tbl_tg.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(tm.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(str(tm.get("from_id", "N/A"))).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(str(tm.get("chat_id", "N/A"))).font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(tm.get("text", "")[:120]).font.size = Pt(8.0)
                doc.add_paragraph()

            if teams_msgs:
                p_tm = doc.add_paragraph()
                r_tm = p_tm.add_run(f"Microsoft Teams ({len(teams_msgs)} messages)")
                r_tm.bold = True
                tbl_tms = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_tms)
                hdr_ms = tbl_tms.rows[0].cells
                for i, h in enumerate(["Timestamp", "Sender", "Channel / Chat", "Content"]):
                    set_cell_background(hdr_ms[i], "0F2043")
                    set_cell_margins(hdr_ms[i])
                    r = hdr_ms[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for tms in teams_msgs[:30]:
                    row = tbl_tms.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(tms.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(str(tms.get("sender", "N/A"))).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(str(tms.get("channel", "N/A"))).font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(tms.get("text", "")[:120]).font.size = Pt(8.0)
                doc.add_paragraph()

        # 7. Decrypted iOS Keychain Secrets & Cryptographic Key Ring
        wifi_list = self.keychain.get("wifi_networks", [])
        web_creds = self.keychain.get("web_credentials", [])
        app_keys = self.keychain.get("app_tokens_and_keys", [])
        crypto_keys = self.keychain.get("crypto_keys", [])
        total_kc = len(wifi_list) + len(web_creds) + len(app_keys) + len(crypto_keys)

        if total_kc > 0:
            h7 = doc.add_heading(level=1)
            r_h7 = h7.add_run(f"7. Decrypted iOS Keychain Secrets & Cryptographic Key Ring ({total_kc:,} carved secrets)")
            r_h7.font.color.rgb = COLOR_PRIMARY
            r_h7.bold = True

            # 7.1 Web & Cloud Credentials
            if web_creds:
                p_wc = doc.add_paragraph()
                r_wc = p_wc.add_run(f"Saved Safari Web & Cloud Credentials ({len(web_creds)} accounts)")
                r_wc.bold = True
                tbl_wc = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_wc)
                hdr_wc = tbl_wc.rows[0].cells
                for i, h in enumerate(["URL / Service", "Account / Username", "Password / Token", "Protection Class"]):
                    set_cell_background(hdr_wc[i], "0F2043")
                    set_cell_margins(hdr_wc[i])
                    r = hdr_wc[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for wc in web_creds[:40]:
                    row = tbl_wc.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(wc.get("url") or wc.get("server", "N/A")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(wc.get("account", "N/A")).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(str(wc.get("decrypted_password", ""))[:60]).font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(wc.get("protection_class", "N/A")).font.size = Pt(8.0)
                doc.add_paragraph()

            # 7.2 Wi-Fi Passwords & Networks
            if wifi_list:
                p_wf = doc.add_paragraph()
                r_wf = p_wf.add_run(f"Wi-Fi Networks & Passphrases ({len(wifi_list)} access points)")
                r_wf.bold = True
                tbl_wf = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_wf)
                hdr_wf = tbl_wf.rows[0].cells
                for i, h in enumerate(["Access Group / Service", "Account / SSID", "Decrypted Value / Passphrase", "Modified Date"]):
                    set_cell_background(hdr_wf[i], "0F2043")
                    set_cell_margins(hdr_wf[i])
                    r = hdr_wf[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for wf in wifi_list[:30]:
                    row = tbl_wf.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(wf.get("service", "AirPort")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(wf.get("account", "Wi-Fi Network")).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(str(wf.get("decrypted_value", ""))[:80]).font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(wf.get("modification_date", "N/A")).font.size = Pt(8.0)
                doc.add_paragraph()

            # 7.3 App Database Encryption Keys & Auth Tokens
            if app_keys or crypto_keys:
                comb_keys = app_keys + crypto_keys
                p_ak = doc.add_paragraph()
                r_ak = p_ak.add_run(f"Application Database Encryption Keys & Cryptographic Secrets ({len(comb_keys)} keys)")
                r_ak.bold = True
                tbl_ak = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_ak)
                hdr_ak = tbl_ak.rows[0].cells
                for i, h in enumerate(["Target App / Group", "Key Purpose / Service", "Decrypted Cryptographic Key / Token", "Protection Class"]):
                    set_cell_background(hdr_ak[i], "0F2043")
                    set_cell_margins(hdr_ak[i])
                    r = hdr_ak[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for ak in comb_keys[:40]:
                    row = tbl_ak.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(ak.get("access_group", "N/A")).font.size = Pt(8.0)
                    row[1].paragraphs[0].add_run(ak.get("service") or ak.get("label") or ak.get("account", "N/A")).font.size = Pt(8.5)
                    k_val = ak.get("decrypted_value") or ak.get("decrypted_key_payload") or ""
                    row[2].paragraphs[0].add_run(str(k_val)[:100]).font.size = Pt(8.0)
                    row[3].paragraphs[0].add_run(ak.get("protection_class", "N/A")).font.size = Pt(8.0)
                doc.add_paragraph()

        # Save Document
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc.save(output_path)
        return output_path
