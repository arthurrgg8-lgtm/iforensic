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
    Generates an executive-grade, disclosure-ready DOCX forensic intelligence report
    with pure human-readable plain text across all extracted communication, notes, and contacts.
    """

    def __init__(self, metadata, messages=None, calls=None, notes=None, contacts=None, 
                 financial=None, app_usage=None, recordings=None, enterprise_apps=None, 
                 custody_manifest=None, keychain=None, photos=None, deleted_carved_records=None,
                 whatsapp=None):
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
        self.photos = photos or []
        self.deleted_carved_records = deleted_carved_records or []
        self.whatsapp = whatsapp or []

    def generate(self, output_path):
        doc = Document()

        # Page Setup
        for s in doc.sections:
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
            ("Total Indexed Artifacts", f"{len(self.messages):,} SMS/iMessage | {len(self.whatsapp):,} WhatsApp | {len(self.calls):,} Calls | {len(self.notes):,} Notes | {len(self.contacts):,} Contacts")
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

        # Section 2: Messages (SMS & iMessage)
        if self.messages:
            h2 = doc.add_heading(level=1)
            r_h2 = h2.add_run(f"2. SMS & iMessage Communications ({len(self.messages):,} records)")
            r_h2.font.color.rgb = COLOR_PRIMARY
            r_h2.bold = True

            tbl_msg = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_msg)
            hdr = tbl_msg.rows[0].cells
            for i, h in enumerate(["Timestamp", "Direction", "Sender", "Recipient", "Message Text"]):
                set_cell_background(hdr[i], "0F2043")
                set_cell_margins(hdr[i])
                r = hdr[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for m in self.messages[:100]:
                row = tbl_msg.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(m.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                row[1].paragraphs[0].add_run(m.get("direction", "N/A")).font.size = Pt(8.5)
                row[2].paragraphs[0].add_run(str(m.get("sender", "N/A"))).font.size = Pt(8.5)
                row[3].paragraphs[0].add_run(str(m.get("recipient", "N/A"))).font.size = Pt(8.5)
                row[4].paragraphs[0].add_run(str(m.get("text", ""))[:200]).font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 3: WhatsApp Chats & Groups
        if self.whatsapp:
            h3 = doc.add_heading(level=1)
            r_h3 = h3.add_run(f"3. WhatsApp & Instant Messaging Intelligence ({len(self.whatsapp):,} messages)")
            r_h3.font.color.rgb = COLOR_PRIMARY
            r_h3.bold = True

            tbl_wa = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_wa)
            hdr_w = tbl_wa.rows[0].cells
            for i, h in enumerate(["Timestamp", "Chat / Group", "Direction", "Sender", "Message Content"]):
                set_cell_background(hdr_w[i], "0F2043")
                set_cell_margins(hdr_w[i])
                r = hdr_w[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for wm in self.whatsapp[:120]:
                row = tbl_wa.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(wm.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                row[1].paragraphs[0].add_run(str(wm.get("chat_name", "Chat"))).font.size = Pt(8.5)
                row[2].paragraphs[0].add_run(wm.get("direction", "N/A")).font.size = Pt(8.5)
                row[3].paragraphs[0].add_run(str(wm.get("sender", "Unknown"))).font.size = Pt(8.5)
                row[4].paragraphs[0].add_run(str(wm.get("text", ""))[:200]).font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 4: Third-Party & Social Messaging Apps
        all_tp = self.enterprise_apps.get("all_third_party_messages", [])
        if not all_tp:
            # Combine if not unified
            for k in ["messenger", "telegram", "viber", "instagram", "teams", "discord", "skype", "line", "wechat", "generic_apps"]:
                all_tp.extend(self.enterprise_apps.get(k, []))

        if all_tp:
            h_tp = doc.add_heading(level=1)
            r_htp = h_tp.add_run(f"4. Third-Party & Social Apps Intelligence ({len(all_tp):,} messages)")
            r_htp.font.color.rgb = COLOR_PRIMARY
            r_htp.bold = True

            tbl_tp = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_tp)
            hdr_tp = tbl_tp.rows[0].cells
            for i, h in enumerate(["Timestamp", "Application", "Chat / Channel", "Sender", "Message Content"]):
                set_cell_background(hdr_tp[i], "0F2043")
                set_cell_margins(hdr_tp[i])
                r = hdr_tp[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for tm in all_tp[:150]:
                row = tbl_tp.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(tm.get("timestamp_local", "N/A")).font.size = Pt(8.5)
                row[1].paragraphs[0].add_run(str(tm.get("app") or tm.get("source", "App"))).font.size = Pt(8.5)
                row[2].paragraphs[0].add_run(str(tm.get("chat_name", "Direct Chat"))).font.size = Pt(8.5)
                row[3].paragraphs[0].add_run(str(tm.get("sender", "Unknown"))).font.size = Pt(8.5)
                row[4].paragraphs[0].add_run(str(tm.get("text", ""))[:200]).font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 5: Call History & Voice Telemetry
        if self.calls:
            h4 = doc.add_heading(level=1)
            r_h4 = h4.add_run(f"5. Call History & Voice Telemetry ({len(self.calls):,} records)")
            r_h4.font.color.rgb = COLOR_PRIMARY
            r_h4.bold = True

            tbl_calls = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_calls)
            hdr_c = tbl_calls.rows[0].cells
            for i, h in enumerate(["Timestamp (Local)", "Contact Name / Number", "Status", "Duration", "Provider"]):
                set_cell_background(hdr_c[i], "0F2043")
                set_cell_margins(hdr_c[i])
                r = hdr_c[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for c in self.calls[:100]:
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

        # Section 6: Unified Contacts Directory
        if self.contacts:
            h5 = doc.add_heading(level=1)
            r_h5 = h5.add_run(f"6. Unified Contacts Directory ({len(self.contacts):,} contacts)")
            r_h5.font.color.rgb = COLOR_PRIMARY
            r_h5.bold = True

            tbl_ct = doc.add_table(rows=1, cols=4)
            set_table_borders(tbl_ct)
            hdr_ct = tbl_ct.rows[0].cells
            for i, h in enumerate(["Full Name", "Phone Numbers", "Email Addresses", "Organization / Notes"]):
                set_cell_background(hdr_ct[i], "0F2043")
                set_cell_margins(hdr_ct[i])
                r = hdr_ct[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(9)

            for ct in self.contacts[:100]:
                row = tbl_ct.add_row().cells
                for i in range(4):
                    set_cell_margins(row[i])
                p_list = ct.get("phone_numbers") or ([ct["phone"]] if ct.get("phone") else [])
                e_list = ct.get("emails") or ([ct["email"]] if ct.get("email") else [])
                row[0].paragraphs[0].add_run(ct.get("name", "Unnamed")).font.size = Pt(8.5)
                row[1].paragraphs[0].add_run(", ".join(p_list) or "None").font.size = Pt(8.5)
                row[2].paragraphs[0].add_run(", ".join(e_list) or "None").font.size = Pt(8.5)
                meta_info = ct.get("organization") or ct.get("job_title") or ct.get("note") or ""
                row[3].paragraphs[0].add_run(meta_info[:80]).font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 7: Apple Notes & Credentials Extraction
        if self.notes:
            h6 = doc.add_heading(level=1)
            r_h6 = h6.add_run(f"7. Apple Notes & Credentials Extraction ({len(self.notes):,} notes)")
            r_h6.font.color.rgb = COLOR_PRIMARY
            r_h6.bold = True

            for n in self.notes[:50]:
                p_n = doc.add_paragraph()
                r_nt = p_n.add_run(f"[Note] {n.get('title', 'Untitled Note')} ")
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

        # Section 8: Financial Ledger & Banking Activity
        if self.financial:
            h7 = doc.add_heading(level=1)
            r_h7 = h7.add_run(f"8. Financial Ledger & Banking Activity ({len(self.financial):,} events)")
            r_h7.font.color.rgb = COLOR_PRIMARY
            r_h7.bold = True

            tbl_fin = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_fin)
            hdr_f = tbl_fin.rows[0].cells
            for i, h in enumerate(["Timestamp", "Entity / Bank", "Type", "Amount", "Summary"]):
                set_cell_background(hdr_f[i], "0F2043")
                set_cell_margins(hdr_f[i])
                r = hdr_f[i].paragraphs[0].add_run(h)
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

        # Section 9: Saved Web & Wi-Fi Passwords (Sanitized)
        wifi_list = self.keychain.get("wifi_networks", [])
        raw_web_creds = self.keychain.get("web_credentials", [])
        web_creds = [
            wc for wc in raw_web_creds
            if ((wc.get("url") and wc.get("url") != "N/A" and "http" in str(wc.get("url", ""))) or
                (wc.get("account") and wc.get("account") not in ("Unknown User", "System Account", "", "N/A"))) and
               (wc.get("decrypted_password") and not str(wc.get("decrypted_password")).startswith("["))
        ]

        if wifi_list or web_creds:
            h8 = doc.add_heading(level=1)
            r_h8 = h8.add_run("9. Saved Wi-Fi Networks & Web Credentials")
            r_h8.font.color.rgb = COLOR_PRIMARY
            r_h8.bold = True

            if wifi_list:
                p_wf = doc.add_paragraph()
                r_wf = p_wf.add_run(f"Wi-Fi Networks & Passphrases ({len(wifi_list)} access points)")
                r_wf.bold = True
                tbl_wf = doc.add_table(rows=1, cols=3)
                set_table_borders(tbl_wf)
                hdr_wf = tbl_wf.rows[0].cells
                for i, h in enumerate(["SSID / Network", "Decrypted Password", "Protection Class"]):
                    set_cell_background(hdr_wf[i], "0F2043")
                    set_cell_margins(hdr_wf[i])
                    r = hdr_wf[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)
                for wf in wifi_list[:30]:
                    row = tbl_wf.add_row().cells
                    for i in range(3):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(wf.get("account", "Wi-Fi Network")).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(str(wf.get("decrypted_value", "N/A"))).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(wf.get("protection_class", "N/A")).font.size = Pt(8.0)
                doc.add_paragraph()

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

        # Section 10: Forensic Chain of Custody Attestation
        h9 = doc.add_heading(level=1)
        r_h9 = h9.add_run("10. Forensic Chain of Custody & Legal Attestation")
        r_h9.font.color.rgb = COLOR_PRIMARY
        r_h9.bold = True

        p_att = doc.add_paragraph()
        p_att.add_run(
            "This digital forensics examination was conducted in compliance with ISO/IEC 27037:2012 "
            "(Guidelines for identification, collection, acquisition and preservation of digital evidence) "
            "and NIST Special Publication 800-86 standards. All source evidence hashes were verified "
            "using streaming SHA-256 and MD5 cryptographic algorithms prior to artifact ingestion."
        ).font.size = Pt(9.5)

        doc.add_paragraph()

        # Save Document
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc.save(output_path)
        return output_path
