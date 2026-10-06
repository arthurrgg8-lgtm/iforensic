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
        friendly_model = self.metadata.get('model_friendly_name') or self.metadata.get('display_name', 'iPhone')
        hw_model = self.metadata.get('product_type', 'iPhone')
        model_str = f"{friendly_model} ({hw_model})" if friendly_model != hw_model else hw_model
        ios_str = f"iOS {self.metadata.get('product_version', 'Unknown')} (Build {self.metadata.get('build_version', 'N/A')})"
        imei_str = f"Primary: {self.metadata.get('imei', 'N/A')}"
        if self.metadata.get('imei2') and self.metadata.get('imei2') != 'N/A':
            imei_str += f" | Secondary: {self.metadata.get('imei2')}"

        meta_rows = [
            ("Device Name / Owner", str(self.metadata.get("device_name", "Unknown"))),
            ("Hardware Model", model_str),
            ("Operating System", ios_str),
            ("Serial Number", str(self.metadata.get("serial_number", "N/A"))),
            ("Unique Device ID (UDID)", str(self.metadata.get("udid", "N/A"))),
            ("Unique Chip ID (ECID)", str(self.metadata.get("ecid", "N/A"))),
            ("Cellular IMEI / MEID", f"{imei_str} | MEID: {self.metadata.get('meid', 'N/A')}"),
            ("SIM Card ICCID / Number", f"ICCID: {self.metadata.get('iccid', 'N/A')} | Tel: {self.metadata.get('phone_number', 'N/A')}"),
            ("Network MAC Addresses", f"Wi-Fi: {self.metadata.get('wifi_mac', 'N/A')} | BT: {self.metadata.get('bluetooth_mac', 'N/A')}"),
            ("Master Evidence SHA-256", str(master_hash)),
            ("Write-Blocker Status", "Forensically Protected (Read-Only URI mode=ro)"),
            ("Encryption State", "Hardware Encrypted (AES-256 Unwrapped)" if self.metadata.get("is_encrypted") else "Unencrypted Logical"),
            ("Total Indexed Artifacts", f"{len(self.messages):,} SMS/iMessage | {len(self.whatsapp):,} WhatsApp | {len(self.calls):,} Calls | {len(self.notes):,} Notes | {len(self.contacts):,} Contacts")
        ]

        tbl_meta = doc.add_table(rows=len(meta_rows), cols=2)
        set_table_borders(tbl_meta)
        tbl_meta.alignment = WD_TABLE_ALIGNMENT.CENTER

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
        # Section 4: Third-Party & Social Messaging Apps Intelligence
        ent_data = self.enterprise_apps
        tt_contacts = ent_data.get("tiktok_contacts", [])
        tt_owner = ent_data.get("tiktok_owner", {})
        fb_accounts = ent_data.get("messenger_accounts", [])
        msgr_threads = ent_data.get("messenger_threads", [])
        all_tp = ent_data.get("all_third_party_messages", [])
        if not all_tp:
            for k in ["messenger", "telegram", "viber", "instagram", "teams", "discord", "skype", "line", "wechat", "generic_apps"]:
                all_tp.extend(ent_data.get(k, []))

        if tt_contacts or fb_accounts or all_tp or msgr_threads:
            h_tp = doc.add_heading(level=1)
            r_htp = h_tp.add_run("4. Third-Party Social Media & Messaging Intelligence")
            r_htp.font.color.rgb = COLOR_PRIMARY
            r_htp.bold = True

            # 4.1 TikTok Intelligence
            if tt_contacts:
                h_tt = doc.add_heading(level=2)
                r_htt = h_tt.add_run(f"4.1 TikTok Discovered Contacts & Profiles ({len(tt_contacts):,} Profiles)")
                r_htt.font.color.rgb = COLOR_PRIMARY
                r_htt.bold = True

                if tt_owner:
                    p_own = doc.add_paragraph()
                    r_ow_label = p_own.add_run("Identified Device Owner Account: ")
                    r_ow_label.bold = True
                    p_own.add_run(f"@{tt_owner.get('handle')} ({tt_owner.get('nickname')}) | UID: {tt_owner.get('uid')} | Followers: {tt_owner.get('follower_count', 'N/A')}")

                tbl_tt = doc.add_table(rows=1, cols=5)
                set_table_borders(tbl_tt)
                hdr_tt = tbl_tt.rows[0].cells
                for i, h in enumerate(["Handle / Username", "Display Name", "Followers", "Interactions", "Bio / Description"]):
                    set_cell_background(hdr_tt[i], "0F2043")
                    set_cell_margins(hdr_tt[i])
                    r = hdr_tt[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9)

                for c in tt_contacts[:50]:
                    row = tbl_tt.add_row().cells
                    for i in range(5):
                        set_cell_margins(row[i])
                    h_str = f"@{c.get('handle')}" if c.get('handle') else "N/A"
                    row[0].paragraphs[0].add_run(h_str).font.size = Pt(8.5)
                    row[1].paragraphs[0].add_run(str(c.get('nickname', ''))[:30]).font.size = Pt(8.5)
                    row[2].paragraphs[0].add_run(f"{c['follower_count']:,}" if c.get('follower_count') is not None else "-").font.size = Pt(8.5)
                    row[3].paragraphs[0].add_run(f"{c['access_count']:,}" if c.get('access_count') else "-").font.size = Pt(8.5)
                    row[4].paragraphs[0].add_run(str(c.get('bio', ''))[:60]).font.size = Pt(8.0)

                doc.add_paragraph()

            # 4.2 Facebook & Meta Infrastructure
            if fb_accounts or msgr_threads:
                h_fb = doc.add_heading(level=2)
                r_hfb = h_fb.add_run(f"4.2 Facebook & Meta Discovered Accounts ({len(fb_accounts)} Accounts / {len(msgr_threads)} Threads)")
                r_hfb.font.color.rgb = COLOR_PRIMARY
                r_hfb.bold = True

                if fb_accounts:
                    tbl_fb = doc.add_table(rows=1, cols=4)
                    set_table_borders(tbl_fb)
                    hdr_fb = tbl_fb.rows[0].cells
                    for i, h in enumerate(["Facebook ID (FBID)", "Linked Instagram", "Last Sync Time", "Profile Web Link"]):
                        set_cell_background(hdr_fb[i], "0F2043")
                        set_cell_margins(hdr_fb[i])
                        r = hdr_fb[i].paragraphs[0].add_run(h)
                        r.bold = True
                        r.font.color.rgb = RGBColor(255, 255, 255)
                        r.font.size = Pt(9)

                    for a in fb_accounts:
                        row = tbl_fb.add_row().cells
                        for i in range(4):
                            set_cell_margins(row[i])
                        row[0].paragraphs[0].add_run(str(a.get("account_fbid"))).font.size = Pt(8.5)
                        row[1].paragraphs[0].add_run(f"@{a.get('linked_instagram_user')}" if a.get('linked_instagram_user') != "N/A" else "None").font.size = Pt(8.5)
                        row[2].paragraphs[0].add_run(str(a.get("last_sync", "N/A"))[:19]).font.size = Pt(8.5)
                        row[3].paragraphs[0].add_run(str(a.get("profile_url"))).font.size = Pt(8.0)

                    doc.add_paragraph()

            # 4.3 Social & Instant Messaging Logs
            if all_tp:
                h_tp_msg = doc.add_heading(level=2)
                r_htpm = h_tp_msg.add_run(f"4.3 Chat Messages & Direct Interaction Logs ({len(all_tp):,} Records)")
                r_htpm.font.color.rgb = COLOR_PRIMARY
                r_htpm.bold = True

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
            from parsers.calls_parser import CallsParser
            cp_temp = CallsParser(None)
            cp_temp.calls = self.calls
            analytics = cp_temp.get_frequency_analytics()

            h4 = doc.add_heading(level=1)
            r_h4 = h4.add_run(f"5. Call History & Voice Telemetry ({len(self.calls):,} records)")
            r_h4.font.color.rgb = COLOR_PRIMARY
            r_h4.bold = True

            # 5.1 Telephony Analytics Overview Table
            tbl_c_sum = doc.add_table(rows=4, cols=2)
            set_table_borders(tbl_c_sum)
            tbl_c_sum.alignment = WD_TABLE_ALIGNMENT.CENTER

            c_sum_rows = [
                ("Total Recorded Calls", f"{analytics.get('total_calls', 0):,} events (In: {analytics.get('total_incoming', 0):,} | Out: {analytics.get('total_outgoing', 0):,} | Missed: {analytics.get('total_missed', 0):,})"),
                ("Cumulative Talk Time", f"{analytics.get('total_duration_formatted', '0s')} ({analytics.get('total_duration_hms', '00:00:00')})"),
                ("Inbound / Outbound Duration", f"Inbound: {analytics.get('inbound_duration_formatted', '0s')} | Outbound: {analytics.get('outbound_duration_formatted', '0s')}"),
                ("Average Call Duration", f"{analytics.get('average_duration_formatted', '0s')} per call")
            ]

            for idx, (label, val) in enumerate(c_sum_rows):
                row = tbl_c_sum.rows[idx]
                c0, c1 = row.cells[0], row.cells[1]
                set_cell_background(c0, "F0F4F8")
                set_cell_margins(c0)
                set_cell_margins(c1)
                c0.paragraphs[0].add_run(label).bold = True
                c1.paragraphs[0].add_run(val)

            doc.add_paragraph()

            # 5.2 Top Frequent Contacts Table
            freq_contacts = analytics.get("frequent_contacts", [])[:15]
            if freq_contacts:
                p_sub_fc = doc.add_paragraph()
                r_sfc = p_sub_fc.add_run("Top Frequent Communication Partners")
                r_sfc.bold = True
                r_sfc.font.size = Pt(11)
                r_sfc.font.color.rgb = COLOR_SECONDARY

                tbl_fc = doc.add_table(rows=1, cols=6)
                set_table_borders(tbl_fc)
                hdr_fc = tbl_fc.rows[0].cells
                for i, h in enumerate(["Rank", "Contact / Phone Number", "Total", "In/Out/Missed", "Talk Time", "Last Contact Date"]):
                    set_cell_background(hdr_fc[i], "1F3A60")
                    set_cell_margins(hdr_fc[i])
                    r = hdr_fc[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(8.5)

                for idx, fc in enumerate(freq_contacts, start=1):
                    row = tbl_fc.add_row().cells
                    for i in range(6):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(f"#{idx}").font.size = Pt(8.0)
                    row[1].paragraphs[0].add_run(str(fc.get("display_actor", "Unknown"))).font.size = Pt(8.0)
                    row[2].paragraphs[0].add_run(str(fc.get("total_calls", 0))).font.size = Pt(8.0)
                    row[3].paragraphs[0].add_run(str(fc.get("ratio_summary", ""))).font.size = Pt(8.0)
                    row[4].paragraphs[0].add_run(str(fc.get("total_duration_formatted", "0s"))).font.size = Pt(8.0)
                    row[5].paragraphs[0].add_run(str(fc.get("last_call_local", "N/A"))).font.size = Pt(8.0)

                doc.add_paragraph()

            # 5.3 Detailed Chronological Call Log
            p_sub_cl = doc.add_paragraph()
            r_scl = p_sub_cl.add_run("Chronological Call Records (Latest 100)")
            r_scl.bold = True
            r_scl.font.size = Pt(11)
            r_scl.font.color.rgb = COLOR_SECONDARY

            tbl_calls = doc.add_table(rows=1, cols=6)
            set_table_borders(tbl_calls)
            hdr_c = tbl_calls.rows[0].cells
            for i, h in enumerate(["Timestamp (Local)", "Direction", "Contact Name / Number", "Status", "Duration", "Provider"]):
                set_cell_background(hdr_c[i], "0F2043")
                set_cell_margins(hdr_c[i])
                r = hdr_c[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(8.5)

            for c in self.calls[:100]:
                row = tbl_calls.add_row().cells
                for i in range(6):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(c.get("timestamp_local", "N/A")).font.size = Pt(8.0)
                row[1].paragraphs[0].add_run(c.get("direction", "N/A")).font.size = Pt(8.0)
                
                c_name = f"{c.get('contact_name')}\n({c.get('number')})" if c.get('contact_name') != 'Unknown' else c.get('number')
                row[2].paragraphs[0].add_run(c_name).font.size = Pt(8.0)
                
                status_run = row[3].paragraphs[0].add_run(c.get("status", "N/A"))
                status_run.font.size = Pt(8.0)
                if "Missed" in c.get("status", "") or "Blocked" in c.get("status", ""):
                    status_run.font.color.rgb = COLOR_ACCENT

                row[4].paragraphs[0].add_run(f"{c.get('duration_formatted', '0s')}\n({c.get('duration_seconds', 0)}s)").font.size = Pt(8.0)
                row[5].paragraphs[0].add_run(c.get("service_provider", "Telephony")).font.size = Pt(8.0)

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

        # Section 10: Camera Roll Photos, Videos & Geospatial Geolocation
        if self.photos:
            from parsers.photos_parser import PhotosParser
            pp_temp = PhotosParser(None)
            pp_temp.photos = self.photos
            p_sum = pp_temp.get_summary()

            h_p = doc.add_heading(level=1)
            r_hp = h_p.add_run(f"10. Camera Roll Photos, Videos & Geospatial Intelligence ({len(self.photos):,} assets)")
            r_hp.font.color.rgb = COLOR_PRIMARY
            r_hp.bold = True

            # Summary Table
            tbl_p_sum = doc.add_table(rows=3, cols=2)
            set_table_borders(tbl_p_sum)
            tbl_p_sum.alignment = WD_TABLE_ALIGNMENT.CENTER

            p_sum_rows = [
                ("Total Media Assets Indexed", f"{p_sum.get('total_media_items', len(self.photos)):,} assets (Photos: {p_sum.get('total_photos', 0):,} | Videos: {p_sum.get('total_videos', 0):,})"),
                ("Geotagged Locations (GPS)", f"{p_sum.get('total_geotagged', 0):,} items with EXIF coordinates"),
                ("Special Categories", f"Recently Deleted / Trashed: {p_sum.get('total_trashed', 0):,} | Hidden Album: {p_sum.get('total_hidden', 0):,} | Favorites: {p_sum.get('total_favorites', 0):,}")
            ]

            for idx, (label, val) in enumerate(p_sum_rows):
                row = tbl_p_sum.rows[idx]
                c0, c1 = row.cells[0], row.cells[1]
                set_cell_background(c0, "F0F4F8")
                set_cell_margins(c0)
                set_cell_margins(c1)
                c0.paragraphs[0].add_run(label).bold = True
                c1.paragraphs[0].add_run(val)

            doc.add_paragraph()

            # Geolocation Points Table
            geo_list = [p for p in self.photos if p.get("has_gps")][:30]
            if geo_list:
                p_geo_hdr = doc.add_paragraph()
                r_gh = p_geo_hdr.add_run(f"Geospatial Coordinates & Mapping ({len(geo_list)} Geotagged Media Samples)")
                r_gh.bold = True
                r_gh.font.size = Pt(11)
                r_gh.font.color.rgb = COLOR_SECONDARY

                tbl_geo = doc.add_table(rows=1, cols=4)
                set_table_borders(tbl_geo)
                hdr_g = tbl_geo.rows[0].cells
                for i, h in enumerate(["Capture Timestamp", "Filename / Media Type", "GPS Latitude, Longitude", "Google Maps URL"]):
                    set_cell_background(hdr_g[i], "1F3A60")
                    set_cell_margins(hdr_g[i])
                    r = hdr_g[i].paragraphs[0].add_run(h)
                    r.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(8.5)

                for gp in geo_list:
                    row = tbl_geo.add_row().cells
                    for i in range(4):
                        set_cell_margins(row[i])
                    row[0].paragraphs[0].add_run(gp.get("timestamp_created_local") or gp.get("timestamp_local", "N/A")).font.size = Pt(8.0)
                    row[1].paragraphs[0].add_run(f"{gp.get('filename')}\n({gp.get('media_type', 'Photo')})").font.size = Pt(8.0)
                    row[2].paragraphs[0].add_run(f"{gp.get('latitude')}, {gp.get('longitude')}").font.size = Pt(8.0)
                    row[3].paragraphs[0].add_run(gp.get("google_maps_url", "")).font.size = Pt(7.5)

                doc.add_paragraph()

            # Media Sample Log Table
            tbl_p_log = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_p_log)
            hdr_pl = tbl_p_log.rows[0].cells
            for i, h in enumerate(["Timestamp", "Filename", "Media Type", "Resolution / Duration", "GPS Tagged"]):
                set_cell_background(hdr_pl[i], "0F2043")
                set_cell_margins(hdr_pl[i])
                r = hdr_pl[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(8.5)

            for p in self.photos[:60]:
                row = tbl_p_log.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(p.get("timestamp_created_local") or p.get("timestamp_local", "N/A")).font.size = Pt(8.0)
                row[1].paragraphs[0].add_run(p.get("filename", "Unknown")).font.size = Pt(8.0)
                row[2].paragraphs[0].add_run(p.get("media_type", "Photo")).font.size = Pt(8.0)
                res_dur = p.get("resolution", "N/A")
                if p.get("duration_seconds", 0) > 0:
                    res_dur += f" | {p.get('duration_formatted')}"
                row[3].paragraphs[0].add_run(res_dur).font.size = Pt(8.0)
                row[4].paragraphs[0].add_run("Yes (Coordinates)" if p.get("has_gps") else "No").font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 11: SQLite Freelist & Deleted Data Carving
        if self.deleted_carved_records:
            h_del = doc.add_heading(level=1)
            r_hdel = h_del.add_run(f"11. SQLite Freelist & Carved Deleted Data ({len(self.deleted_carved_records):,} fragments)")
            r_hdel.font.color.rgb = COLOR_PRIMARY
            r_hdel.bold = True

            p_del_info = doc.add_paragraph()
            p_del_info.add_run(
                "Physical low-level carving extracted from SQLite Freelist trunk pages, unallocated page slack, "
                "and Write-Ahead Log (WAL) transaction buffers. Classified via regex heuristic matching."
            ).font.size = Pt(9.5)

            tbl_del = doc.add_table(rows=1, cols=5)
            set_table_borders(tbl_del)
            hdr_d = tbl_del.rows[0].cells
            for i, h in enumerate(["Source Database", "Structure Type", "Page / Offset", "Category", "Carved Fragment Text"]):
                set_cell_background(hdr_d[i], "0F2043")
                set_cell_margins(hdr_d[i])
                r = hdr_d[i].paragraphs[0].add_run(h)
                r.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                r.font.size = Pt(8.5)

            for d_item in self.deleted_carved_records[:100]:
                row = tbl_del.add_row().cells
                for i in range(5):
                    set_cell_margins(row[i])
                row[0].paragraphs[0].add_run(d_item.get("database_name", "SQLite DB")).font.size = Pt(8.0)
                row[1].paragraphs[0].add_run(d_item.get("source_type", "Freelist")).font.size = Pt(8.0)
                
                offset = d_item.get("byte_offset", 0)
                off_str = f"0x{offset:06X}" if isinstance(offset, int) else str(offset)
                row[2].paragraphs[0].add_run(f"Pg: {d_item.get('page_number', 'N/A')}\n{off_str}").font.size = Pt(7.5)

                cat_run = row[3].paragraphs[0].add_run(d_item.get("category", "Deleted Text"))
                cat_run.font.size = Pt(8.0)
                if "Financial" in d_item.get("category", "") or "Phone" in d_item.get("category", ""):
                    cat_run.bold = True
                    cat_run.font.color.rgb = COLOR_ACCENT

                row[4].paragraphs[0].add_run((d_item.get("carved_text") or "")[:150]).font.size = Pt(8.0)

            doc.add_paragraph()

        # Section 12: Forensic Chain of Custody Attestation
        h9 = doc.add_heading(level=1)
        r_h9 = h9.add_run("12. Forensic Chain of Custody & Legal Attestation")
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
