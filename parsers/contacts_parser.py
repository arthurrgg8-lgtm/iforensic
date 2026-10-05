import sqlite3
import os
import re
from core.db_utils import connect_readonly_sqlite

class ContactsParser:
    """
    Parses iOS AddressBook.sqlitedb (supporting modern iOS FTS tables and legacy ABMultiValue)
    and cross-references external caches (WhatsApp ContactsV2, Truecaller, Viber).
    """

    def __init__(self, db_path, truecaller_path=None, viber_path=None, whatsapp_contacts_path=None):
        self.db_path = db_path
        self.truecaller_path = truecaller_path
        self.viber_path = viber_path
        self.whatsapp_contacts_path = whatsapp_contacts_path
        self.contacts = []
        self.number_to_name = {}

    def parse(self):
        # 1. Parse Native AddressBook.sqlitedb
        if self.db_path and os.path.exists(self.db_path):
            try:
                conn = connect_readonly_sqlite(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Check existing tables in AddressBook
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cursor.fetchall())

                found_records = {}

                # Strategy A: Modern iOS (iOS 10+) ABPersonFullTextSearch_content
                if "ABPersonFullTextSearch_content" in tables:
                    try:
                        cursor.execute("""
                            SELECT 
                                docid, 
                                c0First as first_name, 
                                c1Last as last_name, 
                                c6Organization as organization, 
                                c9Note as note, 
                                c11JobTitle as job_title, 
                                c15DisplayName as display_name, 
                                c16Phone as phone_raw, 
                                c17Email as email_raw,
                                c18Address as address_raw
                            FROM ABPersonFullTextSearch_content
                        """)
                        for row in cursor.fetchall():
                            docid = row["docid"]
                            first = (row["first_name"] or "").strip()
                            last = (row["last_name"] or "").strip()
                            disp = (row["display_name"] or "").strip()
                            org = (row["organization"] or "").strip()
                            
                            name = disp or f"{first} {last}".strip() or org or "Unnamed Contact"
                            
                            # Parse phone numbers (FTS can store space-delimited duplicates/tokens)
                            phones = []
                            raw_p = row["phone_raw"] or ""
                            if raw_p:
                                tokens = raw_p.split()
                                seen_clean = set()
                                for tok in tokens:
                                    clean = re.sub(r'[^0-9+]', '', tok)
                                    if clean and len(clean) >= 4 and clean not in seen_clean:
                                        seen_clean.add(clean)
                                        phones.append(clean)

                            # Parse emails
                            emails = []
                            raw_e = row["email_raw"] or ""
                            if raw_e:
                                for tok in raw_e.split():
                                    if "@" in tok and tok not in emails:
                                        emails.append(tok.strip())

                            found_records[docid] = {
                                "source": "Apple AddressBook (FTS)",
                                "person_id": docid,
                                "name": name,
                                "first_name": first,
                                "last_name": last,
                                "organization": org,
                                "job_title": row["job_title"] or "",
                                "phone": phones[0] if phones else "",
                                "phone_numbers": phones,
                                "raw_phone": raw_p,
                                "email": emails[0] if emails else "",
                                "emails": emails,
                                "note": row["note"] or "",
                                "address": row["address_raw"] or "",
                                "truecaller_match": ""
                            }
                    except Exception:
                        pass

                # Strategy B: ABPerson + ABMultiValue (Legacy iOS & fallback)
                if "ABPerson" in tables:
                    try:
                        if "ABMultiValue" in tables:
                            cursor.execute("""
                                SELECT 
                                    p.ROWID as person_id,
                                    p.First as first_name,
                                    p.Last as last_name,
                                    p.Organization as organization,
                                    p.JobTitle as job_title,
                                    p.Note as note,
                                    mv.value as phone_number,
                                    mv_email.value as email_address
                                FROM ABPerson p
                                LEFT JOIN ABMultiValue mv ON p.ROWID = mv.record_id AND mv.property = 3
                                LEFT JOIN ABMultiValue mv_email ON p.ROWID = mv_email.record_id AND mv_email.property = 4
                            """)
                            for row in cursor.fetchall():
                                pid = row["person_id"]
                                if pid in found_records and found_records[pid]["phone_numbers"]:
                                    continue
                                first = (row["first_name"] or "").strip()
                                last = (row["last_name"] or "").strip()
                                org = (row["organization"] or "").strip()
                                name = f"{first} {last}".strip() or org or "Unnamed Contact"
                                phone = (row["phone_number"] or "").strip()
                                clean_p = re.sub(r'[^0-9+]', '', phone)
                                email = (row["email_address"] or "").strip()

                                rec = found_records.get(pid, {
                                    "source": "Apple AddressBook",
                                    "person_id": pid,
                                    "name": name,
                                    "first_name": first,
                                    "last_name": last,
                                    "organization": org,
                                    "job_title": row["job_title"] or "",
                                    "phone": clean_p or phone,
                                    "phone_numbers": [clean_p] if clean_p else [],
                                    "raw_phone": phone,
                                    "email": email,
                                    "emails": [email] if email else [],
                                    "note": row["note"] or "",
                                    "address": "",
                                    "truecaller_match": ""
                                })
                                if clean_p and clean_p not in rec["phone_numbers"]:
                                    rec["phone_numbers"].append(clean_p)
                                    rec["phone"] = rec["phone_numbers"][0]
                                if email and email not in rec["emails"]:
                                    rec["emails"].append(email)
                                    rec["email"] = rec["emails"][0]
                                found_records[pid] = rec
                        else:
                            # Standard ABPerson query without MultiValue
                            cursor.execute("SELECT ROWID, First, Last, Organization, JobTitle, Note, DisplayName FROM ABPerson")
                            for row in cursor.fetchall():
                                pid = row["ROWID"]
                                if pid not in found_records:
                                    first = (row["First"] or "").strip()
                                    last = (row["Last"] or "").strip()
                                    disp = (row["DisplayName"] or "").strip() if "DisplayName" in row.keys() else ""
                                    org = (row["Organization"] or "").strip()
                                    name = disp or f"{first} {last}".strip() or org or "Unnamed Contact"
                                    found_records[pid] = {
                                        "source": "Apple AddressBook",
                                        "person_id": pid,
                                        "name": name,
                                        "first_name": first,
                                        "last_name": last,
                                        "organization": org,
                                        "job_title": row["JobTitle"] or "",
                                        "phone": "",
                                        "phone_numbers": [],
                                        "raw_phone": "",
                                        "email": "",
                                        "emails": [],
                                        "note": row["Note"] or "",
                                        "address": "",
                                        "truecaller_match": ""
                                    }
                    except Exception:
                        pass

                # Index all found contacts into lookup maps
                for rec in found_records.values():
                    self.contacts.append(rec)
                    for p in rec["phone_numbers"]:
                        if p:
                            self.number_to_name[p] = rec["name"]
                            if len(p) >= 10:
                                self.number_to_name[p[-10:]] = rec["name"]

                conn.close()
            except Exception:
                pass

        # 2. Parse WhatsApp Contacts (ContactsV2.sqlite) if available
        if self.whatsapp_contacts_path and os.path.exists(self.whatsapp_contacts_path):
            try:
                wa_conn = connect_readonly_sqlite(self.whatsapp_contacts_path)
                wa_conn.row_factory = sqlite3.Row
                wa_cur = wa_conn.cursor()
                wa_cur.execute("SELECT ZFULLNAME, ZPHONENUMBER, ZWHATSAPPID, ZABOUTTEXT FROM ZWAADDRESSBOOKCONTACT WHERE ZFULLNAME IS NOT NULL OR ZPHONENUMBER IS NOT NULL")
                for row in wa_cur.fetchall():
                    name = (row["ZFULLNAME"] or "").strip()
                    phone = (row["ZPHONENUMBER"] or "").strip()
                    clean_p = re.sub(r'[^0-9+]', '', phone)
                    if not name and row["ZWHATSAPPID"]:
                        name = f"WA_{row['ZWHATSAPPID']}"
                    if name and clean_p:
                        # Cross-link if exists
                        matched = False
                        for c in self.contacts:
                            if clean_p in c["phone_numbers"] or (len(clean_p) >= 10 and any(p.endswith(clean_p[-10:]) for p in c["phone_numbers"])):
                                matched = True
                                break
                        if not matched:
                            self.contacts.append({
                                "source": "WhatsApp Contacts",
                                "person_id": "WA",
                                "name": name,
                                "first_name": name,
                                "last_name": "",
                                "organization": "",
                                "job_title": "",
                                "phone": clean_p,
                                "phone_numbers": [clean_p],
                                "raw_phone": phone,
                                "email": "",
                                "emails": [],
                                "note": row["ZABOUTTEXT"] or "",
                                "address": "",
                                "truecaller_match": ""
                            })
                        if clean_p not in self.number_to_name:
                            self.number_to_name[clean_p] = name
                            if len(clean_p) >= 10:
                                self.number_to_name[clean_p[-10:]] = name
                wa_conn.close()
            except Exception:
                pass

        # 3. Parse Truecaller Cache (db.sqlite)
        if self.truecaller_path and os.path.exists(self.truecaller_path):
            try:
                tc_conn = connect_readonly_sqlite(self.truecaller_path)
                tc_conn.row_factory = sqlite3.Row
                tc_cur = tc_conn.cursor()
                tc_cur.execute("SELECT ZNAME, ZPHONE, ZABOUT FROM ZCONTACT WHERE ZPHONE IS NOT NULL")
                for row in tc_cur.fetchall():
                    name = (row["ZNAME"] or "").strip()
                    phone = (row["ZPHONE"] or "").strip()
                    clean_p = re.sub(r'[^0-9+]', '', phone)
                    if name and clean_p:
                        # Match against existing contacts
                        for c in self.contacts:
                            if clean_p in c["phone_numbers"] or (len(clean_p) >= 10 and any(p.endswith(clean_p[-10:]) for p in c["phone_numbers"])):
                                c["truecaller_match"] = name
                        if clean_p not in self.number_to_name:
                            self.number_to_name[clean_p] = f"[Truecaller] {name}"
                            if len(clean_p) >= 10:
                                self.number_to_name[clean_p[-10:]] = f"[Truecaller] {name}"
                tc_conn.close()
            except Exception:
                pass

        return self.contacts

    def resolve_number(self, phone_number):
        if not phone_number:
            return "Unknown"
        clean = re.sub(r'[^0-9+]', '', str(phone_number))
        if clean in self.number_to_name:
            return self.number_to_name[clean]
        if len(clean) >= 10 and clean[-10:] in self.number_to_name:
            return self.number_to_name[clean[-10:]]
        return str(phone_number)

