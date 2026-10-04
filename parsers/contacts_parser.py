import sqlite3
import os
import re
from core.db_utils import connect_readonly_sqlite

class ContactsParser:
    """
    Parses iOS AddressBook.sqlitedb and cross-references external caches (Truecaller / Viber).
    """

    def __init__(self, db_path, truecaller_path=None, viber_path=None):
        self.db_path = db_path
        self.truecaller_path = truecaller_path
        self.viber_path = viber_path
        self.contacts = []
        self.number_to_name = {}

    def parse(self):
        # 1. Parse Native AddressBook.sqlitedb
        if self.db_path and os.path.exists(self.db_path):
            try:
                conn = connect_readonly_sqlite(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = """
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
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    first = row["first_name"] or ""
                    last = row["last_name"] or ""
                    org = row["organization"] or ""
                    full_name = f"{first} {last}".strip() or org or "Unnamed Contact"

                    phone = row["phone_number"] or ""
                    clean_phone = re.sub(r'[^0-9+]', '', phone)

                    email = row["email_address"] or ""

                    record = {
                        "source": "Apple AddressBook",
                        "person_id": row["person_id"],
                        "name": full_name,
                        "organization": org,
                        "phone": clean_phone or phone,
                        "raw_phone": phone,
                        "email": email,
                        "note": row["note"] or ""
                    }
                    self.contacts.append(record)
                    if clean_phone:
                        self.number_to_name[clean_phone] = full_name
                        # Also store last 10 digits
                        if len(clean_phone) >= 10:
                            self.number_to_name[clean_phone[-10:]] = full_name

                conn.close()
            except Exception:
                pass

        # 2. Parse Truecaller Cache (db.sqlite)
        if self.truecaller_path and os.path.exists(self.truecaller_path):
            try:
                tc_conn = connect_readonly_sqlite(self.truecaller_path)
                tc_conn.row_factory = sqlite3.Row
                tc_cur = tc_conn.cursor()
                tc_cur.execute("SELECT ZNAME, ZPHONE, ZABOUT FROM ZCONTACT WHERE ZPHONE IS NOT NULL")
                for row in tc_cur.fetchall():
                    name = row["ZNAME"] or ""
                    phone = row["ZPHONE"] or ""
                    clean_p = re.sub(r'[^0-9+]', '', phone)
                    if name and clean_p:
                        self.contacts.append({
                            "source": "Truecaller Cache",
                            "person_id": "TC",
                            "name": name,
                            "organization": "",
                            "phone": clean_p,
                            "raw_phone": phone,
                            "email": "",
                            "note": row["ZABOUT"] or ""
                        })
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
        return phone_number
