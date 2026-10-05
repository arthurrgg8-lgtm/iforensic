import os
import re
import struct
import string

class SQLiteFreelistCarver:
    """
    Enterprise-grade SQLite Freelist & Unallocated Space Deleted Data Carver.
    Extracts deleted records, orphaned chat messages, deleted note fragments,
    and phone numbers directly from SQLite database pages and freelist buffers.
    """

    PHONE_REGEX = re.compile(rb'(\+?[1-9]\d{6,14})')
    EMAIL_REGEX = re.compile(rb'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')
    URL_REGEX = re.compile(rb'(https?://[a-zA-Z0-9./?=_%&:-]+)')
    PRINTABLE_CHARS = set(bytes(string.printable, 'ascii'))

    @staticmethod
    def carve_deleted_records(db_path, min_length=4, max_records=200):
        """
        Parses raw SQLite database pages, inspecting freelist pages and unallocated cell areas.
        Returns a list of carved deleted records.
        """
        if not db_path or not os.path.exists(db_path):
            return []

        carved_artifacts = []
        seen_payloads = set()

        try:
            with open(db_path, "rb") as f:
                header = f.read(100)
                if not header.startswith(b"SQLite format 3\x00"):
                    return []

                page_size = struct.unpack(">H", header[16:18])[0]
                if page_size == 1:
                    page_size = 65536
                elif page_size == 0:
                    page_size = 4096

                # Freelist trunk page pointer and total freelist pages
                freelist_trunk = struct.unpack(">I", header[32:36])[0]
                freelist_count = struct.unpack(">I", header[36:40])[0]

                file_size = os.path.getsize(db_path)
                total_pages = file_size // page_size

                # 1. Carve active Freelist pages
                current_trunk = freelist_trunk
                visited_trunks = set()
                while current_trunk != 0 and current_trunk not in visited_trunks and current_trunk <= total_pages:
                    visited_trunks.add(current_trunk)
                    offset = (current_trunk - 1) * page_size
                    f.seek(offset)
                    trunk_data = f.read(page_size)
                    if len(trunk_data) < 8:
                        break
                    
                    next_trunk = struct.unpack(">I", trunk_data[0:4])[0]
                    leaf_count = struct.unpack(">I", trunk_data[4:8])[0]

                    # Parse leaf freelist pages
                    for i in range(min(leaf_count, (page_size - 8) // 4)):
                        leaf_page = struct.unpack(">I", trunk_data[8 + (i * 4): 12 + (i * 4)])[0]
                        if 0 < leaf_page <= total_pages:
                            f.seek((leaf_page - 1) * page_size)
                            leaf_data = f.read(page_size)
                            fragments = SQLiteFreelistCarver._extract_strings_from_buffer(leaf_data, min_length)
                            for frag in fragments:
                                if frag not in seen_payloads:
                                    seen_payloads.add(frag)
                                    carved_artifacts.append({
                                        "source_type": "Freelist Page",
                                        "page_number": leaf_page,
                                        "byte_offset": (leaf_page - 1) * page_size,
                                        "carved_text": frag,
                                        "category": SQLiteFreelistCarver._classify_fragment(frag)
                                    })
                                    if len(carved_artifacts) >= max_records:
                                        break
                    current_trunk = next_trunk

                # 2. Carve Unallocated Space across all B-tree leaf pages
                for page_idx in range(1, min(total_pages + 1, 500)):
                    offset = (page_idx - 1) * page_size
                    f.seek(offset)
                    page_data = f.read(page_size)
                    if len(page_data) < 8:
                        continue

                    page_header_offset = 100 if page_idx == 1 else 0
                    page_type = page_data[page_header_offset]

                    # Page types: 0x0D (table leaf), 0x0A (index leaf)
                    if page_type in (0x0D, 0x0A):
                        cell_count = struct.unpack(">H", page_data[page_header_offset + 3: page_header_offset + 5])[0]
                        cell_content_start = struct.unpack(">H", page_data[page_header_offset + 5: page_header_offset + 7])[0]
                        if cell_content_start == 0:
                            cell_content_start = 65536

                        # Header size: 8 bytes for leaf pages
                        header_size = 8
                        unallocated_start = page_header_offset + header_size + (cell_count * 2)
                        unallocated_end = cell_content_start

                        if unallocated_start < unallocated_end <= len(page_data):
                            unallocated_buf = page_data[unallocated_start:unallocated_end]
                            fragments = SQLiteFreelistCarver._extract_strings_from_buffer(unallocated_buf, min_length)
                            for frag in fragments:
                                if frag not in seen_payloads and len(frag) >= min_length:
                                    seen_payloads.add(frag)
                                    carved_artifacts.append({
                                        "source_type": "Unallocated Cell Area",
                                        "page_number": page_idx,
                                        "byte_offset": offset + unallocated_start,
                                        "carved_text": frag,
                                        "category": SQLiteFreelistCarver._classify_fragment(frag)
                                    })
                                    if len(carved_artifacts) >= max_records:
                                        break

        except Exception:
            pass

        return carved_artifacts

    @staticmethod
    def _extract_strings_from_buffer(buf, min_len=4):
        """
        Extracts human-readable ASCII and UTF-8 string sequences from raw binary buffer.
        """
        results = []
        cur_chars = bytearray()

        for b in buf:
            if 32 <= b <= 126 or b in (9, 10, 13):
                cur_chars.append(b)
            else:
                if len(cur_chars) >= min_len:
                    try:
                        decoded = cur_chars.decode('utf-8', errors='ignore').strip()
                        # Filter out pure noise/symbols
                        if len(decoded) >= min_len and any(c.isalnum() for c in decoded):
                            results.append(decoded)
                    except Exception:
                        pass
                cur_chars = bytearray()

        if len(cur_chars) >= min_len:
            try:
                decoded = cur_chars.decode('utf-8', errors='ignore').strip()
                if len(decoded) >= min_len and any(c.isalnum() for c in decoded):
                    results.append(decoded)
            except Exception:
                pass

        return results

    @staticmethod
    def _classify_fragment(text):
        """
        Classifies carved fragment as Phone, Email, URL, Financial, or General Message.
        """
        t_lower = text.lower()
        if re.search(r'https?://', text):
            return "URL / Link"
        if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text):
            return "Email Address"
        if re.search(r'(\+?[1-9]\d{7,14})', text) and not any(c.isalpha() for c in text):
            return "Phone Number"
        if any(w in t_lower for w in ["otp", "bank", "card", "usd", "npr", "rs", "payment", "transferred", "code", "password", "pin"]):
            return "Financial / Credential Fragment"
        return "Deleted Chat / Note Text"
