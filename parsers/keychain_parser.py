import os
import plistlib
import struct
import base64
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
from cryptography.hazmat.backends import default_backend

class KeychainParser:
    """
    Enterprise iOS Keychain Decryption & Cryptographic Secrets Extraction Engine.
    
    Parses and decrypts:
    1. Generic Passwords (genp): Wi-Fi Passwords, App Secrets, Database Encryption Keys (Signal/WhatsApp), Auth Tokens.
    2. Internet Passwords (inet): Safari Saved Logins, Mail/IMAP/SMTP/Exchange Credentials, Cloud SSO.
    3. Cryptographic Keys (keys): Symmetric AES-256 keys, RSA/ECDSA Private/Public Keys, Secure Enclave refs.
    4. Certificates (cert): Stored Identity Certificates, Corporate Trust Profiles.
    """

    KEYCHAIN_CLASS_NAMES = {
        6: "kSecAttrAccessibleAfterFirstUnlock",
        7: "kSecAttrAccessibleAlways",
        8: "kSecAttrAccessibleWhenUnlocked",
        9: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        10: "kSecAttrAccessibleAlwaysThisDeviceOnly",
        11: "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"
    }

    def __init__(self, keychain_path_or_blob, crypto_engine=None):
        self.keychain_source = keychain_path_or_blob
        self.crypto_engine = crypto_engine
        self.raw_data = None
        self.items = {
            "wifi_networks": [],
            "web_credentials": [],
            "app_tokens_and_keys": [],
            "vpn_and_system": [],
            "crypto_keys": [],
            "certificates": [],
            "all_decrypted_records": []
        }
        self.total_secrets = 0
        self._load_keychain()

    def _load_keychain(self):
        if isinstance(self.keychain_source, str) and os.path.exists(self.keychain_source):
            try:
                with open(self.keychain_source, "rb") as f:
                    self.raw_data = f.read()
            except Exception:
                pass
        elif isinstance(self.keychain_source, bytes):
            self.raw_data = self.keychain_source

    def _decrypt_v_data(self, v_data, class_hint=None):
        """
        Multi-strategy decryption for iOS Keychain v_Data binary blobs.
        Attempts:
        1. Plaintext UTF-8 / XML / bplist00 detection
        2. AES-GCM / AES-CBC with unwrapped Class Keys
        3. RFC 3394 unwrapped item key AES decryption
        """
        if not v_data:
            return None, "Empty payload"

        if not isinstance(v_data, (bytes, bytearray)):
            if isinstance(v_data, str):
                return v_data, "Plaintext string"
            return str(v_data), "Plaintext object"

        # 1. Plaintext checks
        if v_data.startswith(b"bplist00") or v_data.startswith(b"<?xml"):
            try:
                parsed = plistlib.loads(v_data)
                return parsed, "Plaintext Plist"
            except Exception:
                pass

        try:
            utf8_str = v_data.decode("utf-8")
            if utf8_str.isprintable():
                return utf8_str, "Plaintext UTF-8"
        except Exception:
            pass

        # If no crypto engine or unwrapped keys, return hex representation
        if not self.crypto_engine or not self.crypto_engine.unwrapped_keys:
            return v_data.hex(), "Raw Encrypted Hex (No Master Keys)"

        unwrapped_keys = self.crypto_engine.unwrapped_keys

        # Try key classes in priority order (class_hint first, then available keys)
        test_classes = []
        if class_hint and class_hint in unwrapped_keys:
            test_classes.append(class_hint)
        for cls_id in unwrapped_keys:
            if cls_id not in test_classes:
                test_classes.append(cls_id)

        # Strategy 2: Check for Apple Keychain Wrapped Key Header (class_id + 40 bytes wrapped key + payload)
        if len(v_data) >= 44:
            header_class = struct.unpack("<I", v_data[:4])[0]
            wrapped_key = v_data[4:44]
            cipher_payload = v_data[44:]

            target_class_key = unwrapped_keys.get(header_class) or unwrapped_keys.get(class_hint)
            if target_class_key and len(wrapped_key) == 40:
                try:
                    item_key = aes_key_unwrap(target_class_key, wrapped_key, backend=default_backend())
                    # Try AES-GCM or AES-CBC on cipher_payload
                    # AES-GCM: Tag (16 bytes) + IV (16 or 12 bytes) + Ciphertext or IV + Ciphertext + Tag
                    if len(cipher_payload) >= 28:
                        # Case 1: Tag (16 bytes) + IV (12 bytes) + Ciphertext
                        try:
                            tag = cipher_payload[:16]
                            iv = cipher_payload[16:28]
                            ct = cipher_payload[28:]
                            aesgcm = AESGCM(item_key)
                            pt = aesgcm.decrypt(iv, ct + tag, None)
                            return self._decode_decrypted_bytes(pt)
                        except Exception:
                            pass

                        # Case 2: IV (16 bytes) + Ciphertext + Tag (16 bytes)
                        try:
                            iv = cipher_payload[:16]
                            ct = cipher_payload[16:-16]
                            tag = cipher_payload[-16:]
                            aesgcm = AESGCM(item_key)
                            pt = aesgcm.decrypt(iv, ct + tag, None)
                            return self._decode_decrypted_bytes(pt)
                        except Exception:
                            pass

                    # Case 3: AES-256-CBC with Zero IV or 16-byte IV
                    try:
                        iv = cipher_payload[:16] if len(cipher_payload) > 32 else (b"\x00" * 16)
                        ct = cipher_payload[16:] if len(cipher_payload) > 32 else cipher_payload
                        cipher = Cipher(algorithms.AES(item_key), modes.CBC(iv), backend=default_backend())
                        dec = cipher.decryptor()
                        pt = dec.update(ct) + dec.finalize()
                        # Unpad PKCS#7 if valid
                        pad_len = pt[-1] if len(pt) > 0 else 0
                        if 1 <= pad_len <= 16 and pt.endswith(bytes([pad_len]) * pad_len):
                            pt = pt[:-pad_len]
                        return self._decode_decrypted_bytes(pt)
                    except Exception:
                        pass
                except Exception:
                    pass

        # Strategy 3: Direct Class Key AES-GCM & AES-CBC Decryption
        for cls_id in test_classes:
            class_key = unwrapped_keys[cls_id]

            # Try AES-GCM with standard 12/16 byte IV prefixes
            if len(v_data) >= 28:
                for iv_len in [12, 16]:
                    try:
                        iv = v_data[:iv_len]
                        ct_and_tag = v_data[iv_len:]
                        aesgcm = AESGCM(class_key)
                        pt = aesgcm.decrypt(iv, ct_and_tag, None)
                        return self._decode_decrypted_bytes(pt)
                    except Exception:
                        pass

            # Try AES-256-CBC with zero IV
            try:
                iv = b"\x00" * 16
                cipher = Cipher(algorithms.AES(class_key), modes.CBC(iv), backend=default_backend())
                dec = cipher.decryptor()
                pt = dec.update(v_data) + dec.finalize()
                pad_len = pt[-1] if len(pt) > 0 else 0
                if 1 <= pad_len <= 16 and pt.endswith(bytes([pad_len]) * pad_len):
                    pt = pt[:-pad_len]
                res, method = self._decode_decrypted_bytes(pt)
                if method != "Raw Hex Bytes":
                    return res, f"AES-256-CBC (Class {cls_id})"
            except Exception:
                pass

        # Fallback to base64 / hex representation
        return v_data.hex(), "Encrypted Payload (Hex)"

    def _decode_decrypted_bytes(self, pt_bytes):
        if not pt_bytes:
            return "", "Empty Decrypted"

        # Check for Plist
        if pt_bytes.startswith(b"bplist00") or pt_bytes.startswith(b"<?xml"):
            try:
                parsed = plistlib.loads(pt_bytes)
                return parsed, "Decrypted Binary Plist"
            except Exception:
                pass

        # Check for UTF-8 printable string
        try:
            s = pt_bytes.decode("utf-8")
            if s.isprintable() and len(s) > 0:
                return s, "Decrypted UTF-8 String"
        except Exception:
            pass

        # Return hex and size note
        return f"0x{pt_bytes.hex()} ({len(pt_bytes)} bytes cryptographic key/token)", "Decrypted Key/Token Bytes"

    def parse(self):
        """
        Parses all keychain tables (genp, inet, cert, keys) and extracts decrypted credentials & cryptographic keys.
        """
        if not self.raw_data:
            return self.items

        plist = None
        try:
            plist = plistlib.loads(self.raw_data)
        except Exception:
            if self.raw_data and len(self.raw_data) > 0:
                # Try unpadding 1 to 16 bytes
                for pad_len in range(1, 17):
                    try:
                        plist = plistlib.loads(self.raw_data[:-pad_len])
                        if isinstance(plist, dict):
                            break
                    except Exception:
                        pass

        if not isinstance(plist, dict):
            return self.items

        all_records = []

        # 1. Generic Passwords (genp) - Wi-Fi, App Secrets, Database Keys, System Tokens
        genp_list = plist.get("genp", [])
        if isinstance(genp_list, list):
            for item in genp_list:
                if not isinstance(item, dict):
                    continue
                rec = self._parse_generic_password(item)
                if rec:
                    all_records.append(rec)
                    # Categorize
                    agrp = str(rec.get("access_group", "")).lower()
                    svce = str(rec.get("service", "")).lower()
                    if "wifi" in agrp or "airport" in svce or "airdrop" in svce:
                        self.items["wifi_networks"].append(rec)
                    elif any(k in agrp or k in svce for k in ["signal", "whisper", "whatsapp", "telegram", "proton", "teams", "cipher", "key", "token", "secret"]):
                        self.items["app_tokens_and_keys"].append(rec)
                    elif any(k in agrp or k in svce for k in ["vpn", "ipsec", "ppp", "network", "system", "apple"]):
                        self.items["vpn_and_system"].append(rec)
                    else:
                        self.items["app_tokens_and_keys"].append(rec)

        # 2. Internet Passwords (inet) - Safari Saved Logins, Web Portals, Cloud SSO
        inet_list = plist.get("inet", [])
        if isinstance(inet_list, list):
            for item in inet_list:
                if not isinstance(item, dict):
                    continue
                rec = self._parse_internet_password(item)
                if rec:
                    all_records.append(rec)
                    self.items["web_credentials"].append(rec)

        # 3. Cryptographic Keys (keys) - AES symmetric keys, Private/Public Keys
        keys_list = plist.get("keys", [])
        if isinstance(keys_list, list):
            for item in keys_list:
                if not isinstance(item, dict):
                    continue
                rec = self._parse_crypto_key(item)
                if rec:
                    all_records.append(rec)
                    self.items["crypto_keys"].append(rec)

        # 4. Certificates (cert) - Trust identities & Enterprise certs
        cert_list = plist.get("cert", [])
        if isinstance(cert_list, list):
            for item in cert_list:
                if not isinstance(item, dict):
                    continue
                rec = self._parse_certificate(item)
                if rec:
                    all_records.append(rec)
                    self.items["certificates"].append(rec)

        self.items["all_decrypted_records"] = all_records
        self.total_secrets = len(all_records)
        return self.items

    def _parse_generic_password(self, item):
        agrp = self._clean_str(item.get("agrp"))
        acct = self._clean_str(item.get("acct"))
        svce = self._clean_str(item.get("svce"))
        desc = self._clean_str(item.get("desc") or item.get("labl"))
        clas_id = item.get("clas")
        cdat = self._format_date(item.get("cdat"))
        mdat = self._format_date(item.get("mdat"))
        v_data = item.get("v_Data")

        dec_val, method = self._decrypt_v_data(v_data, class_hint=clas_id)

        # Wi-Fi extraction enhancement (parse SSID and PSK from plist if present)
        wifi_ssid = None
        wifi_psk = None
        if isinstance(dec_val, dict):
            wifi_ssid = dec_val.get("SSID_STR") or dec_val.get("SSID")
            wifi_psk = dec_val.get("Passphrase") or dec_val.get("Password") or dec_val.get("PSK")
            if wifi_ssid or wifi_psk:
                dec_val = f"SSID: {wifi_ssid or 'N/A'} | Passphrase: {wifi_psk or 'N/A'}"

        return {
            "type": "Generic Password / Secret",
            "access_group": agrp or "apple",
            "account": acct or "System Account",
            "service": svce or "Generic Service",
            "description": desc or "Stored Credential",
            "protection_class": self.KEYCHAIN_CLASS_NAMES.get(clas_id, f"Class {clas_id}"),
            "creation_date": cdat,
            "modification_date": mdat,
            "decrypted_value": str(dec_val),
            "decryption_method": method
        }

    def _parse_internet_password(self, item):
        agrp = self._clean_str(item.get("agrp"))
        acct = self._clean_str(item.get("acct"))
        srvr = self._clean_str(item.get("srvr"))
        ptcl = self._clean_str(item.get("ptcl"))
        path = self._clean_str(item.get("path"))
        port = item.get("port", "")
        clas_id = item.get("clas")
        cdat = self._format_date(item.get("cdat"))
        mdat = self._format_date(item.get("mdat"))
        v_data = item.get("v_Data")

        dec_val, method = self._decrypt_v_data(v_data, class_hint=clas_id)

        target_url = srvr
        if ptcl and srvr:
            target_url = f"{ptcl.lower()}://{srvr}"
            if port and port not in (80, 443, 0):
                target_url += f":{port}"
            if path:
                target_url += f"/{path.lstrip('/')}"

        return {
            "type": "Internet / Web Credential",
            "access_group": agrp or "com.apple.safari",
            "account": acct or "Unknown User",
            "server": srvr or "Web Portal",
            "url": target_url or "N/A",
            "protocol": ptcl or "HTTPS",
            "protection_class": self.KEYCHAIN_CLASS_NAMES.get(clas_id, f"Class {clas_id}"),
            "creation_date": cdat,
            "modification_date": mdat,
            "decrypted_password": str(dec_val),
            "decryption_method": method
        }

    def _parse_crypto_key(self, item):
        agrp = self._clean_str(item.get("agrp"))
        labl = self._clean_str(item.get("labl") or item.get("klbl"))
        ktyp = item.get("ktyp") # 0 = RSA, 1 = Elliptic Curve, 2 = AES
        bsiz = item.get("bsiz") # Key size in bits (e.g. 256, 2048)
        clas_id = item.get("clas")
        cdat = self._format_date(item.get("cdat"))
        v_data = item.get("v_Data")

        dec_val, method = self._decrypt_v_data(v_data, class_hint=clas_id)

        key_types = {0: "RSA Key", 1: "ECDSA Key", 2: "AES Symmetric Key"}
        type_str = key_types.get(ktyp, f"Cryptographic Key (Type {ktyp})")

        return {
            "type": "Cryptographic Key",
            "key_type": type_str,
            "bit_size": bsiz or "256",
            "access_group": agrp or "com.apple.security",
            "label": labl or "Application Cryptographic Key",
            "protection_class": self.KEYCHAIN_CLASS_NAMES.get(clas_id, f"Class {clas_id}"),
            "creation_date": cdat,
            "decrypted_key_payload": str(dec_val),
            "decryption_method": method
        }

    def _parse_certificate(self, item):
        agrp = self._clean_str(item.get("agrp"))
        labl = self._clean_str(item.get("labl"))
        subj = self._clean_str(item.get("subj"))
        issr = self._clean_str(item.get("issr"))
        clas_id = item.get("clas")
        cdat = self._format_date(item.get("cdat"))
        v_data = item.get("v_Data")

        cert_val, method = self._decrypt_v_data(v_data, class_hint=clas_id)

        return {
            "type": "Security Certificate",
            "access_group": agrp or "com.apple.security.cert",
            "label": labl or subj or "Identity Certificate",
            "subject": subj or "N/A",
            "issuer": issr or "N/A",
            "protection_class": self.KEYCHAIN_CLASS_NAMES.get(clas_id, f"Class {clas_id}"),
            "creation_date": cdat,
            "payload_summary": f"Certificate ({len(str(cert_val))} chars)",
            "decryption_method": method
        }

    def export_keychain_json(self, output_path):
        """
        Exports all decrypted keychain secrets to court-ready JSON format.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        export_payload = {
            "export_timestamp": datetime.now().isoformat(),
            "total_decrypted_secrets": self.total_secrets,
            "summary_counts": {
                "wifi_networks": len(self.items["wifi_networks"]),
                "web_credentials": len(self.items["web_credentials"]),
                "app_tokens_and_keys": len(self.items["app_tokens_and_keys"]),
                "vpn_and_system": len(self.items["vpn_and_system"]),
                "crypto_keys": len(self.items["crypto_keys"]),
                "certificates": len(self.items["certificates"])
            },
            "wifi_networks": self.items["wifi_networks"],
            "web_credentials": self.items["web_credentials"],
            "app_tokens_and_keys": self.items["app_tokens_and_keys"],
            "vpn_and_system": self.items["vpn_and_system"],
            "crypto_keys": self.items["crypto_keys"],
            "certificates": self.items["certificates"],
            "all_records": self.items["all_decrypted_records"]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_payload, f, indent=2, ensure_ascii=False)
        return output_path

    def _clean_str(self, val):
        if val is None:
            return ""
        if isinstance(val, bytes):
            try:
                return val.decode("utf-8")
            except Exception:
                return val.hex()
        return str(val)

    def _format_date(self, dt):
        if not dt:
            return "N/A"
        if isinstance(dt, datetime):
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return str(dt)
