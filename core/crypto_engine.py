import os
import plistlib
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class BackupKeyBag:
    """
    Parses Apple iOS BackupKeyBag binary data structures (TLV - Tag-Length-Value).
    Extracts PBKDF2 / scrypt parameters and protection class keys.
    """

    def __init__(self, keybag_bytes):
        self.raw_data = keybag_bytes
        self.attrs = {}
        self.class_keys = {}
        self.salt = None
        self.iter_count = 10000
        self.dpic = None
        self.dpsl = None
        self._parse_tlv()

    def _parse_tlv(self):
        offset = 0
        current_class = None
        current_wrap = None
        current_ktyp = None

        while offset + 8 <= len(self.raw_data):
            tag = self.raw_data[offset:offset+4].decode("ascii", errors="ignore")
            length = struct.unpack(">I", self.raw_data[offset+4:offset+8])[0]
            offset += 8
            if offset + length > len(self.raw_data):
                break
            val = self.raw_data[offset:offset+length]
            offset += length

            if tag == "SALT":
                self.salt = val
            elif tag == "ITER":
                self.iter_count = struct.unpack(">I", val)[0]
            elif tag == "DPIC":
                self.dpic = struct.unpack(">I", val)[0]
            elif tag == "DPSL":
                self.dpsl = val
            elif tag == "CLAS":
                current_class = struct.unpack(">I", val)[0]
            elif tag == "WRAP":
                current_wrap = struct.unpack(">I", val)[0]
            elif tag == "KTYP":
                current_ktyp = struct.unpack(">I", val)[0]
            elif tag == "WKEY":
                if current_class is not None:
                    self.class_keys[current_class] = {
                        "wrap": current_wrap,
                        "ktyp": current_ktyp,
                        "wkey": val
                    }


class CryptoEngine:
    """
    Enterprise iOS Backup Decryption & Key Derivation Engine.
    Handles:
    1. Detection of encryption status in Manifest.plist
    2. KeyBag parsing and passphrase verification (PBKDF2 / scrypt)
    3. AES-256 Key Unwrapping (RFC 3394) and on-the-fly database decryption
    """

    def __init__(self, backup_dir):
        self.backup_dir = os.path.abspath(backup_dir)
        self.manifest_plist_path = os.path.join(self.backup_dir, "Manifest.plist")
        if not os.path.exists(self.manifest_plist_path):
            self.manifest_plist_path = os.path.join(self.backup_dir, "Snapshot", "Manifest.plist")

        self.is_encrypted = False
        self.keybag = None
        self.manifest_data = {}
        self.unwrapped_keys = {}
        self._load_manifest()

    def _load_manifest(self):
        if not os.path.exists(self.manifest_plist_path):
            return

        try:
            with open(self.manifest_plist_path, "rb") as f:
                self.manifest_data = plistlib.load(f)
                self.is_encrypted = self.manifest_data.get("IsEncrypted", False)
                keybag_blob = self.manifest_data.get("BackupKeyBag")
                if keybag_blob:
                    self.keybag = BackupKeyBag(keybag_blob)
        except Exception:
            pass

    def verify_and_unlock(self, passphrase):
        """
        Derives master key from passphrase and tests unwrapping class keys.
        Returns (success: bool, message: str)
        """
        if not self.is_encrypted:
            return True, "Backup is not encrypted. Ready for standard extraction."

        if not self.keybag:
            return False, "Corrupted Manifest: BackupKeyBag structure is missing."

        pass_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase

        # 1. Derive Passphrase Key
        try:
            # Check if double-pass derivation (DPIC/DPSL) is used (iOS 10.2+)
            if self.keybag.dpic and self.keybag.dpsl:
                # Scrypt or PBKDF2 Stage 1
                try:
                    kdf1 = Scrypt(salt=self.keybag.dpsl, length=32, n=32768, r=8, p=1, backend=default_backend())
                    pass_key1 = kdf1.derive(pass_bytes)
                except Exception:
                    kdf1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.keybag.dpsl, iterations=self.keybag.dpic, backend=default_backend())
                    pass_key1 = kdf1.derive(pass_bytes)

                # Stage 2: PBKDF2 with SALT and ITER
                kdf2 = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=self.keybag.salt, iterations=self.keybag.iter_count, backend=default_backend())
                master_key = kdf2.derive(pass_key1)
            else:
                # Standard single-stage PBKDF2
                kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=self.keybag.salt, iterations=self.keybag.iter_count, backend=default_backend())
                master_key = kdf.derive(pass_bytes)

            # 2. Test unwrapping class keys
            unwrapped_count = 0
            for cls_id, key_info in self.keybag.class_keys.items():
                wkey = key_info.get("wkey")
                if wkey and len(wkey) == 40: # AES-256 wrapped key (32 bytes payload + 8 bytes IV)
                    try:
                        unwrapped = aes_key_unwrap(master_key, wkey, backend=default_backend())
                        self.unwrapped_keys[cls_id] = unwrapped
                        unwrapped_count += 1
                    except InvalidUnwrap:
                        pass

            if unwrapped_count > 0:
                return True, f"Passphrase verified! Successfully unwrapped {unwrapped_count} Protection Class Keys."
            else:
                return False, "Incorrect backup password. Class keys could not be unwrapped."

        except Exception as e:
            return False, f"Key derivation error: {str(e)}"

    def decrypt_manifest_db(self, output_decrypted_path):
        """
        Decrypts the Manifest.db SQLite database if class keys have been unwrapped.
        """
        manifest_key_blob = self.manifest_data.get("ManifestKey")
        if not manifest_key_blob or not self.unwrapped_keys:
            return False, "ManifestKey blob or unwrapped class keys missing."

        try:
            # Class ID is in the first 4 bytes of ManifestKey blob
            class_id = struct.unpack("<I", manifest_key_blob[:4])[0] if len(manifest_key_blob) >= 4 else 3
            class_key = self.unwrapped_keys.get(class_id, list(self.unwrapped_keys.values())[0])

            # Unwrap file key
            wrapped_file_key = manifest_key_blob[4:] if len(manifest_key_blob) > 4 else manifest_key_blob
            if len(wrapped_file_key) == 40:
                file_key = aes_key_unwrap(class_key, wrapped_file_key, backend=default_backend())
            else:
                file_key = class_key

            # Find encrypted Manifest.db
            enc_manifest_path = os.path.join(self.backup_dir, "Manifest.db")
            if not os.path.exists(enc_manifest_path):
                enc_manifest_path = os.path.join(self.backup_dir, "Snapshot", "Manifest.db")

            if not os.path.exists(enc_manifest_path):
                return False, "Encrypted Manifest.db not found on disk."

            with open(enc_manifest_path, "rb") as f:
                ciphertext = f.read()

            # AES-256-CBC with zero IV
            iv = b"\x00" * 16
            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            if plaintext.startswith(b"SQLite format 3\x00"):
                with open(output_decrypted_path, "wb") as out_f:
                    out_f.write(plaintext)
                return True, "Manifest.db successfully decrypted and verified as valid SQLite 3 database!"
            else:
                return False, "Decryption completed but decrypted payload is not a valid SQLite database."

        except Exception as e:
            return False, f"Decryption failure: {str(e)}"
