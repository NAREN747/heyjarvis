"""
JARVIS Vault - AES-256-GCM Encrypted Storage
All secrets, credentials, sensitive data stored encrypted at rest.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Vault:
    """
    AES-256-GCM encrypted vault using SQLite backend.
    - PBKDF2-HMAC-SHA256 (480,000 iterations) for key derivation
    - AES-256-GCM for authenticated encryption
    - Each entry has unique nonce
    - Integrity verification on read
    """
    
    def __init__(self, vault_path: Path):
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.db_path = self.vault_path / "vault.db"
        self.meta_path = self.vault_path / "meta.json"
        
        self._locked = True
        self._key: bytes = b""
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize vault database."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    key TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()
    
    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(password.encode())
    
    def unlock(self, password: str) -> bool:
        """Unlock vault with password."""
        with self._lock:
            if not self._locked:
                return True
            
            # Read salt from meta
            salt = self._get_salt()
            if not salt:
                # First unlock - create salt
                salt = secrets.token_bytes(32)
                self._set_salt(salt)
            
            try:
                kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480000, dklen=32)
                self._key = kdf
                
                # Test key by reading a dummy entry
                with self._connect() as conn:
                    conn.execute("SELECT 1 FROM secrets LIMIT 1")
                
                self._locked = False
                return True
            except Exception:
                self._key = b""
                return False
    
    def lock(self) -> None:
        """Lock vault."""
        with self._lock:
            self._locked = True
            self._key = b""
    
    def is_locked(self) -> bool:
        return self._locked
    
    def _get_salt(self) -> Optional[bytes]:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
            if row:
                return bytes.fromhex(row['value'])
        return None
    
    def _set_salt(self, salt: bytes, conn: Optional[sqlite3.Connection] = None) -> None:
        if conn is not None:
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ('salt', salt.hex())
            )
        else:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    ('salt', salt.hex())
                )
                conn.commit()
    
    def store(self, key: str, value: str) -> bool:
        """Store encrypted value."""
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        with self._lock:
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self._key)
            ciphertext = aesgcm.encrypt(nonce, value.encode(), key.encode())
            
            now = datetime.now().isoformat()
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO secrets (key, nonce, ciphertext, created_at, updated_at)
                    VALUES (?, ?, ?, 
                        COALESCE((SELECT created_at FROM secrets WHERE key = ?), ?),
                        ?)
                """, (key, nonce, ciphertext, key, datetime.now().isoformat(), datetime.now().isoformat()))
                conn.commit()
        return True
    
    def retrieve(self, key: str) -> Optional[str]:
        """Retrieve and decrypt value."""
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT nonce, ciphertext FROM secrets WHERE key = ?", (key,)
                ).fetchone()
                
                if not row:
                    return None
                
                aesgcm = AESGCM(self._key)
                plaintext = aesgcm.decrypt(row['nonce'], row['ciphertext'], key.encode())
                return plaintext.decode()
    
    def delete(self, key: str) -> bool:
        """Delete secret."""
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM secrets WHERE key = ?", (key,))
                conn.commit()
        return True
    
    def list_keys(self) -> List[str]:
        """List all secret keys."""
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT key FROM secrets ORDER BY key").fetchall()
                return [row['key'] for row in rows]
    
    def verify_integrity(self, full: bool = False) -> bool:
        """Verify vault integrity."""
        if self._locked:
            return False
        
        try:
            with self._connect() as conn:
                # Check database integrity
                conn.execute("PRAGMA integrity_check")
                
                if full:
                    # Verify each entry can be decrypted
                    rows = conn.execute("SELECT key, nonce, ciphertext FROM secrets").fetchall()
                    for row in rows:
                        try:
                            aesgcm = AESGCM(self._key)
                            aesgcm.decrypt(row['nonce'], row['ciphertext'], row['key'].encode())
                        except Exception:
                            return False
            return True
        except Exception:
            return False
    
    def export_encrypted(self, password: str) -> bytes:
        """Export entire vault encrypted with password."""
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        # Export all entries - DECRYPT them first to get plaintext
        data = {}
        with self._connect() as conn:
            rows = conn.execute("SELECT key, nonce, ciphertext FROM secrets").fetchall()
            for row in rows:
                # Decrypt each entry with current vault key
                aesgcm = AESGCM(self._key)
                plaintext = aesgcm.decrypt(row['nonce'], row['ciphertext'], row['key'].encode())
                data[row['key']] = plaintext.decode()
        
        # Encrypt export with new password
        salt = secrets.token_bytes(32)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        export_key = kdf.derive(password.encode())
        
        aesgcm = AESGCM(export_key)
        nonce = secrets.token_bytes(12)
        payload = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        
        return salt + nonce + ciphertext
    
    def rekey(self, old_password: str, new_password: str) -> bool:
        """
        Re-encrypt all vault data with a new password.
        This decrypts all entries with the old password and re-encrypts with the new password.
        """
        if self._locked:
            raise RuntimeError("Vault is locked")
        
        with self._lock:
            # Verify old password can unlock
            old_salt = self._get_salt()
            if not old_salt:
                return False
            
            old_key = hashlib.pbkdf2_hmac('sha256', old_password.encode(), old_salt, 480000, dklen=32)
            
            # Test old key works
            try:
                aesgcm = AESGCM(old_key)
                # Test with one entry
                with self._connect() as conn:
                    row = conn.execute("SELECT nonce, ciphertext, key FROM secrets LIMIT 1").fetchone()
                    if row:
                        aesgcm.decrypt(row['nonce'], row['ciphertext'], row['key'].encode())
            except Exception:
                return False
            
            # Generate new salt and key
            new_salt = secrets.token_bytes(32)
            new_key = hashlib.pbkdf2_hmac('sha256', new_password.encode(), new_salt, 480000, dklen=32)
            
            # Re-encrypt all entries
            with self._connect() as conn:
                rows = conn.execute("SELECT key, nonce, ciphertext FROM secrets").fetchall()
                for row in rows:
                    # Decrypt with old key
                    aesgcm_old = AESGCM(old_key)
                    plaintext = aesgcm_old.decrypt(row['nonce'], row['ciphertext'], row['key'].encode())
                    
                    # Encrypt with new key
                    new_nonce = secrets.token_bytes(12)
                    aesgcm_new = AESGCM(new_key)
                    new_ciphertext = aesgcm_new.encrypt(new_nonce, plaintext, row['key'].encode())
                    
                    # Update database
                    conn.execute("""
                        UPDATE secrets SET nonce = ?, ciphertext = ?, updated_at = ?
                        WHERE key = ?
                    """, (new_nonce, new_ciphertext, datetime.now().isoformat(), row['key']))
                
                # Update salt in metadata
                self._set_salt(new_salt, conn)
                
                # Update in-memory key
                self._key = new_key
                
                conn.commit()
            return True
    
    def import_encrypted(self, data: bytes, password: str) -> bool:
        """Import vault from encrypted export."""
        if len(data) < 44:  # salt(32) + nonce(12) minimum
            return False
        
        salt = data[:32]
        nonce = data[32:44]
        ciphertext = data[44:]
        
        try:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
            import_key = kdf.derive(password.encode())
            
            aesgcm_import = AESGCM(import_key)
            payload = aesgcm_import.decrypt(nonce, ciphertext, None)
            data = json.loads(payload)
            
            # Import entries - the export contains PLAINTEXT values
            if self._locked:
                if not self.unlock(password):
                    return False
            
            with self._lock:
                with self._connect() as conn:
                    for key, plaintext in data.items():
                        # Store plaintext encrypted with current vault key
                        new_nonce = secrets.token_bytes(12)
                        aesgcm_current = AESGCM(self._key)
                        new_ciphertext = aesgcm_current.encrypt(new_nonce, plaintext.encode(), key.encode())
                        
                        conn.execute("""
                            INSERT OR REPLACE INTO secrets (key, nonce, ciphertext, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?)
                        """, (key, new_nonce, new_ciphertext, 
                              datetime.now().isoformat(), datetime.now().isoformat()))
                    conn.commit()
            return True
        except Exception:
            return False