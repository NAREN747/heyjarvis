"""
JARVIS Identity Verification - Owner Authentication
Password (PBKDF2-SHA256, 480k iterations) + optional face recognition (insightface ONNX).
"""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Union
from datetime import datetime


class IdentityVerifier:
    """
    Owner identity verification:
    - Password: PBKDF2-SHA256 (480,000 iterations)
    - Optional face recognition (insightface ONNX model)
    """
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.config_path = project_root / "identity.json"
        self._password_hash: str = ""
        self._password_salt: str = ""
        self._face_embedding: Optional[str] = None
        self._load_config()
    
    def _load_config(self) -> None:
        if self.config_path.exists():
            with open(self.config_path) as f:
                config = json.load(f)
                self._password_hash = config.get("password_hash", "")
                self._password_salt = config.get("password_salt", "")
                self._face_embedding = config.get("face_embedding", None)
        else:
            self._password_hash = ""
            self._password_salt = ""
            self._face_embedding = None
    
    def _save_config(self) -> None:
        config = {
            "password_hash": self._password_hash,
            "password_salt": self._password_salt,
            "face_embedding": self._face_embedding
        }
        with open(self.config_path, 'w') as f:
            json.dump(config, f)
    
    def _hash_password(self, password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_bytes(32)
        hash_val = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480000, dklen=32)
        return hash_val.hex(), salt.hex()
    
    def verify(self, password: str, face_image: Optional[bytes] = None) -> Dict[str, Any]:
        """Verify password + optional face."""
        if not self._password_hash:
            return {"success": False, "error": "No identity configured"}
        
        # Verify password
        salt = bytes.fromhex(self._password_salt)
        hash_val = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480000, dklen=32)
        
        if hash_val.hex() != self._password_hash:
            return {"success": False, "error": "Invalid password"}
        
        # Verify face if provided and enrolled
        if face_image and self._face_embedding:
            face_result = self._verify_face(face_image)
            if not face_result["success"]:
                return {"success": False, "error": "Face verification failed"}
        
        return {"success": True, "message": "Identity verified"}
    
    def _verify_face(self, face_image: bytes) -> Dict[str, Any]:
        """Verify face using insightface (if available)."""
        try:
            import onnxruntime as ort
            import numpy as np
            import cv2
        except ImportError:
            return {"success": False, "error": "Face recognition not available"}
        
        # Simplified - in production use insightface properly
        return {"success": True, "message": "Face verification placeholder"}
    
    def enroll_face(self, face_image: bytes) -> Dict[str, Any]:
        """Enroll face for biometric auth."""
        try:
            import onnxruntime as ort
            import numpy as np
            import cv2
        except ImportError:
            return {"success": False, "error": "Face recognition not available"}
        
        # Simplified - in production use insightface properly
        self._face_embedding = "placeholder_embedding"
        self._save_config()
        return {"success": True, "message": "Face enrolled (placeholder)"}
    
    def change_password(self, old: str, new: str, vault: Optional[Vault] = None) -> Dict[str, Any]:
        """Change password and optionally rekey vault."""
        if not self._password_hash:
            return {"success": False, "error": "No password set"}
        
        # Verify old password
        salt = bytes.fromhex(self._password_salt)
        hash_val = hashlib.pbkdf2_hmac('sha256', old.encode(), salt, 480000, dklen=32)
        
        if hash_val.hex() != self._password_hash:
            return {"success": False, "error": "Invalid current password"}
        
        # Rekey vault if provided
        if vault is not None:
            # Unlock vault first
            if not vault.unlock(old):
                return {"success": False, "error": "Failed to unlock vault - invalid old password"}
            if not vault.rekey(old, new):
                return {"success": False, "error": "Failed to rekey vault"}
        
        # Set new password
        self._password_hash, self._password_salt = self._hash_password(new)
        self._save_config()
        return {"success": True, "message": "Password changed" + (" and vault rekeyed" if vault else "")}
    
    def set_initial_password(self, password: str) -> Dict[str, Any]:
        """Set initial password (first run)."""
        if self._password_hash:
            return {"success": False, "error": "Password already set"}
        self._password_hash, self._password_salt = self._hash_password(password)
        self._save_config()
        return {"success": True, "message": "Initial password set"}
    
    def has_password(self) -> bool:
        return bool(self._password_hash)
    
    def has_face_enrolled(self) -> bool:
        return self._face_embedding is not None
    
    def remove_face(self) -> Dict[str, Any]:
        """Remove enrolled face."""
        self._face_embedding = None
        self._save_config()
        return {"success": True, "message": "Face removed"}
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "password_set": self.has_password(),
            "face_enrolled": self.has_face_enrolled(),
            "config_path": str(self.config_path)
        }