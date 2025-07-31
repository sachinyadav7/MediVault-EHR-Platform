"""
Enhanced encryption utilities for MediVault
Provides AES-256 encryption for medical files and sensitive data
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets
import hashlib
import json
from datetime import datetime, timedelta

class EncryptionManager:
    """Advanced encryption manager for medical data"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key_from_password(self, password_hash, salt):
        """
        Derive encryption key from password hash and salt using PBKDF2
        """
        try:
            # Convert base64 salt back to bytes
            if isinstance(salt, str):
                salt_bytes = base64.b64decode(salt.encode('utf-8'))
            else:
                salt_bytes = salt
            
            # Use password hash as the password for key derivation
            password_bytes = password_hash.encode('utf-8') if isinstance(password_hash, str) else password_hash
            
            # Create key derivation function with high iteration count
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=200000,  # High iteration count for security
                backend=self.backend
            )
            
            # Derive key and encode for Fernet
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            return key
            
        except Exception as e:
            raise Exception(f"Error deriving encryption key: {str(e)}")
    
    def encrypt_file(self, data, key):
        """
        Encrypt file data using Fernet (AES-256)
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            fernet = Fernet(key)
            
            # Add metadata to encrypted data
            metadata = {
                'encrypted_at': datetime.utcnow().isoformat(),
                'algorithm': 'AES-256-CBC',
                'key_derivation': 'PBKDF2-SHA256',
                'iterations': 200000
            }
            
            # Combine metadata and data
            combined_data = {
                'metadata': metadata,
                'data': base64.b64encode(data).decode('utf-8')
            }
            
            json_data = json.dumps(combined_data).encode('utf-8')
            encrypted_data = fernet.encrypt(json_data)
            
            return encrypted_data
            
        except Exception as e:
            raise Exception(f"Error encrypting file: {str(e)}")
    
    def decrypt_file(self, encrypted_data, key):
        """
        Decrypt file data using Fernet (AES-256)
        """
        try:
            fernet = Fernet(key)
            decrypted_json = fernet.decrypt(encrypted_data)
            
            # Parse combined data
            combined_data = json.loads(decrypted_json.decode('utf-8'))
            
            # Extract original data
            original_data = base64.b64decode(combined_data['data'])
            
            return original_data
            
        except Exception as e:
            raise Exception(f"Error decrypting file: {str(e)}")
    
    def generate_secure_key(self):
        """
        Generate a new random encryption key
        """
        return Fernet.generate_key()
    
    def generate_salt(self, size=32):
        """
        Generate a cryptographically secure salt
        """
        return base64.b64encode(secrets.token_bytes(size)).decode('utf-8')
    
    def hash_password_secure(self, password, salt=None):
        """
        Create a secure password hash using SHA-256 with salt
        """
        if salt is None:
            salt = self.generate_salt()
        
        # Combine password and salt
        combined = f"{password}{salt}".encode('utf-8')
        
        # Create hash
        hash_obj = hashlib.sha256()
        hash_obj.update(combined)
        
        return {
            'hash': hash_obj.hexdigest(),
            'salt': salt
        }
    
    def verify_password(self, password, stored_hash, salt):
        """
        Verify password against stored hash
        """
        try:
            new_hash = self.hash_password_secure(password, salt)
            return new_hash['hash'] == stored_hash
        except Exception:
            return False

class AsymmetricEncryption:
    """
    RSA asymmetric encryption for secure key exchange
    """
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate RSA key pair for asymmetric encryption
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def serialize_private_key(self, private_key, password=None):
        """
        Serialize private key to PEM format
        """
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        return pem
    
    def serialize_public_key(self, public_key):
        """
        Serialize public key to PEM format
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem
    
    def encrypt_with_public_key(self, data, public_key):
        """
        Encrypt data with RSA public key
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    
    def decrypt_with_private_key(self, encrypted_data, private_key):
        """
        Decrypt data with RSA private key
        """
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted

class SecureTokenManager:
    """
    Secure token generation and management
    """
    
    @staticmethod
    def generate_access_token(length=32):
        """
        Generate secure access token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_emergency_code(length=8):
        """
        Generate emergency access code
        """
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def generate_session_id():
        """
        Generate secure session ID
        """
        return secrets.token_hex(32)
    
    @staticmethod
    def generate_file_hash(file_content):
        """
        Generate SHA-256 hash of file content for integrity checking
        """
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        
        return hashlib.sha256(file_content).hexdigest()

class DataIntegrity:
    """
    Data integrity and verification utilities
    """
    
    @staticmethod
    def create_checksum(data):
        """
        Create MD5 checksum for data integrity
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def verify_checksum(data, expected_checksum):
        """
        Verify data integrity using checksum
        """
        actual_checksum = DataIntegrity.create_checksum(data)
        return actual_checksum == expected_checksum
    
    @staticmethod
    def create_digital_signature(data, private_key):
        """
        Create digital signature for data authenticity
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    @staticmethod
    def verify_digital_signature(data, signature, public_key):
        """
        Verify digital signature for data authenticity
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# Initialize global encryption manager
encryption_manager = EncryptionManager()

# Export commonly used functions for backward compatibility
def derive_key_from_password(password_hash, salt):
    """Backward compatibility wrapper"""
    return encryption_manager.derive_key_from_password(password_hash, salt)

def encrypt_file(data, key):
    """Backward compatibility wrapper"""
    return encryption_manager.encrypt_file(data, key)

def decrypt_file(encrypted_data, key):
    """Backward compatibility wrapper"""
    return encryption_manager.decrypt_file(encrypted_data, key)

def generate_secure_token(length=32):
    """Generate secure token"""
    return SecureTokenManager.generate_access_token(length)

def generate_emergency_code():
    """Generate emergency access code"""
    return SecureTokenManager.generate_emergency_code()

# Security utilities for common operations
class SecurityUtils:
    """
    Common security utilities
    """
    
    @staticmethod
    def is_safe_filename(filename):
        """
        Check if filename is safe for storage
        """
        dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        return not any(char in filename for char in dangerous_chars)
    
    @staticmethod
    def sanitize_filename(filename):
        """
        Sanitize filename for safe storage
        """
        import re
        # Remove dangerous characters
        filename = re.sub(r'[^\w\s-.]', '', filename)
        # Replace spaces with underscores
        filename = re.sub(r'[-\s]+', '_', filename)
        return filename
    
    @staticmethod
    def validate_file_type(filename, allowed_extensions):
        """
        Validate file type against allowed extensions
        """
        if '.' not in filename:
            return False
        
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in allowed_extensions
    
    @staticmethod
    def get_file_size_mb(file_content):
        """
        Get file size in MB
        """
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        
        return len(file_content) / (1024 * 1024)

# Export security utilities
security_utils = SecurityUtils()