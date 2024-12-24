from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json

from secure_bye_array import SecureByteArray


class AESCipher:
    def __init__(self, master_key):
        """Initialize AESCipher with a master key, converting it to SecureByteArray"""
        self.master_key = SecureByteArray(master_key.encode())
        self.BLOCK_SIZE = 32

    def generate_salt(self):
        """Generate a cryptographically secure salt as SecureByteArray"""
        return SecureByteArray(os.urandom(32))

    def _ensure_secure_bytes(self, data):
        """
        Helper method to ensure data is in SecureByteArray format.
        Handles conversion from bytes or SecureByteArray safely.
        """
        if isinstance(data, SecureByteArray):
            return data
        elif isinstance(data, bytes):
            return SecureByteArray(data)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

    def derive_key(self, user_id, salt):
        """
        Derive a user-specific key using PBKDF2.
        Handles type conversion safely.
        """
        try:
            # Convert salt to SecureByteArray if needed
            secure_salt = self._ensure_secure_bytes(salt)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=32,
                salt=secure_salt.to_bytes(),
                iterations=200000,
                backend=default_backend()
            )

            # Combine user_id and master_key securely
            key_material = SecureByteArray(
                user_id.encode() + self.master_key.to_bytes()
            )

            # Derive key
            derived_key = SecureByteArray(
                kdf.derive(key_material.to_bytes())
            )

            return derived_key
        finally:
            if 'key_material' in locals():
                key_material.secure_zero()
            if 'secure_salt' in locals() and secure_salt is not salt:  # Only zero if we created a new object
                secure_salt.secure_zero()

    def encrypt(self, data, user_id, salt):
        """
        Encrypt data using AES-256-CBC with secure memory management.
        """
        key = None
        iv = None
        padded_data = None

        try:
            # Convert input data to JSON bytes if needed
            if not isinstance(data, bytes):
                data = json.dumps(data).encode()

            # Generate IV and derive key
            iv = SecureByteArray(os.urandom(16))
            key = self.derive_key(user_id, self._ensure_secure_bytes(salt))

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key.to_bytes()),
                modes.CBC(iv.to_bytes()),
                backend=default_backend()
            )

            # Apply padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = SecureByteArray(
                padder.update(data) + padder.finalize()
            )

            # Encrypt data
            encryptor = cipher.encryptor()
            ciphertext = SecureByteArray(
                encryptor.update(padded_data.to_bytes()) + encryptor.finalize()
            )

            # Combine IV and ciphertext
            result = SecureByteArray(iv.to_bytes() + ciphertext.to_bytes())
            return base64.b64encode(result.to_bytes())

        finally:
            # Clean up all sensitive data
            for secure_array in [key, iv, padded_data]:
                if secure_array is not None:
                    secure_array.secure_zero()

    def decrypt(self, encrypted_data, user_id, salt):
        """
        Decrypt data with secure memory management.
        Now handles both bytes and SecureByteArray inputs properly.
        """
        key = None
        encrypted = None
        iv = None
        ciphertext = None
        padded_data = None
        decrypted_data = None

        try:
            # Handle potentially encoded input
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode()

            # Decode base64 and convert to SecureByteArray
            encrypted = SecureByteArray(base64.b64decode(encrypted_data))

            # Extract IV and ciphertext
            iv = SecureByteArray(encrypted.to_bytes()[:16])
            ciphertext = SecureByteArray(encrypted.to_bytes()[16:])

            # Derive key with proper salt handling
            key = self.derive_key(user_id, self._ensure_secure_bytes(salt))

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key.to_bytes()),
                modes.CBC(iv.to_bytes()),
                backend=default_backend()
            )

            # Decrypt data
            decryptor = cipher.decryptor()
            padded_data = SecureByteArray(
                decryptor.update(ciphertext.to_bytes()) + decryptor.finalize()
            )

            # Remove padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = SecureByteArray(
                unpadder.update(padded_data.to_bytes()) + unpadder.finalize()
            )

            # Try to decode as JSON or return as string
            try:
                return json.loads(decrypted_data.to_bytes())
            except json.JSONDecodeError:
                return decrypted_data.to_bytes().decode()

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

        finally:
            # Clean up all sensitive data
            secure_arrays = [key, encrypted, iv,
                             ciphertext, padded_data, decrypted_data]
            for secure_array in secure_arrays:
                if secure_array is not None:
                    try:
                        secure_array.secure_zero()
                    except Exception as cleanup_error:
                        print(f"Error during cleanup: {str(cleanup_error)}")
