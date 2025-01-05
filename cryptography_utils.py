"""
Secure Cryptographic Operations Framework
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025
This module implements a comprehensive cryptographic system with a strong focus on
secure memory management, user identity protection, and robust encryption operations.
It provides a defense-in-depth approach to protecting sensitive data through multiple
layers of security controls and careful memory handling.
Core Security Features:

Memory Protection

Secure byte array implementation for sensitive data
Automatic memory zeroing after operations
Protected key material handling
Managed cleanup of cryptographic artifacts


Encryption Operations

AES-256-CBC encryption with PKCS7 padding
Secure initialization vector management
Salt generation and validation
Protected cipher operations


Key Management

Secure key derivation using PBKDF2-HMAC-SHA3-256
User-specific key isolation
Master key protection
Salt management for key derivation


Identity Protection

Secure user ID hashing with HMAC-SHA256
Protected hash verification
Timing attack prevention
Base64 URL-safe encoding



Security Considerations:

All cryptographic operations use constant-time comparisons
Memory containing sensitive data is securely erased
Side-channel attack protections are implemented
Cryptographic error states are safely handled
Key material is protected throughout its lifecycle
User identities are consistently hashed
Encryption operations are isolated per user

Dependencies:

-cryptography: Core cryptographic operations
-secure_byte_array: Protected memory management
-hashlib: Hashing operations
-base64: Secure encoding
-typing: Type safety
-logging: Security event tracking
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json
import logging
import hmac
import hashlib
from typing import Union, Any
from secure_bye_array import SecureByteArray


class CryptographicError(Exception):
    """Custom exception for cryptographic errors."""
    pass


class AESCipher:
    """
    Secure implementation of AES encryption with protected memory management and user ID hashing.

    This class provides:
    - AES-256-CBC encryption with secure key derivation
    - Secure memory management using SecureByteArray
    - Protection against timing and side-channel attacks
    - Automatic PKCS7 padding management
    - Secure user ID hashing with HMAC-SHA256 and base64 encoding

    Attributes:
        BLOCK_SIZE (int): AES block size in bytes
        KEY_LENGTH (int): Key length in bytes
        IV_LENGTH (int): Initialization vector length
        SALT_LENGTH (int): Salt length for key derivation
        KDF_ITERATIONS (int): Number of iterations for key derivation
    """

    # Security constants
    BLOCK_SIZE = 32
    KEY_LENGTH = 32  # AES-256
    IV_LENGTH = 16
    SALT_LENGTH = 32
    KDF_ITERATIONS = 300000  # Increased for greater security

    def __init__(self, master_key: Union[str, bytes, SecureByteArray]):
        """
        Initializes the AES cipher with a master key and optional app secret for user ID hashing.

        Args:
            master_key: Master key as string, bytes, or SecureByteArray

        Raises:
            CryptographicError: If the master key is invalid
        """
        # Logging configuration
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

        try:
            # Conversion and validation of the master key
            if isinstance(master_key, str):
                master_key = master_key.encode()
            self.master_key = self._ensure_secure_bytes(master_key)

            # Verify the minimum key length
            if len(self.master_key.to_bytes()) < self.KEY_LENGTH:
                raise CryptographicError("The master key is too short")

            # Initialize app secret for user ID hashing
            self.app_secret = os.environ.get(
                'HASH_SECRET_KEY')
            self.app_secret = self._ensure_secure_bytes(self.app_secret)

        except Exception as e:
            self.logger.error(f"Error initializing the cipher: {e}")
            raise CryptographicError("Unable to initialize the cipher") from e

    def hash_user_id(self, provider: str, original_id: str) -> str:
        """
        Generates a secure and consistent hash of the user ID using HMAC-SHA256,
        encoded in URL-safe base64 format.

        Args:
            provider: OAuth provider identifier (e.g., 'google', 'github')
            original_id: Original user ID from the provider

        Returns:
            str: Base64 encoded hash, URL-safe without padding

        Raises:
            ValueError: If provider or original_id is empty
            CryptographicError: If hashing fails
        """
        if not provider or not original_id:
            raise ValueError("Provider and user ID are required")

        try:
            # Combine provider and ID in a consistent format
            combined = f"{provider}:{original_id}"

            # Use HMAC-SHA256 to generate a secure hash
            hmac_obj = hmac.new(
                key=self.app_secret.to_bytes(),
                msg=combined.encode(),
                digestmod=hashlib.sha256
            )

            # Convert to URL-safe base64 without padding
            hash_bytes = hmac_obj.digest()  # Get raw bytes instead of hexadecimal
            return base64.urlsafe_b64encode(hash_bytes).rstrip(b'=').decode('ascii')

        except Exception as e:
            self.logger.error(f"Error hashing user ID: {e}")
            raise CryptographicError("Unable to hash user ID") from e

    def verify_user_id_hash(self, provider: str, original_id: str, hashed_id: str) -> bool:
        """
        Verifies if a base64 encoded hash matches a given user ID using constant-time comparison.

        Args:
            provider: OAuth provider identifier
            original_id: Original user ID
            hashed_id: Base64 encoded hash to verify

        Returns:
            bool: True if the hash matches, False otherwise

        Raises:
            CryptographicError: If verification fails
        """
        try:
            # Add padding back if necessary
            padding_length = (4 - len(hashed_id) % 4) % 4
            padded_hash = hashed_id + '=' * padding_length

            # Convert base64 hash back to bytes for comparison
            hash_bytes = base64.urlsafe_b64decode(padded_hash)

            # Generate expected hash and compare in constant time
            expected_hash = self.hash_user_id(provider, original_id)
            expected_padded = expected_hash + '=' * padding_length
            expected_bytes = base64.urlsafe_b64decode(expected_padded)

            return hmac.compare_digest(hash_bytes, expected_bytes)

        except Exception as e:
            self.logger.error(f"Error verifying user ID hash: {e}")
            raise CryptographicError("Unable to verify user ID hash") from e

    def _convert_to_secure_bytes(self, data: Union[str, bytes, SecureByteArray]) -> SecureByteArray:
        """
        Safely converts various input types to SecureByteArray.

        Args:
            data: Input data to convert

        Returns:
            SecureByteArray: Secure byte representation of input
        """
        try:
            if isinstance(data, SecureByteArray):
                return data
            elif isinstance(data, str):
                return SecureByteArray(data.encode())
            elif isinstance(data, bytes):
                return SecureByteArray(data)
            else:
                raise ValueError(f"Unsupported data type: {type(data)}")
        except Exception as e:
            self.logger.error(f"Error converting data: {e}")
            raise CryptographicError("Data conversion failed") from e

    def _ensure_secure_bytes(self, data: Union[bytes, str, SecureByteArray]) -> SecureByteArray:
        """
        Converts data to SecureByteArray securely.

        Args:
            data: Data to convert

        Returns:
            SecureByteArray: Converted data

        Raises:
            ValueError: If the data type is not supported
        """
        try:
            if isinstance(data, SecureByteArray):
                return data
            elif isinstance(data, (bytes, str)):
                return SecureByteArray(data if isinstance(data, bytes) else data.encode())
            else:
                raise ValueError(f"Unsupported data type: {type(data)}")
        except Exception as e:
            self.logger.error(f"Error converting data: {e}")
            raise

    def generate_salt(self) -> SecureByteArray:
        """
        Generates a cryptographically secure salt.

        Returns:
            SecureByteArray: Generated salt
        """
        try:
            return SecureByteArray(os.urandom(self.SALT_LENGTH))
        except Exception as e:
            self.logger.error(f"Error generating salt: {e}")
            raise CryptographicError("Unable to generate salt") from e

    def derive_key(self, user_id: str, salt: Union[bytes, SecureByteArray]) -> SecureByteArray:
        """
        Derives a user-specific key using PBKDF2-HMAC-SHA3-256.

        Args:
            user_id: User identifier
            salt: Salt for key derivation

        Returns:
            SecureByteArray: Derived key

        Raises:
            CryptographicError: If key derivation fails
        """
        key_material = None
        secure_salt = None
        derived_key = None

        try:
            # Secure conversion of salt
            secure_salt = self._ensure_secure_bytes(salt)

            # KDF configuration
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=self.KEY_LENGTH,
                salt=secure_salt.to_bytes(),
                iterations=self.KDF_ITERATIONS,
                backend=default_backend()
            )

            # Secure combination of user_id and master_key
            key_material = SecureByteArray(
                user_id.encode() + self.master_key.to_bytes()
            )

            # Key derivation
            derived_key = SecureByteArray(kdf.derive(key_material.to_bytes()))

            return derived_key

        except Exception as e:
            self.logger.error(f"Error deriving key: {e}")
            raise CryptographicError("Unable to derive key") from e

        finally:
            # Secure memory cleanup
            for secure_data in [key_material, secure_salt]:
                if secure_data is not None and secure_data is not salt:
                    secure_data.secure_zero()

    def encrypt(self, data: Any, user_id: str, salt: Union[bytes, SecureByteArray]) -> bytes:
        """
        Encrypts data using AES-256-CBC with secure memory management.

        Args:
            data: Data to encrypt (can be any JSON serializable type)
            user_id: User identifier
            salt: Salt for key derivation

        Returns:
            bytes: Encrypted data encoded in base64

        Raises:
            CryptographicError: If encryption fails
        """
        key = iv = padded_data = ciphertext = result = None

        try:
            # Data preparation - Convert SecureByteArray to bytes before JSON serialization
            if isinstance(data, SecureByteArray):
                data = data.to_bytes()
            elif not isinstance(data, bytes):
                data = json.dumps(data).encode()

            # IV generation and key derivation
            iv = SecureByteArray(os.urandom(self.IV_LENGTH))
            key = self.derive_key(user_id, salt)

            # Cipher creation
            cipher = Cipher(
                algorithms.AES(key.to_bytes()),
                modes.CBC(iv.to_bytes()),
                backend=default_backend()
            )

            # Data padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = SecureByteArray(
                padder.update(data) + padder.finalize())

            # Encryption
            encryptor = cipher.encryptor()
            ciphertext = SecureByteArray(
                encryptor.update(padded_data.to_bytes()) + encryptor.finalize()
            )

            # Combine IV and ciphertext
            result = SecureByteArray(iv.to_bytes() + ciphertext.to_bytes())

            return base64.b64encode(result.to_bytes())

        except Exception as e:
            self.logger.error(f"Error during encryption: {e}")
            raise CryptographicError("Unable to encrypt data") from e

        finally:
            # Secure memory cleanup
            for secure_data in [key, iv, padded_data, ciphertext, result]:
                if secure_data is not None:
                    secure_data.secure_zero()

    def decrypt(self, encrypted_data: Union[str, bytes, SecureByteArray], user_id: str,
                salt: Union[bytes, SecureByteArray]) -> Any:
        """
        Decrypts data with secure memory management.

        Args:
            encrypted_data: Encrypted data (can be string, bytes, or SecureByteArray)
            user_id: User identifier
            salt: Salt used for encryption

        Returns:
            Any: Decrypted data (JSON object or string)
        """
        key = encrypted = iv = ciphertext = padded_data = decrypted_data = None

        try:
            # Convert input to SecureByteArray if needed
            if isinstance(encrypted_data, (str, bytes)):
                if isinstance(encrypted_data, str):
                    encrypted_data = encrypted_data.encode()
                encrypted_data = SecureByteArray(
                    base64.b64decode(encrypted_data))
            elif isinstance(encrypted_data, SecureByteArray):
                # If it's already a SecureByteArray, decode its contents
                encrypted_data = SecureByteArray(
                    base64.b64decode(encrypted_data.to_bytes())
                )

            # Process IV and ciphertext
            encrypted = encrypted_data
            iv = SecureByteArray(encrypted.to_bytes()[:self.IV_LENGTH])
            ciphertext = SecureByteArray(encrypted.to_bytes()[self.IV_LENGTH:])

            # Key derivation
            key = self.derive_key(user_id, salt)

            # Create and initialize cipher
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

            # Try JSON decoding first
            try:
                return json.loads(decrypted_data.to_bytes())
            except json.JSONDecodeError:
                return decrypted_data.to_bytes().decode()

        except Exception as e:
            self.logger.error(f"Error during decryption: {e}")
            raise CryptographicError("Unable to decrypt data") from e

        finally:
            # Secure cleanup of all temporary secure arrays
            for secure_array in [key, encrypted, iv, ciphertext,
                                 padded_data, decrypted_data]:
                if secure_array is not None:
                    try:
                        secure_array.secure_zero()
                    except Exception as cleanup_error:
                        self.logger.error(
                            f"Error during cleanup: {cleanup_error}")
