from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json
import logging
from typing import Union, Any
from secure_bye_array import SecureByteArray


class CryptographicError(Exception):
    """Custom exception for cryptographic errors."""
    pass


class AESCipher:
    """
    Secure implementation of AES encryption with protected memory management.

    This class provides:
    - AES-256-CBC encryption with secure key derivation
    - Secure memory management using SecureByteArray
    - Protection against timing and side-channel attacks
    - Automatic PKCS7 padding management

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
        Initializes the AES cipher with a master key.

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

        except Exception as e:
            self.logger.error(
                f"Error initializing the cipher: {e}")
            raise CryptographicError(
                "Unable to initialize the cipher") from e

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
            # Data preparation
            if not isinstance(data, bytes):
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

    def decrypt(self, encrypted_data: Union[str, bytes], user_id: str,
                salt: Union[bytes, SecureByteArray]) -> Any:
        """
        Decrypts data with secure memory management.

        Args:
            encrypted_data: Encrypted data encoded in base64
            user_id: User identifier
            salt: Salt used for encryption

        Returns:
            Any: Decrypted data (JSON object or string)

        Raises:
            CryptographicError: If decryption fails
        """
        key = encrypted = iv = ciphertext = padded_data = decrypted_data = None

        try:
            # Preparation of encrypted data
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode()

            # Base64 decoding and separation of IV/ciphertext
            encrypted = SecureByteArray(base64.b64decode(encrypted_data))
            iv = SecureByteArray(encrypted.to_bytes()[:self.IV_LENGTH])
            ciphertext = SecureByteArray(encrypted.to_bytes()[self.IV_LENGTH:])

            # Key derivation
            key = self.derive_key(user_id, salt)

            # Cipher creation
            cipher = Cipher(
                algorithms.AES(key.to_bytes()),
                modes.CBC(iv.to_bytes()),
                backend=default_backend()
            )

            # Decryption
            decryptor = cipher.decryptor()
            padded_data = SecureByteArray(
                decryptor.update(ciphertext.to_bytes()) + decryptor.finalize()
            )

            # Padding removal
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = SecureByteArray(
                unpadder.update(padded_data.to_bytes()) + unpadder.finalize()
            )

            # JSON or string decoding
            try:
                return json.loads(decrypted_data.to_bytes())
            except json.JSONDecodeError:
                return decrypted_data.to_bytes().decode()

        except Exception as e:
            self.logger.error(f"Error during decryption: {e}")
            raise CryptographicError("Unable to decrypt data") from e

        finally:
            # Secure memory cleanup
            secure_arrays = [key, encrypted, iv,
                             ciphertext, padded_data, decrypted_data]
            for secure_array in secure_arrays:
                if secure_array is not None:
                    try:
                        secure_array.secure_zero()
                    except Exception as cleanup_error:
                        self.logger.error(
                            f"Error during cleanup: {cleanup_error}")
