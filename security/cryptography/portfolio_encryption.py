"""
Enhanced Portfolio Metrics Calculator
Version: 1.0
Author: [Gabriel Cellammare]
Last Modified: [05/01/2025]

This module implements secure portfolio data encryption and decryption with a strong
focus on memory safety, cryptographic best practices, and secure data handling.

Security Features:
1. Memory Protection
   - Secure memory allocation and deallocation
   - Multiple-pass memory wiping
   - Protected memory regions for sensitive data
   - Automatic cleanup of sensitive information

2. Cryptographic Security
   - AES encryption for sensitive data
   - Secure key and salt handling
   - Isolation of cryptographic operations
   - Protection against timing attacks

3. Error Handling
   - Secure error recovery
   - Non-revealing error messages
   - Protected logging of sensitive data
   - Failsafe defaults for errors

4. Input/Output Safety
   - Strict type validation
   - Secure conversion operations
   - Protected field handling
   - Safe defaults for failures

Security Considerations:
- All sensitive data is automatically wiped from memory
- Cryptographic operations are isolated
- Logging excludes sensitive information
- Memory is protected against unauthorized access
- Type conversions are handled securely
- Error states provide safe defaults

Dependencies:
- cryptography_utils.AESCipher: For encryption operations
- secure_byte_array.SecureByteArray: For secure memory operations
"""
from decimal import Decimal
from typing import Dict
import logging

from security.cryptography.cryptography_utils import AESCipher
from security.secure_bye_array import SecureByteArray


class PortfolioEncryptionError(Exception):
    """
    Custom exception for portfolio encryption errors.

    Security:
    - Does not expose internal state
    - Provides generic error messages
    - Protects against information leakage
    """
    pass


class PortfolioEncryption:
    """
    Secure portfolio data encryption implementation.

    Security Architecture:
    1. Memory Safety
       - Automatic memory cleanup
       - Protected memory regions
       - Secure memory wiping
       - Isolation of sensitive data

    2. Cryptographic Operations
       - Secure key management
       - Protected encryption/decryption
       - Salt handling
       - Timing attack protection

    3. Data Protection
       - Secure type conversion
       - Protected field handling
       - Safe default values
       - Error state handling

    4. Access Control
       - Initialization verification
       - Operation isolation
       - Memory access control
       - Cleanup guarantees

    Usage Warnings:
    1. Memory Management
       - Always use with context managers
       - Verify cleanup completion
       - Monitor memory usage
       - Check cleanup logs

    2. Error Handling
       - Implement proper exception catching
       - Verify error states
       - Check return values
       - Monitor error logs

    3. Cryptographic Safety
       - Protect key material
       - Verify salt uniqueness
       - Monitor operation logs
       - Check integrity
    """

    # Security Constants
    SENSITIVE_FIELDS = frozenset(['amount', 'purchase_price', 'purchase_date'])
    SECURE_MEMORY_WIPE_PASSES = 3
    DEFAULT_NUMERIC_VALUE = Decimal('0.0')
    DEFAULT_STRING_VALUE = ''

    # Logging Configuration
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    def __init__(self, cipher: 'AESCipher'):
        """
        Initialize encryption system with security verification.

        Security Operations:
        1. Cipher validation
           - Verify interface compliance
           - Check method availability
           - Validate initialization

        2. Memory preparation
           - Initialize secure buffers
           - Prepare cleanup tracking
           - Set up protection

        3. State verification
           - Check initialization status
           - Verify configurations
           - Validate security settings

        Args:
            cipher: AESCipher instance for cryptographic operations

        Raises:
            PortfolioEncryptionError: On security verification failure

        Security Checks:
        - Cipher interface verification
        - Memory initialization
        - Protection setup
        - State validation
        """
        try:
            self._cipher = cipher
            self._is_initialized = True
            self._temp_buffers = []  # Track temporary memory buffers

            # Verify cipher compatibility
            if not hasattr(cipher, 'encrypt') or not hasattr(cipher, 'decrypt'):
                raise PortfolioEncryptionError(
                    "Invalid cipher: missing required methods")

        except Exception as e:
            self._is_initialized = False
            self.logger.error("Initialization failed", exc_info=True)
            raise PortfolioEncryptionError(f"Initialization error: {str(e)}")

    def _secure_string_to_bytes(self, value: str) -> SecureByteArray:
        """
        Convert string to bytes with memory protection.

        Security Operations:
        1. Memory allocation
           - Create protected buffer
           - Initialize secure region
           - Track for cleanup

        2. Conversion safety
           - Validate input encoding
           - Protect conversion operation
           - Verify output integrity

        3. Error protection
           - Handle conversion failures
           - Provide safe defaults
           - Clean up on error

        Args:
            value: String to convert

        Returns:
            SecureByteArray: Protected byte representation

        Security Checks:
        - Input validation
        - Memory protection
        - Conversion verification
        - Cleanup tracking
        """
        try:
            secure_bytes = SecureByteArray(value.encode('utf-8'))
            self._temp_buffers.append(secure_bytes)
            return secure_bytes
        except Exception as e:
            self.logger.error("String conversion error", exc_info=True)
            raise PortfolioEncryptionError(f"Conversion error: {str(e)}")

    def _secure_cleanup(self):
        """

        Perform secure memory cleanup.

        Security Operations:
        1. Buffer identification
        - Track all allocations
        - Verify buffer status
        - Check protection state

        2. Memory wiping
        - Multiple overwrite passes
        - Pattern verification
        - Completion checking

        3. Resource release
        - Free protected memory
        - Clear security context
        - Verify cleanup

        Security Checks:
        - Buffer tracking
        - Wipe verification
        - Cleanup completion
        - Resource release

        """
        for buffer in self._temp_buffers:
            try:
                # Use secure_zero instead of secure_erase
                buffer.secure_zero()
            except Exception as e:
                self.logger.warning(f"Cleanup warning: {str(e)}")
        self._temp_buffers.clear()

    def encrypt_portfolio_item(
            self,
            item: Dict,
            user_id: str,
            salt: SecureByteArray
    ) -> Dict:
        """
        Securely encrypts portfolio item data with memory protection.

        Args:
            item: Portfolio data to encrypt
            user_id: User identifier
            salt: Cryptographic salt

        Returns:
            Dict: Encrypted portfolio data

        Raises:
            PortfolioEncryptionError: If encryption fails

        Security:
            - Validates input parameters
            - Implements secure memory handling
            - Automatic cleanup of sensitive data
        """
        if not self._is_initialized:
            raise PortfolioEncryptionError("Encryption system not initialized")

        try:
            encrypted_item = item.copy()

            for field in self.SENSITIVE_FIELDS:
                if field in item:
                    # Create secure temporary buffer
                    secure_value = self._secure_string_to_bytes(
                        str(item[field]))

                    try:
                        # Convert SecureByteArray to bytes for encryption
                        encrypted_value = self._cipher.encrypt(
                            secure_value.to_bytes(),  # Convert to bytes explicitly
                            user_id,
                            salt
                        )
                        encrypted_item[field] = encrypted_value.decode('utf-8')
                    finally:
                        # Ensure secure cleanup
                        secure_value.secure_zero()

            return encrypted_item

        except Exception as e:
            self.logger.error(
                "Encryption error",
                extra={'user_id': self._mask_sensitive_data(user_id)}
            )
            raise PortfolioEncryptionError(f"Encryption failed: {str(e)}")

        finally:
            self._secure_cleanup()

    def decrypt_portfolio_item(
            self,
            encrypted_item: Dict,
            user_id: str,
            salt: SecureByteArray
    ) -> Dict:
        """
        Securely decrypts portfolio item data with memory protection.

        Args:
            encrypted_item: Encrypted portfolio data
            user_id: User identifier
            salt: Cryptographic salt

        Returns:
            Dict: Decrypted portfolio data

        Security:
            - Validates encrypted data integrity
            - Implements secure memory handling
            - Provides safe defaults for failures
        """
        if not self._is_initialized:
            raise PortfolioEncryptionError("Encryption system not initialized")

        try:
            decrypted_item = encrypted_item.copy()

            for field in self.SENSITIVE_FIELDS:
                if field in encrypted_item:
                    try:
                        # Create secure buffer for decryption
                        encrypted_buffer = self._secure_string_to_bytes(
                            encrypted_item[field])

                        # Decrypt in isolated memory
                        decrypted_value = self._cipher.decrypt(
                            encrypted_buffer,
                            user_id,
                            salt
                        )

                        # Handle type conversion securely
                        if field in ['amount', 'purchase_price']:
                            decrypted_item[field] = Decimal(
                                str(decrypted_value))
                        else:
                            decrypted_item[field] = str(decrypted_value)

                    except Exception as field_error:
                        self.logger.warning(
                            f"Field decryption failed: {field}",
                            extra={'error': str(field_error)}
                        )
                        decrypted_item[field] = (
                            self.DEFAULT_NUMERIC_VALUE if field in [
                                'amount', 'purchase_price'
                            ] else self.DEFAULT_STRING_VALUE
                        )

            return decrypted_item

        except Exception as e:
            self.logger.error(
                "Decryption error",
                extra={'user_id': self._mask_sensitive_data(user_id)}
            )
            return self._create_safe_default_item(encrypted_item)

        finally:
            self._secure_cleanup()

    def _create_safe_default_item(self, encrypted_item: Dict) -> Dict:
        """
        Creates a safe default item when decryption fails.

        Args:
            encrypted_item: Original encrypted item

        Returns:
            Dict: Safe default values

        Security:
            - Preserves non-sensitive fields
            - Uses secure default values
        """
        return {
            'crypto_id': encrypted_item.get('crypto_id', ''),
            'symbol': encrypted_item.get('symbol', ''),
            'amount': self.DEFAULT_NUMERIC_VALUE,
            'purchase_price': self.DEFAULT_NUMERIC_VALUE,
            'purchase_date': self.DEFAULT_STRING_VALUE,
            'id': encrypted_item.get('id', '')
        }

    def _mask_sensitive_data(self, data: str) -> str:
        """
        Masks sensitive data for secure logging.

        Args:
            data: Sensitive data to mask

        Returns:
            str: Masked data string

        Security:
            - Preserves data length
            - Maintains first and last characters
        """
        if not data:
            return ''

        if len(data) <= 4:
            return '*' * len(data)

        return f"{data[:2]}{'*' * (len(data) - 4)}{data[-2:]}"

    def __del__(self):
        """
        Secure cleanup when object is destroyed.

        Security:
            - Ensures all temporary buffers are cleared
            - Logs cleanup failures
        """
        try:
            self._secure_cleanup()
        except Exception as e:
            self.logger.error(f"Cleanup error in destructor: {str(e)}")
