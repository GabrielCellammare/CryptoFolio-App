import array
import ctypes
import secrets
from typing import Optional, Union
import logging


class MemorySecurityError(Exception):
    """Custom exception for memory security errors."""
    pass


class SecureByteArray:
    """
    Secure implementation for handling sensitive data in memory.

    This class provides:
    - Secure memory management with automatic cleanup
    - Protection against memory dumping
    - Secure overwriting of sensitive data
    - Context management for automatic cleanup

    Attributes:
        _data (array.array): Byte array containing the data
        _address (int): Memory address of the array
        _length (int): Length of the array in bytes
        _is_locked (bool): Indicates if the array is locked for modifications
    """

    # Logging configuration
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    # Security constants
    SECURE_WIPE_PASSES = 3  # Number of passes for secure wiping
    MIN_RANDOM_BYTES = 32   # Minimum number of random bytes for overwriting

    def __init__(self, data: Optional[Union[bytes, bytearray, array.array]] = None):
        """
        Initializes a new SecureByteArray.

        Args:
            data: Initial data to store (optional)

        Raises:
            MemorySecurityError: If secure memory allocation fails
        """
        try:
            if data is not None:
                if not isinstance(data, (bytes, bytearray, array.array)):
                    raise TypeError(
                        "Data must be bytes, bytearray, or array")

                self._data = array.array('B', data)
                self._address = self._data.buffer_info()[0]
                self._length = len(self._data)
            else:
                self._data = array.array('B')
                self._address = self._data.buffer_info()[0]
                self._length = 0

            self._is_locked = False
            self._verify_memory_allocation()

        except Exception as e:
            self.logger.error(
                f"Error initializing SecureByteArray: {e}")
            raise MemorySecurityError(
                "Unable to initialize secure memory") from e

    def _verify_memory_allocation(self) -> None:
        """
        Verifies that memory has been allocated correctly.

        Raises:
            MemorySecurityError: If memory allocation failed
        """
        if self._length > 0 and (self._address is None or self._address == 0):
            raise MemorySecurityError("Memory allocation failed")

    def secure_zero(self) -> None:
        """
        Overwrites memory with random data and then zeros securely.
        Uses multiple passes to make data recovery more difficult.
        """
        if self._length == 0:
            return

        try:
            for _ in range(self.SECURE_WIPE_PASSES):
                # Overwrite with random data
                random_data = secrets.token_bytes(
                    max(self._length, self.MIN_RANDOM_BYTES))
                ctypes.memmove(self._address, random_data, self._length)

            # Final overwrite with zeros
            ctypes.memset(self._address, 0, self._length)

        except Exception as e:
            self.logger.error(
                f"Error during secure memory wiping: {e}")
            raise MemorySecurityError(
                "Unable to securely wipe memory") from e

    def to_bytes(self) -> bytes:
        """
        Returns a secure copy of the data as bytes.

        Returns:
            bytes: Copy of the data

        Raises:
            MemorySecurityError: If the array is locked
        """
        if self._is_locked:
            raise MemorySecurityError(
                "Cannot access data while the array is locked")
        return bytes(self._data)
