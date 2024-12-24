from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json
import array
import ctypes
import secrets


class SecureByteArray:
    """
    Classe wrapper per gestire array di byte in modo sicuro,
    garantendo la pulizia della memoria dopo l'uso.
    """

    def __init__(self, data=None):
        self._data = array.array('B', data if data else [])
        self._address = self._data.buffer_info()[0]
        self._length = len(self._data)

    def __del__(self):
        # Sovrascriviamo la memoria con dati casuali prima di deallocare
        self.secure_zero()

    def secure_zero(self):
        """Sovrascrive la memoria con valori casuali e poi con zeri"""
        if self._length > 0:
            # Prima sovrascriviamo con dati casuali
            random_data = secrets.token_bytes(self._length)
            ctypes.memmove(self._address, random_data, self._length)
            # Poi azzeriamo
            ctypes.memset(self._address, 0, self._length)

    def to_bytes(self):
        """Restituisce una copia dei dati come bytes"""
        return bytes(self._data)

    @classmethod
    def from_bytes(cls, data):
        """Crea un SecureByteArray da bytes"""
        return cls(data)
