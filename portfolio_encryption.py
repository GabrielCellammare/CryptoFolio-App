class PortfolioEncryption:
    """
    Portfolio encryption manager that handles secure encryption and decryption of portfolio items.
    Provides proper type handling and conversion throughout the process.
    """

    def __init__(self, cipher):
        """Initialize with an AESCipher instance for cryptographic operations"""
        self.cipher = cipher

    def encrypt_portfolio_item(self, item, user_id, salt):
        """
        Encrypts sensitive portfolio item fields with comprehensive type handling.

        Args:
            item (dict): Portfolio item to encrypt
            user_id (str): User identifier for encryption
            salt (SecureByteArray): Encryption salt

        Returns:
            dict: Encrypted portfolio item with properly encoded values
        """
        try:
            # Create a copy to avoid modifying the original
            encrypted_item = item.copy()
            sensitive_fields = ['amount', 'purchase_price', 'purchase_date']

            # Process each sensitive field
            for field in sensitive_fields:
                if field in item:
                    # Convert numerical values to strings for encryption
                    field_value = str(item[field])
                    try:
                        # Encrypt the field value
                        encrypted_value = self.cipher.encrypt(
                            field_value,
                            user_id,
                            salt
                        )
                        # Store the base64-encoded encrypted value
                        encrypted_item[field] = encrypted_value.decode('utf-8')
                    except Exception as e:
                        print(f"Error encrypting field {field}: {e}")
                        raise ValueError(
                            f"Encryption failed for field {field}")

            return encrypted_item

        except Exception as e:
            print(f"Portfolio encryption error: {e}")
            raise

    def decrypt_portfolio_item(self, encrypted_item, user_id, salt):
        """
        Decrypts sensitive portfolio item fields with proper type handling.

        Args:
            encrypted_item (dict): Encrypted portfolio item
            user_id (str): User identifier for decryption
            salt (SecureByteArray): Decryption salt

        Returns:
            dict: Decrypted portfolio item with correct data types
        """
        try:
            # Create a copy to avoid modifying the original
            decrypted_item = encrypted_item.copy()
            sensitive_fields = ['amount', 'purchase_price', 'purchase_date']

            for field in sensitive_fields:
                if field in encrypted_item:
                    try:
                        # Get the encrypted value - it's already a string
                        encrypted_value = encrypted_item[field]

                        # Decrypt the value
                        decrypted_value = self.cipher.decrypt(
                            encrypted_value,  # Pass the string directly
                            user_id,
                            salt
                        )

                        # Handle the decrypted value based on field type
                        if field in ['amount', 'purchase_price']:
                            try:
                                # Convert numeric fields to float
                                if isinstance(decrypted_value, str):
                                    decrypted_item[field] = float(
                                        decrypted_value.strip())
                                else:
                                    # If it's already a number, just convert to float
                                    decrypted_item[field] = float(
                                        decrypted_value)
                            except (ValueError, TypeError) as e:
                                print(f"Error converting {
                                      field} to float: {e}")
                                decrypted_item[field] = 0.0
                        else:
                            # For non-numeric fields, ensure we have a string
                            if isinstance(decrypted_value, (bytes, bytearray)):
                                decrypted_item[field] = decrypted_value.decode(
                                    'utf-8')
                            else:
                                decrypted_item[field] = str(decrypted_value)

                    except Exception as field_error:
                        print(f"Error decrypting field {field}: {field_error}")
                        # Set safe default values for failed decryption
                        decrypted_item[field] = 0.0 if field in [
                            'amount', 'purchase_price'] else ''

            return decrypted_item

        except Exception as e:
            print(f"Portfolio decryption error: {e}")
            # Return a safe default object if decryption fails completely
            return {
                'crypto_id': encrypted_item.get('crypto_id', ''),
                'symbol': encrypted_item.get('symbol', ''),
                'amount': 0.0,
                'purchase_price': 0.0,
                'purchase_date': '',
                'id': encrypted_item.get('id', '')
            }
