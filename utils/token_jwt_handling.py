import base64
from datetime import datetime, timedelta, timezone
from functools import wraps
import logging
import os
from flask import request
import jwt
from typing import Dict, Any, Optional, Tuple
from firebase_admin import firestore


class AuthError(Exception):
    """Custom exception for authentication errors"""

    def __init__(self, error: str, status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


class TokenJWTHandling:
    def __init__(self, db, cipher):
        """
        Initialize TokenJWTHandling with database and cipher instances

        Args:
            db: Firebase database instance
            cipher: AESCipher instance for encryption/decryption
        """
        self.__db = db
        self.__MAX_DAILY_TOKENS = 2
        # Configuration
        self.__JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
        self.__JWT_TOKEN_EXPIRATION = timedelta(days=7)
        self.__JWT_REQUEST_COOLDOWN = timedelta(hours=12)
        self.__cipher = cipher

    def get_user_token_history(self, user_id: str, since: datetime) -> list:
        """
        Retrieves the token generation history for a specific user from Firestore.

        Args:
            user_id (str): The unique identifier of the user whose token history is being retrieved.
            since (datetime): The starting datetime point from which to retrieve the history.

        Returns:
            List[Dict]: A list of dictionaries containing token history records.
        """
        token_docs = (self.__db.collection('user_tokens')
                      .where('user_id', '==', user_id)
                      .where('created_at', '>=', since)
                      # Only consider active tokens
                      .order_by('created_at', direction='DESCENDING')
                      .stream())

        return [doc.to_dict() for doc in token_docs]

    def check_token_request_eligibility(self, user_id: str) -> Tuple[bool, Optional[datetime], Optional[str]]:
        """
        Determines if a user is eligible to request a new token based on daily limits and cooldown periods.

        Args:
            user_id (str): The unique identifier of the user requesting a token.

        Returns:
            Tuple[bool, Optional[datetime], Optional[str]]: Eligibility info, next eligible time, and error message
        """
        current_time = datetime.now(timezone.utc)
        day_start = current_time.replace(
            hour=0, minute=0, second=0, microsecond=0)

        # Get active tokens from database
        token_history = self.get_user_token_history(user_id, day_start)

        if not token_history:
            return True, None, None

        # Check daily token limit
        if len(token_history) >= self.__MAX_DAILY_TOKENS:
            next_day = day_start + timedelta(days=1)
            return False, next_day, f'Daily limit reached. Next eligible: {next_day.isoformat()}'

        # Check cooldown period
        latest_token = token_history[0]
        last_request_time = latest_token['created_at']
        next_eligible_time = last_request_time + self.__JWT_REQUEST_COOLDOWN

        if current_time < next_eligible_time:
            return False, next_eligible_time, f'Please wait until {next_eligible_time.isoformat()}'

        return True, None, None

    def _encrypt_token_data(self, token_data: dict, user_id: str, salt: bytes) -> dict:
        """
        Encrypt sensitive token data before storing in Firebase.

        Args:
            token_data: Token data to encrypt
            user_id: User identifier for encryption
            salt: Salt for key derivation

        Returns:
            dict: Token data with encrypted fields
        """
        encrypted_data = token_data.copy()
        # Added expires_at to sensitive fields for encryption
        sensitive_fields = ['access_token', 'refresh_token', 'expires_at']

        try:
            for field in sensitive_fields:
                if field in token_data:
                    encrypted_value = self.__cipher.encrypt(
                        token_data[field],
                        user_id,
                        salt
                    )
                    encrypted_data[field] = encrypted_value.decode('utf-8')

            return encrypted_data

        except Exception as e:
            logging.error(f"Token encryption error: {str(e)}")
            raise AuthError("Token encryption failed", 500)

    def _decrypt_token_data(self, encrypted_data: dict, user_id: str, salt: bytes) -> dict:
        """
        Decrypt token data retrieved from Firebase.

        Args:
            encrypted_data: Encrypted token data
            user_id: User identifier for decryption
            salt: Salt for key derivation

        Returns:
            dict: Decrypted token data
        """
        decrypted_data = encrypted_data.copy()
        sensitive_fields = ['access_token', 'refresh_token', 'expires_at']

        try:
            for field in sensitive_fields:
                if field in encrypted_data:
                    decrypted_value = self.__cipher.decrypt(
                        encrypted_data[field],
                        user_id,
                        salt
                    )
                    if isinstance(decrypted_value, bytes):
                        decrypted_value = decrypted_value.decode('utf-8')
                    decrypted_data[field] = decrypted_value

            return decrypted_data

        except Exception as e:
            logging.error(f"Token decryption error: {str(e)}")
            raise AuthError("Token decryption failed", 500)

    def _store_encrypted_token(self, user_id: str, token_data: dict) -> None:
        """
        Store encrypted token data in Firebase.

        Args:
            user_id: User identifier
            token_data: Token data to store
        """
        try:
            # Get user's salt from security collection
            security_ref = self.__db.collection(
                'user_security').document(user_id)
            security_data = security_ref.get()

            encoded_salt = security_data.to_dict()['salt']
            salt_bytes = base64.b64decode(encoded_salt)

            # Encrypt token data
            encrypted_data = self._encrypt_token_data(
                token_data, user_id, salt_bytes)

            # Store in Firebase
            self.__db.collection('user_tokens').add({
                'user_id': user_id,
                **encrypted_data,
                'created_at': firestore.SERVER_TIMESTAMP,
                'status': 'active'
            })

        except Exception as e:
            logging.error(f"Token storage error: {str(e)}")
            raise AuthError("Failed to store token", 500)

    def expire_previous_tokens(self, user_id: str) -> None:
        """
        Expires all active tokens for a given user to ensure only one token is active at a time.

        Args:
            user_id (str): The unique identifier of the user whose tokens should be expired.
        """
        try:
            current_time = datetime.now(timezone.utc)

            # Get user's salt from security collection
            security_ref = self.__db.collection(
                'user_security').document(user_id)
            security_data = security_ref.get()

            if not security_data.exists:
                return None

            encoded_salt = security_data.to_dict()['salt']
            salt_bytes = base64.b64decode(encoded_salt)

            # Query for active tokens - we'll check expiration after decryption
            active_tokens = (self.__db.collection('user_tokens')
                             .where('user_id', '==', user_id)
                             .where('status', '==', 'active')
                             .stream())

            tokens_to_expire = []
            # Decrypt and check expiration for each token
            for token_doc in active_tokens:
                encrypted_token = token_doc.to_dict()
                decrypted_token = self._decrypt_token_data(
                    encrypted_token, user_id, salt_bytes)

                # Check if token is expired based on decrypted expiration date
                if current_time > datetime.fromisoformat(decrypted_token['expires_at']):
                    tokens_to_expire.append((token_doc.id, decrypted_token))

            # Create a batch operation for efficiency
            batch = self.__db.batch()

            expired_count = 0
            # Use the pre-filtered tokens_to_expire list
            for token_id, decrypted_token in tokens_to_expire:
                doc_ref = self.__db.collection(
                    'user_tokens').document(token_id)

                # Update token status to expired
                batch.update(doc_ref, {
                    'status': 'expired',
                    'expired_at': current_time,
                    'expired_reason': 'new_token_generated'
                })

                expired_count += 1

            # Only commit if there are tokens to expire
            if expired_count > 0:
                batch.commit()

                # Create an audit log entry for the mass expiration
                self.__db.collection('audit_logs').add({
                    'user_id': user_id,
                    'action': 'expire_tokens',
                    'tokens_expired': expired_count,
                    'reason': 'new_token_generated',
                    'timestamp': current_time,
                    'ip_address': request.remote_addr,
                    'user_agent': request.user_agent.string
                })

        except Exception as e:
            logging.error(f"Error expiring tokens: {str(e)}")
            raise AuthError("Failed to expire tokens", 500)

    def get_active_token(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the most recent active token for a specified user.

        Args:
            user_id (str): The unique identifier of the user.

        Returns:
            Optional[Dict[str, Any]]: Dictionary containing token information if an active token exists
        """
        try:
            current_time = datetime.now(timezone.utc)

            # Get user's salt
            security_ref = self.__db.collection(
                'user_security').document(user_id)
            security_data = security_ref.get()

            if not security_data.exists:
                return None

            encoded_salt = security_data.to_dict()['salt']
            salt_bytes = base64.b64decode(encoded_salt)

            # Query for active tokens
            tokens = (self.__db.collection('user_tokens')
                      .where('user_id', '==', user_id)
                      .where('status', '==', 'active')
                      .order_by('expires_at', direction='DESCENDING')
                      .limit(1)
                      .stream())

            token_list = list(tokens)
            if not token_list:
                return None

            # Decrypt token data before returning
            encrypted_token = token_list[0].to_dict()
            decrypted_token = self._decrypt_token_data(
                encrypted_token, user_id, salt_bytes)

            # Check if token is expired based on decrypted expiration date
            if current_time > datetime.fromisoformat(decrypted_token['expires_at']):
                return None

            return decrypted_token

        except Exception as e:
            logging.error(f"Error retrieving active token: {str(e)}")
            return None

    def generate_tokens(self, user_id: str) -> Dict[str, Any]:
        """
        Generate new JWT token with encryption and storage.

        Args:
            user_id (str): User identifier

        Returns:
            Dict[str, Any]: Generated token information
        """
        try:
            # Check if user is eligible for a new token
            is_eligible, next_eligible_time, error_message = self.check_token_request_eligibility(
                user_id)

            if not is_eligible:
                raise AuthError(error_message, 429)

            # Expire all previous active tokens before generating a new one
            self.expire_previous_tokens(user_id)

            current_time = datetime.now(timezone.utc)
            token_exp = current_time + self.__JWT_TOKEN_EXPIRATION

            # Generate new JWT with creation timestamp
            access_token = jwt.encode({
                'exp': token_exp,
                'iat': current_time,
                'created_at': current_time.isoformat(),
                'user_id': user_id,
                'type': 'access'
            }, self.__JWT_SECRET_KEY, algorithm='HS256')

            # Enhanced token document
            token_data = {
                'user_id': user_id,
                'access_token': access_token,
                'created_at': current_time,
                'expires_at': token_exp.isoformat(),
                'status': 'active',
                'device_info': {
                    'ip_address': request.remote_addr,
                    'user_agent': request.user_agent.string
                }
            }

            # Store encrypted token
            self._store_encrypted_token(user_id, token_data)

            # Calculate next token request time
            next_token_time = current_time + self.__JWT_REQUEST_COOLDOWN

            return {
                'access_token': access_token,
                'token_created_at': current_time.isoformat(),
                'expires_in': int(self.__JWT_TOKEN_EXPIRATION.total_seconds()),
                'expires_at': token_exp.isoformat(),
                'next_token_request': next_token_time.isoformat()
            }

        except Exception as e:
            logging.error(f"Token generation error: {str(e)}")
            raise AuthError("Failed to generate tokens", 500)

    def get_token_creation_time(self, token: str) -> Optional[datetime]:
        """
        Retrieve token creation time from JWT claims
        """
        try:
            payload = jwt.decode(
                token, self.__JWT_SECRET_KEY, algorithms=['HS256'])
            created_at = payload.get('created_at')
            return datetime.fromisoformat(created_at) if created_at else None
        except (jwt.InvalidTokenError, ValueError):
            return None

    def jwt_required(self, f):
        """
        Decorator that verifies JWT tokens and ensures proper authentication for protected routes.
        Handles both the decrypted token from the user and the encrypted version in the database.

        Args:
            f (Callable): The function to be decorated.

        Returns:
            Callable: The decorated function with JWT verification.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')

            if not auth_header or not auth_header.startswith('Bearer '):
                raise AuthError('Missing or invalid token format', 401)

            # This is the decrypted token from the user
            token = auth_header.split(' ')[1]

            try:
                # First verify JWT signature and expiration
                payload = jwt.decode(
                    token, self.__JWT_SECRET_KEY, algorithms=['HS256'])

                # Verify token type
                if payload.get('type') != 'access':
                    raise AuthError('Invalid token type', 401)

                user_id = payload['user_id']

                # Get user's salt for encryption comparison
                security_ref = self.__db.collection(
                    'user_security').document(user_id)
                security_data = security_ref.get()

                if not security_data.exists:
                    raise AuthError('Security data not found', 401)

                encoded_salt = security_data.to_dict()['salt']
                salt_bytes = base64.b64decode(encoded_salt)

                # Find active tokens for this user
                token_docs = (self.__db.collection('user_tokens')
                              .where('user_id', '==', user_id)
                              .where('status', '==', 'active')
                              .limit(1)
                              .get())

                if not token_docs:
                    raise AuthError('No active tokens found', 401)

                token_doc = list(token_docs)[0].to_dict()

                # Decrypt stored token to compare with provided token
                decrypted_token = self._decrypt_token_data(
                    token_doc, user_id, salt_bytes)

                # Compare the decrypted stored token with the provided token
                if decrypted_token.get('access_token') != token:
                    raise AuthError('Token not found in database', 401)

                # Check expiration using decrypted expiry
                expiry = datetime.fromisoformat(
                    decrypted_token.get('expires_at'))
                if not expiry or datetime.now(timezone.utc) > expiry:
                    # Update token status to expired
                    doc_ref = list(token_docs)[0].reference
                    doc_ref.update({'status': 'expired'})
                    raise AuthError('Token expired', 401)

                # Add user_id to request
                request.user_id = user_id

                return f(*args, **kwargs)

            except jwt.ExpiredSignatureError:
                raise AuthError('Token expired', 401)
            except jwt.InvalidTokenError:
                raise AuthError('Invalid token', 401)
            except Exception as e:
                # Log error securely
                self.__db.collection('error_logs').add({
                    'error_type': 'token_verification_error',
                    'error_message': str(e),
                    'timestamp': datetime.now(timezone.utc),
                    'request_path': request.path,
                    'request_method': request.method
                })
                raise AuthError('Token verification failed', 401)

        return decorated
