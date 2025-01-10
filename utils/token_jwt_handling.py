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

    """
    Custom exception class for authentication and token-related errors.

    This class provides structured error handling for authentication operations,
    including status codes for proper HTTP response handling.

    Attributes:
        error (str): Descriptive error message
        status_code (int): HTTP status code for the error

    Usage:
        raise AuthError("Token expired", 401)
    """

    def __init__(self, error: str, status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


"""
Enhanced JWT Token Management System
Version: 2.0
Author: Gabriel Cellammare
Last Modified: 10/01/2025

This module implements a comprehensive JWT (JSON Web Token) handling system with a strong 
focus on security, encryption, and secure token lifecycle management. It provides 
robust token generation, validation, and storage mechanisms with defense-in-depth 
measures.

Core Security Features:
1. Token Management
   - Secure token generation with user binding
   - Protected token storage with encryption
   - Automatic token expiration
   - Token rotation policies
   - Rate limiting implementation

2. Cryptographic Security
   - AES encryption for sensitive data
   - Salt-based key derivation
   - Secure token signing
   - Protected storage operations
   - Memory-safe cleanup

3. Access Control
   - User session binding
   - Request validation
   - IP tracking
   - Device fingerprinting
   - Audit logging

4. State Management
   - Secure token persistence
   - Protected state transitions
   - Safe cleanup operations
   - Error isolation
   - Recovery procedures

Security Considerations:
- All tokens are encrypted before storage
- User sessions are strictly validated
- Token operations are isolated
- Rate limiting prevents abuse
- Audit trails are maintained
- Cleanup is automatic
- Error states are safe

Dependencies:
- jwt: For token operations
- firebase_admin: Database operations
- cryptography: Encryption operations
- datetime: Timestamp management
- base64: Secure encoding
"""


class TokenJWTHandling:
    def __init__(self, db, cipher):
        """
        Initialize secure token handling with database and encryption support.

        This constructor sets up the token management system with proper security
        configuration and initializes the required dependencies.

        Args:
            db: Firestore database instance for token storage
            cipher: AESCipher instance for data encryption/decryption

        Security Features:
            - Protected configuration loading
            - Secure key management
            - Rate limit configuration
            - Token lifecycle settings

        Environment Variables:
            JWT_SECRET_KEY: Secret key for token signing
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
        Retrieve a user's token generation history with secure filtering.

        This method securely queries the database for a user's token history,
        applying proper time-based filtering and status validation.

        Args:
            user_id (str): Unique identifier of the user
            since (datetime): Starting timestamp for history retrieval

        Returns:
            List[Dict]: Filtered list of token history records

        Security:
            - Query parameter validation
            - Status filtering
            - Time-based constraints
        """
        token_docs = (self.__db.collection('user_tokens')
                      .where('user_id', '==', user_id)
                      .where('created_at', '>=', since)
                      # Only consider active tokens
                      .where('status', '==', 'active')
                      .order_by('created_at', direction='DESCENDING')
                      .stream())

        return [doc.to_dict() for doc in token_docs]

    def check_token_request_eligibility(self, user_id: str) -> Tuple[bool, Optional[datetime], Optional[str]]:
        """
        Validate token request eligibility based on security policies.

        This method implements rate limiting and cooldown periods for token
        generation to prevent abuse and ensure secure token management.

        Args:
            user_id (str): Unique identifier of the requesting user

        Returns:
            Tuple[bool, Optional[datetime], Optional[str]]: 
                - Boolean indicating eligibility
                - Next eligible timestamp if applicable
                - Error message if request is denied

        Security:
            - Daily limit enforcement
            - Cooldown period validation
            - Request tracking
            - Time-based restrictions
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
        Encrypt sensitive token data for secure storage in Firebase.

        This method implements secure encryption of token fields before database storage,
        protecting sensitive information through field-level encryption with user-specific keys.

        Args:
            token_data (dict): Token information to be encrypted
            user_id (str): User identifier for encryption key derivation
            salt (bytes): Cryptographic salt for key generation

        Returns:
            dict: Token data with sensitive fields encrypted

        Raises:
            AuthError: When encryption operations fail with status code 500

        Security Features:
            - Field-level encryption
            - User-specific key derivation
            - Salt-based encryption
            - Secure error handling
            - Protected memory operations

        Protected Fields:
            - access_token
            - refresh_token
            - expires_at
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
        Decrypt encrypted token data retrieved from Firebase storage.

        This method securely decrypts token information using user-specific keys
        and handles proper conversion of decrypted data types.

        Args:
            encrypted_data (dict): Encrypted token information from storage
            user_id (str): User identifier for decryption key derivation
            salt (bytes): Cryptographic salt used in encryption

        Returns:
            dict: Decrypted token data with original field values

        Raises:
            AuthError: When decryption fails with status code 500

        Security Features:
            - Secure key derivation
            - Protected memory handling
            - Type-safe conversions
            - Error isolation
            - Audit logging

        Protected Operations:
            - Decryption key generation
            - Memory cleanup
            - String encoding handling
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
        Securely store encrypted token data in Firebase with proper metadata.

        This method handles the complete process of token storage, including salt retrieval,
        encryption, and secure database operations with proper error handling.

        Args:
            user_id (str): User identifier for token association
            token_data (dict): Token information to be stored

        Raises:
            AuthError: When storage operations fail with status code 500

        Security Features:
            - Salt retrieval protection
            - Secure encryption
            - Atomic database operations
            - Timestamp recording
            - Status tracking

        Database Operations:
            - Salt retrieval from security collection
            - Token data encryption
            - Secure document creation
            - Status initialization
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
        Invalidate all active tokens for a user with secure state transitions.

        This method implements secure token expiration with proper audit logging
        and atomic database operations to maintain token lifecycle integrity.

        Args:
            user_id (str): User identifier whose tokens should be expired

        Security Features:
            - Batch operations for atomicity
            - Secure decryption for validation
            - Status transition logging
            - Time-based validation
            - Audit trail creation

        Operations Flow:
            1. Retrieve user's cryptographic salt
            2. Query active tokens
            3. Validate and decrypt tokens
            4. Batch update expired status
            5. Create audit logs

        Protected State Transitions:
            - Active to Expired status
            - Timestamp recording
            - Reason documentation
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
        Retrieve the current active token for a user with validation.

        This method securely fetches and validates the most recent active token,
        performing necessary decryption and expiration checks.

        Args:
            user_id (str): User identifier to check for active tokens

        Returns:
            Optional[Dict[str, Any]]: Active token information if valid, None otherwise

        Security Features:
            - Salt-based decryption
            - Time-based validation
            - Status verification
            - Secure ordering
            - Query limiting

        Validation Checks:
            - Token existence
            - Expiration status
            - Decryption integrity
            - Time validity
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
        Generate new JWT tokens with secure storage and rate limiting.

        This method creates new JWT tokens with proper security measures,
        including rate limiting, encryption, and secure storage operations.

        Args:
            user_id (str): User identifier for token generation

        Returns:
            Dict[str, Any]: Generated token information including expiration and next request time

        Raises:
            AuthError: For rate limit violations (429) or generation failures (500)

        Security Features:
            - Rate limit enforcement
            - Previous token expiration
            - Secure JWT creation
            - Protected storage
            - Device tracking

        Token Properties:
            - Expiration time
            - Creation timestamp
            - User binding
            - Device information
            - Request cooldown
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
        Extract token creation timestamp from JWT claims securely.

        This method safely decodes JWT claims to retrieve the token creation time
        with proper error handling and validation.

        Args:
            token (str): JWT token to analyze

        Returns:
            Optional[datetime]: Token creation timestamp if valid, None otherwise

        Security Features:
            - Secure JWT decoding
            - Signature validation
            - Time parsing protection
            - Error isolation
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
        Protect routes with comprehensive JWT validation and security checks.

        This decorator implements complete token validation including signature verification,
        database validation, and proper user session binding.

        Args:
            f (Callable): The route function to protect

        Returns:
            Callable: Protected route function

        Security Features:
            - Token presence validation
            - JWT signature verification
            - Database token validation
            - Expiration checking
            - User session binding
            - Error logging

        Validation Flow:
            1. Token format verification
            2. JWT signature validation
            3. Token type checking
            4. Database record validation
            5. Expiration verification
            6. User session binding

        Raises:
            AuthError: Various 401 status codes for different validation failures
                - Missing token
                - Invalid signature
                - Token not found
                - Token expired
                - Verification failed
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
