from datetime import datetime, timedelta, timezone
from functools import wraps
import os
from flask import request
import jwt
from typing import Dict, Any, Optional, Tuple


class AuthError(Exception):
    """Custom exception for authentication errors"""

    def __init__(self, error: str, status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


class TokenJWTHandling:
    def __init__(self, db):
        self.__db = db
        self.__MAX_DAILY_TOKENS = 2
        # Configuration
        self.__JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
        self.__JWT_TOKEN_EXPIRATION = timedelta(days=7)
        self.__JWT_REQUEST_COOLDOWN = timedelta(hours=12)

    def get_user_token_history(self, user_id: str, since: datetime) -> list:
        """
        Retrieves the token generation history for a specific user from Firestore.

        Args:
            user_id (str): The unique identifier of the user whose token history is being retrieved.
            since (datetime): The starting datetime point from which to retrieve the history.

        Returns:
            List[Dict]: A list of dictionaries containing token history records, where each dictionary
            contains token details such as creation time, expiration, and status.

        Raises:
            FirestoreError: If there's an error accessing the Firestore database.

        Example:
            >>> history = get_user_token_history("user123", datetime(2024, 1, 1))
            >>> print(history[0])
            {
                'user_id': 'user123',
                'created_at': datetime(2024, 1, 5, 10, 30),
                'status': 'active',
                'expires_at': datetime(2024, 1, 12, 10, 30)
            }
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
        Determines if a user is eligible to request a new token based on daily limits and cooldown periods.

        Args:
            user_id (str): The unique identifier of the user requesting a token.

        Returns:
            Tuple[bool, Optional[datetime], Optional[str]]: A tuple containing:
                - bool: Whether the user is eligible for a new token
                - Optional[datetime]: The next time the user will be eligible (if currently ineligible)
                - Optional[str]: An error message explaining why the user is ineligible (if applicable)

        Raises:
            FirestoreError: If there's an error accessing the token history.

        Example:
            >>> is_eligible, next_time, message = check_token_request_eligibility("user123")
            >>> if not is_eligible:
            >>>     print(f"Next eligible at {next_time}: {message}")

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

    def get_active_token(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the most recent active token for a specified user.

        Args:
            user_id (str): The unique identifier of the user.

        Returns:
            Optional[Dict[str, Any]]: Dictionary containing token information if an active token exists,
            None otherwise. The dictionary includes:
                - access_token: The JWT token string
                - created_at: Token creation timestamp
                - expires_at: Token expiration timestamp
                - status: Current token status

        Raises:
            FirestoreError: If there's an error accessing the token data.

        Example:
            >>> token_info = get_active_token("user123")
            >>> if token_info:
            >>>     print(f"Token expires at {token_info['expires_at']}")
        """
        current_time = datetime.now(timezone.utc)

        # Query for active tokens
        tokens = (self.__db.collection('user_tokens')
                  .where('user_id', '==', user_id)
                  .where('status', '==', 'active')
                  .where('expires_at', '>', current_time)
                  .order_by('expires_at', direction='DESCENDING')
                  .limit(1)
                  .stream())

        token_list = list(tokens)
        return token_list[0].to_dict() if token_list else None

    def expire_previous_tokens(self, user_id: str) -> None:
        """
        Expires all active tokens for a given user to ensure only one token is active at a time.

        Args:
            user_id (str): The unique identifier of the user whose tokens should be expired.

        Side Effects:
            - Updates token status in database to 'expired'
            - Creates audit log entries for token expiration
            - Updates expiration timestamps

        Raises:
            FirestoreError: If there's an error updating the token status.

        Security:
            - Creates detailed audit logs for token expiration
            - Uses batch operations for atomic updates
            - Maintains complete expiration history

        Example:
            >>> expire_previous_tokens("user123")  # Expires all active tokens for user123
        """
        current_time = datetime.now(timezone.utc)

        # Query for all active tokens belonging to the user
        active_tokens = (self.__db.collection('user_tokens')
                         .where('user_id', '==', user_id)
                         .where('status', '==', 'active')
                         .stream())

        # Create a batch operation for efficiency
        batch = self.__db.batch()

        expired_count = 0
        for token_doc in active_tokens:
            doc_ref = self.__db.collection(
                'user_tokens').document(token_doc.id)

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

    def generate_tokens(self, user_id: str) -> Dict[str, Any]:
        """
        Enhanced token generation with improved storage and tracking.
        Now includes automatic expiration of previous tokens.
        """

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
        token_doc = {
            'user_id': user_id,
            'access_token': access_token,
            'created_at': current_time,
            'expires_at': token_exp,
            'status': 'active',
            'device_info': {
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            }
        }

        # Store token document
        self.__db.collection('user_tokens').add(token_doc)

        # Calculate next token request time
        next_token_time = current_time + self.__JWT_REQUEST_COOLDOWN

        return {
            'access_token': access_token,
            'token_created_at': current_time.isoformat(),
            'expires_in': int(self.__JWT_TOKEN_EXPIRATION.total_seconds()),
            'expires_at': token_exp.isoformat(),
            'next_token_request': next_token_time.isoformat()
        }

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

        Args:
            f (Callable): The function to be decorated.

        Returns:
            Callable: The decorated function with JWT verification.

        Raises:
            AuthError: In cases of:
                - Missing or invalid token format
                - Expired token
                - Invalid token signature
                - Token not found in database
                - Token type mismatch
                - Token verification failure

        Security Features:
            - Verifies JWT signature
            - Checks token expiration
            - Validates token in database
            - Maintains audit trail
            - Secure error logging
            - Automatic token status updates

        Example:
            >>> @jwt_required
            >>> def protected_route():
            >>>     return "Access granted"
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')

            if not auth_header or not auth_header.startswith('Bearer '):
                raise AuthError('Missing or invalid token format', 401)

            token = auth_header.split(' ')[1]

            try:
                # Verify JWT signature and expiration
                payload = jwt.decode(token, self.__JWT_SECRET_KEY,
                                     algorithms=['HS256'])

                # Verify token type
                if payload.get('type') != 'access':
                    raise AuthError('Invalid token type', 401)

                user_id = payload['user_id']

                # Check token in Firebase
                token_docs = (self.__db.collection('user_tokens')
                              .where('user_id', '==', user_id)
                              .where('access_token', '==', token)
                              .where('status', '==', 'active')
                              .limit(1)
                              .get())

                if not token_docs:
                    raise AuthError('Token not found in database', 401)

                token_doc = list(token_docs)[0].to_dict()
                expiry = token_doc.get('expires_at')

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
