"""
CSRFProtection: Advanced Cross-Site Request Forgery protection for Flask applications.

This class implements a comprehensive CSRF protection system using both tokens and nonces,
providing double-submit cookie pattern and per-request validation to prevent CSRF attacks.

Security features:
- Double-submit cookie pattern with secure token generation
- One-time use nonces for request validation
- Automatic token/nonce expiration
- Secure headers implementation
- Session security hardening
"""

import logging
from flask import Flask, make_response
from functools import wraps
from flask import session, request, abort
import secrets
import time
from datetime import timedelta
from typing import Optional, Dict, Callable
from cryptography.fernet import Fernet

# Configure logging for security events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CSRFProtection:
    """
    Implements CSRF protection for Flask applications using both tokens and nonces.

    The class uses a double-submit cookie pattern combined with per-request nonces
    to provide strong protection against CSRF attacks. It also implements automatic
    cleanup of expired tokens and secure header configuration.
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize CSRF protection.

        Args:
            app: Optional Flask application instance. If provided, automatically
                initializes the protection for the app.
        """
        # Dictionary to track used nonces with their expiration timestamps
        self.used_nonces: Dict[str, float] = {}

        # Nonce validity duration (5 minutes)
        self.NONCE_EXPIRATION = 300

        # Token validity duration (1 hour)
        self.TOKEN_EXPIRATION = 3600

        # Minimum token length for security
        self.MIN_TOKEN_LENGTH = 64

        # Maximum number of stored nonces to prevent memory exhaustion
        self.MAX_NONCES = 10000

        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Configure CSRF protection for a Flask application.

        Sets up secure session configuration, registers cleanup handlers,
        and adds security headers to all responses.

        Args:
            app: Flask application instance to protect
        """
        # Configure secure session settings
        app.config.update(
            SESSION_COOKIE_SECURE=True,      # Require HTTPS
            SESSION_COOKIE_HTTPONLY=True,    # Prevent JavaScript access
            SESSION_COOKIE_SAMESITE='Lax',   # Protect against CSRF
            PERMANENT_SESSION_LIFETIME=timedelta(
                hours=1),  # Session expiration
            SESSION_COOKIE_NAME='secure_session'  # Non-default session name
        )

        @app.before_request
        def cleanup_expired_nonces() -> None:
            """Remove expired nonces and enforce maximum storage limit."""
            current_time = time.time()

            # Clean expired nonces
            self.used_nonces = {
                nonce: exp_time
                for nonce, exp_time in self.used_nonces.items()
                if exp_time > current_time
            }

            # If too many nonces are stored, remove oldest ones
            if len(self.used_nonces) > self.MAX_NONCES:
                sorted_nonces = sorted(
                    self.used_nonces.items(), key=lambda x: x[1])
                self.used_nonces = dict(sorted_nonces[-self.MAX_NONCES:])

        @app.after_request
        def add_security_headers(response):
            """Add security headers to all responses."""
            response.headers.update({
                'X-Content-Type-Options': 'nosniff',  # Prevent MIME type sniffing
                'X-Frame-Options': 'DENY',  # Prevent clickjacking
                'X-XSS-Protection': '1; mode=block',  # Enable XSS filtering
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',  # Require HTTPS
                'Content-Security-Policy': (
                    "default-src 'self'; "
                    "img-src 'self' data:; "  # Permette immagini dal proprio dominio e data URLs
                    # Permette gli stili necessari
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                    # Permette gli script necessari
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com; "
                    "font-src 'self' https://cdnjs.cloudflare.com"  # Permette i font necessari
                ),
                'Cache-Control': 'no-store, must-revalidate'  # Prevent caching
            })
            return response

            @wraps(f)
            def decorated_function(*args, **kwargs):
                if request.method in ['POST', 'PUT', 'DELETE']:
                    token = request.cookies.get('csrf_token')
                    client_token = request.headers.get('X-CSRF-Token')
                    nonce = request.headers.get('X-CSRF-Nonce')

                    # Add debug logging
                    logger.debug(f"Cookie token: {token}")
                    logger.debug(f"Header token: {client_token}")
                    logger.debug(f"Session token: {session.get('csrf_token')}")
                    logger.debug(f"Nonce: {nonce}")

    def generate_token(self) -> str:
        """
        Generate a new CSRF token or return existing one.

        Returns:
            str: A secure random token of sufficient length

        Note:
            Tokens are stored in the session and remain valid for the session duration
        """

        """Generate an encrypted CSRF token"""

        raw_token = secrets.token_urlsafe(self.MIN_TOKEN_LENGTH)
        timestamp = str(int(time.time()))
        token_data = f"{raw_token}:{timestamp}"
        encrypted_token = self.fernet.encrypt(token_data.encode()).decode()

        # Store in both cookie and session for OAuth flow
        session['csrf_token'] = encrypted_token
        response = make_response()
        response.set_cookie(
            'csrf_token',
            encrypted_token,
            secure=True,
            httponly=True,
            samesite='Lax',
            max_age=self.TOKEN_EXPIRATION
        )
        return encrypted_token

    def generate_nonce(self) -> str:
        """
        Generate a single-use nonce for request validation.

        Returns:
            str: A secure random nonce

        Note:
            Nonces expire after NONCE_EXPIRATION seconds and can only be used once
        """
        if len(self.used_nonces) >= self.MAX_NONCES:
            logger.warning("Nonce storage limit reached, cleaning old nonces")
            self._cleanup_oldest_nonces()

        nonce = secrets.token_urlsafe(16)
        encrypted_nonce = self.fernet.encrypt(nonce.encode()).decode()
        self.used_nonces[encrypted_nonce] = time.time() + self.NONCE_EXPIRATION
        return encrypted_nonce

    def validate_and_refresh_token(self, encrypted_token):
        """
        Proposed implementation that combines validation and regeneration
        """
        if not encrypted_token:
            return self.generate_token(), False

        session_token = session.get('csrf_token')
        if not session_token or session_token != encrypted_token:
            return self.generate_token(), False

        try:
            decrypted_data = self.fernet.decrypt(
                encrypted_token.encode()).decode()
            token, timestamp = decrypted_data.split(':')
            token_age = time.time() - float(timestamp)

            if token_age >= self.TOKEN_EXPIRATION:
                # Generate new token when expired
                return self.generate_token(), False

            return encrypted_token, True
        except Exception:
            return self.generate_token(), False

    # In security.py decorated_function:

    def validate_nonce(self, encrypted_nonce: Optional[str]) -> bool:
        """
        Validate a nonce and mark it as used.

        Args:
            nonce: The nonce to validate

        Returns:
            bool: True if nonce is valid and unused, False otherwise
        """
        if not encrypted_nonce or encrypted_nonce not in self.used_nonces:
            logger.warning("Invalid or missing nonce")
            return False

        try:
            self.fernet.decrypt(encrypted_nonce.encode())
            current_time = time.time()
            expiration_time = self.used_nonces.get(encrypted_nonce, 0)

            if current_time > expiration_time:
                logger.warning("Expired nonce used")
                del self.used_nonces[encrypted_nonce]
                return False

            # Remove nonce after successful validation (one-time use)
            del self.used_nonces[encrypted_nonce]
            return True

        except Exception:
            return False

    def csrf_protect(self, f: Callable) -> Callable:
        """
        Decorator to protect routes against CSRF attacks.

        Args:
            f: The Flask route function to protect

        Returns:
            Callable: Protected route function

        Note:
            Requires both valid token and nonce for state-changing requests
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE']:
                token = request.cookies.get('csrf_token')
                client_token = request.headers.get('X-CSRF-Token')
                nonce = request.headers.get('X-CSRF-Nonce')

                if not token or not client_token or token != client_token:
                    logger.warning("CSRF token validation failed")
                    abort(403, description="Invalid CSRF token")

                # Validazione con potenziale refresh
                new_token, is_valid = self.validate_and_refresh_token(token)
                if not is_valid:
                    logger.warning("CSRF token validation failed")
                    abort(403, description="Invalid CSRF token")

                # Se il token è stato rigenerato, aggiorna il cookie
                if new_token != token:
                    response = make_response(f(*args, **kwargs))
                    response.set_cookie('csrf_token', new_token,
                                        secure=True, httponly=True,
                                        samesite='Lax',
                                        max_age=self.TOKEN_EXPIRATION)
                    return response

                if not self.validate_nonce(nonce):
                    logger.warning("CSRF nonce validation failed")
                    abort(403, description="Invalid or expired nonce")

                logger.info("CSRF validation successful")

            return f(*args, **kwargs)
        return decorated_function

    def _cleanup_oldest_nonces(self) -> None:
        """
        Remove oldest nonces when storage limit is reached.
        """
        if len(self.used_nonces) > self.MAX_NONCES:
            sorted_nonces = sorted(
                self.used_nonces.items(), key=lambda x: x[1])
            self.used_nonces = dict(sorted_nonces[-self.MAX_NONCES//2:])
