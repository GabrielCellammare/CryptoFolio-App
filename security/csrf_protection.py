"""
CSRFProtection: Advanced Cross-Site Request Forgery protection for Flask applications.
Version: 1.0
Author: [Gabriel Cellammare]
Last Modified: [05/01/2025]

This module provides comprehensive CSRF protection for Flask applications by implementing:
- Double-submit cookie pattern with secure token generation
- One-time use nonces for request validation
- Automatic token/nonce expiration
- Secure headers implementation
- Session security hardening

Security Considerations:
1. Token Generation: Uses cryptographic-grade random generation
2. Token Storage: Implements secure cookie storage with encryption
3. Nonce Management: Provides one-time use validation with expiration
4. Memory Protection: Implements cleanup to prevent DOS attacks
5. Header Security: Implements security headers following OWASP recommendations

Dependencies:
- Flask
- cryptography.fernet
- secrets (for secure random generation)
- logging (for security event tracking)
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

# Configure logging with structured format for security audit
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CSRFProtection:
    """
    CSRF Protection Implementation

    This class provides a comprehensive CSRF protection system using:
    - Double-submit cookie validation
    - One-time nonces
    - Token encryption
    - Automatic expiration

    Security Features:
    - Encrypted tokens using Fernet (symmetric encryption)
    - Session-bound tokens
    - One-time use nonces
    - Automatic cleanup of expired tokens/nonces
    - Memory protection against DOS

    Usage:
        csrf = CSRFProtection(app)

        @app.route('/protected', methods=['POST'])
        @csrf.csrf_protect
        def protected_route():
            return 'Protected'
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize CSRF protection.

        Args:
            app (Optional[Flask]): Flask application instance for auto-initialization

        Security Notes:
        - Generates a new Fernet key for token encryption
        - Configures security constants for token/nonce management
        - Implements memory protection limits
        """
        self.used_nonces: Dict[str, float] = {}
        self.NONCE_EXPIRATION = 300  # 5 minutes
        self.TOKEN_EXPIRATION = 3600  # 1 hour
        self.MIN_TOKEN_LENGTH = 64  # Minimum secure token length
        self.MAX_NONCES = 10000  # DOS protection limit

        # Generate encryption key for token protection
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Configure application security settings.

        Args:
            app (Flask): Flask application to secure

        Security Implementation:
        - Secure session configuration
        - Security headers following OWASP recommendations
        - Automatic cleanup handlers
        """
        # Security-focused session configuration
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
            SESSION_COOKIE_NAME='secure_session'
        )

        @app.before_request
        def cleanup_expired_nonces() -> None:
            """
            Cleanup handler for expired nonces.

            Security Features:
            - Removes expired nonces
            - Implements DOS protection
            - Memory usage control
            """
            current_time = time.time()

            # Remove expired nonces
            self.used_nonces = {
                nonce: exp_time
                for nonce, exp_time in self.used_nonces.items()
                if exp_time > current_time
            }

            # Memory protection
            if len(self.used_nonces) > self.MAX_NONCES:
                sorted_nonces = sorted(
                    self.used_nonces.items(), key=lambda x: x[1])
                self.used_nonces = dict(sorted_nonces[-self.MAX_NONCES:])

        @app.after_request
        def add_security_headers(response):
            """
            Add security headers to all responses.

            Security Headers:
            - X-Content-Type-Options: Prevent MIME sniffing
            - X-Frame-Options: Prevent clickjacking
            - X-XSS-Protection: Basic XSS protection
            - HSTS: Enforce HTTPS
            - CSP: Content Security Policy
            - Cache-Control: Prevent sensitive data caching
            """
            response.headers.update({
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': (
                    "default-src 'self'; "
                    "img-src 'self' data:; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com; "
                    "font-src 'self' https://cdnjs.cloudflare.com"
                ),
                'Cache-Control': 'no-store, must-revalidate'
            })
            return response

    def generate_token(self) -> str:
        """
        Generate encrypted CSRF token.

        Returns:
            str: Encrypted token

        Security Features:
        - Uses secrets for cryptographic random generation
        - Implements token encryption
        - Includes timestamp for expiration
        - Secure cookie settings
        """
        raw_token = secrets.token_urlsafe(self.MIN_TOKEN_LENGTH)
        timestamp = str(int(time.time()))
        token_data = f"{raw_token}:{timestamp}"
        encrypted_token = self.fernet.encrypt(token_data.encode()).decode()

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
        Generate one-time use nonce.

        Returns:
            str: Encrypted nonce

        Security Features:
        - One-time use validation
        - Automatic expiration
        - Memory protection
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
        Validate and optionally refresh CSRF token.

        Args:
            encrypted_token (str): Token to validate

        Returns:
            tuple: (new/current token, validity boolean)

        Security Features:
        - Token validation
        - Automatic refresh on expiration
        - Encryption verification
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
                return self.generate_token(), False

            return encrypted_token, True
        except Exception:
            return self.generate_token(), False

    def validate_nonce(self, encrypted_nonce: Optional[str]) -> bool:
        """
        Validate one-time use nonce.

        Args:
            encrypted_nonce (str): Nonce to validate

        Returns:
            bool: Validation result

        Security Features:
        - One-time use enforcement
        - Expiration checking
        - Encryption validation
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

            del self.used_nonces[encrypted_nonce]
            return True

        except Exception:
            return False

    def csrf_protect(self, f: Callable) -> Callable:
        """
        Route decorator for CSRF protection.

        Args:
            f (Callable): Route function to protect

        Returns:
            Callable: Protected route function

        Security Features:
        - Token validation
        - Nonce validation
        - Double-submit verification
        - Generic error messages
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE']:
                token = request.cookies.get('csrf_token')
                client_token = request.headers.get('X-CSRF-Token')
                nonce = request.headers.get('X-CSRF-Nonce')

                if not all([token, client_token, nonce]):
                    logger.warning("Missing security credentials")
                    abort(403, description="Missing security credentials")

                if not self.validate_nonce(nonce):
                    logger.warning("Security validation failed")
                    abort(403, description="Security validation failed")

                if token != client_token:
                    logger.warning("Security validation failed")
                    abort(403, description="Security validation failed")

                new_token, is_valid = self.validate_and_refresh_token(token)
                if not is_valid:
                    logger.warning("Security validation failed")
                    abort(403, description="Security validation failed")

            return f(*args, **kwargs)
        return decorated_function

    def _cleanup_oldest_nonces(self) -> None:
        """
        Internal method for nonce cleanup.

        Security Features:
        - Memory protection
        - DOS prevention
        """
        if len(self.used_nonces) > self.MAX_NONCES:
            sorted_nonces = sorted(
                self.used_nonces.items(), key=lambda x: x[1])
            self.used_nonces = dict(sorted_nonces[-self.MAX_NONCES//2:])
