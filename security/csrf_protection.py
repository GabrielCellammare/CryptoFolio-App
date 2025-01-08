"""
Enhanced CSRF Protection System
Version: 2.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

Key Security Features:
1. JavaScript Origin Validation
2. Request Origin Binding
3. Enhanced Token Protection
4. Anti-Automation Measures
5. Request Chain Validation
"""

import base64
import hmac
import logging
import os
import re
import struct
import json
from urllib.parse import urlparse
from venv import logger
from flask import Flask, Response, current_app, jsonify, make_response, redirect, session, request, abort
from functools import lru_cache, wraps
import secrets
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Callable, Set, Tuple
from cryptography.fernet import Fernet
import hashlib


class CSRFProtection:
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self._signing_key = secrets.token_bytes(32)
        self._js_origin_key = secrets.token_bytes(32)
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

        # Token and nonce management
        self.used_nonces: Dict[str, Dict] = {}
        self._token_cache: Dict[str, Dict] = {}

        # Configure logging with DEBUG level
        self.logger = logging.getLogger('csrf_protection')
        self.logger.setLevel(logging.DEBUG)  # Set to DEBUG level

        # Create a console handler with formatting
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)

        # Add handler if it doesn't exist
        if not self.logger.handlers:
            self.logger.addHandler(console_handler)
        # Origin management
        self._allowed_origins = set()
        self._dynamic_origins = set()

        # Set of supported environments
        self.SUPPORTED_ENVIRONMENTS: Set[str] = frozenset(
            {'development', 'production'})

        # Security constants
        self.NONCE_EXPIRATION = 300
        self.MAX_NONCES = 10000
        self.MIN_TOKEN_LENGTH = 64
        self._token_lifetime = 3600
        self._max_tokens_per_session = 3
        self._max_uses_per_token = 100

        # Request chain tracking
        self._request_chains: Dict[str, Dict] = {}

        # Security configuration constants
        self.SECURITY_HEADERS = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': self._build_csp_policy(),
            'Cache-Control': 'no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), camera=(), microphone=()'
        }

        self.COOKIE_SETTINGS = {
            'secure': True,
            'httponly': True,
            'samesite': 'Lax',
            'domain': None,  # Will be set based on request
            'path': '/',
        }

        self.SESSION_CONFIG = {
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=1),
            'SESSION_COOKIE_NAME': 'secure_session',
            'SESSION_PROTECTION': 'strong'
        }

        if app:
            self.init_app(app)

    def _parse_origins_list(self, origins_string: str) -> set:
        """
        Parse origins string into a set of allowed origins and patterns.

        Args:
            origins_string (str): Comma-separated list of origins

        Returns:
            set: Set of allowed origins
        """
        origins = set()
        if not origins_string:
            return origins

        for origin in origins_string.split(','):
            origin = origin.strip()
            if origin:
                if '*' in origin:
                    # Store wildcard patterns separately
                    self._dynamic_origins.add(origin.replace('*', '.*'))
                else:
                    origins.add(origin)

        return origins

    def _build_csp_policy(self) -> str:
        """
        Build a comprehensive Content Security Policy.
        This method centralizes CSP configuration for easier maintenance.
        """
        return "; ".join([
            "default-src 'self'",
            "img-src 'self' data: https:",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com",
            "font-src 'self' https://cdnjs.cloudflare.com",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "upgrade-insecure-requests"
        ])

    def init_app(self, app: Flask) -> None:
        """
        Initialize application with security configurations.
        """
        # Apply session configuration
        app.config.update(self.SESSION_CONFIG)

        try:
            # Parse allowed origins
            dev_origins = self._parse_origins_list(
                os.getenv('DEV_ALLOWED_ORIGINS', '')
            )
            prod_origins = self._parse_origins_list(
                os.getenv('PROD_ALLOWED_ORIGINS', '')
            )

            # Add ngrok domains for development
            if os.getenv('FLASK_ENV') == 'development':
                dev_origins.add('*.ngrok-free.app')
                dev_origins.add('*.ngrok.io')

            # Store based on environment
            current_env = os.getenv('FLASK_ENV', 'production')
            self._allowed_origins = dev_origins if current_env == 'development' else prod_origins

            # Create environment configurations
            environments = {
                'development': {
                    'origins': list(dev_origins),
                    'max_requests': 100
                },
                'production': {
                    'origins': list(prod_origins),
                    'max_requests': 1000
                }
            }

            # Store in app config
            app.config['ENVIRONMENTS'] = environments

            @app.before_request
            def secure_request():
                """Enforce HTTPS and validate request origin"""
                if not request.is_secure and not app.debug:
                    return redirect(request.url.replace('http://', 'https://', 1), code=301)

            @app.after_request
            def add_security_headers(response):
                """Add comprehensive security headers to all responses"""
                response.headers.update(self.SECURITY_HEADERS)

                # Remove potentially dangerous headers
                response.headers.pop('Server', None)
                response.headers.pop('X-Powered-By', None)

                return response

        except Exception as e:
            logger.error(f"CSRF Protection initialization failed: {str(e)}")
            raise

    @lru_cache(maxsize=100)
    def _get_allowed_origins(self) -> List[str]:
        """
        Get cached list of allowed origins for current environment.
        Uses lru_cache for performance optimization.

        Returns:
            List[str]: List of allowed origins for the current environment
        """
        env = os.getenv('FLASK_ENV', 'production')

        if env not in self.SUPPORTED_ENVIRONMENTS:
            logger.warning(f"Unsupported environment {env}, using production")
            env = 'production'

        try:
            return current_app.config['ENVIRONMENTS'][env]['origins']

        except (KeyError, AttributeError):
            logger.error(f"Missing environment configuration for {env}")
            return []

    def _validate_origin_format(self, origin: str) -> bool:
        """
        Validates the format of an origin string to ensure it meets security requirements.

        This method performs several security checks:
        1. Basic format validation (protocol://domain[:port])
        2. Protocol restriction (only http/https)
        3. Domain validation
        4. Port number validation if present

        Args:
            origin: The origin string to validate

        Returns:
            bool: True if the origin format is valid, False otherwise
        """
        if not origin or '\x00' in origin:  # Check for null bytes
            return False

        try:
            # Parse the origin URL
            parsed = urlparse(origin)

            # Verify basic structure
            if not all([parsed.scheme, parsed.netloc]):
                return False

            # Validate protocol
            if parsed.scheme not in {'http', 'https'}:
                return False

            # Handle local development
            is_local = (
                parsed.netloc.startswith('localhost') or
                parsed.netloc.startswith('127.0.0.1') or
                parsed.netloc == '[::1]'
            )

            if is_local:
                # Allow local addresses only in development
                if os.getenv('FLASK_ENV') != 'development':
                    self.logger.warning(
                        "Local address rejected in non-development environment")
                    return False

                # Validate port if present
                if ':' in parsed.netloc:
                    try:
                        port = int(parsed.netloc.split(':')[1])
                        if not (1024 <= port <= 65535):
                            return False
                    except ValueError:
                        return False

                return True

            # For non-local origins:
            # Check for valid domain structure
            if not parsed.netloc or '.' not in parsed.netloc:
                return False

            # Reject paths for origins
            if parsed.path and parsed.path != '/':
                return False

            # Special handling for ngrok in development
            if os.getenv('FLASK_ENV') == 'development':
                if any(domain in parsed.netloc for domain in ['ngrok-free.app', 'ngrok.io']):
                    return True

            return True

        except Exception as e:
            self.logger.warning(f"Origin format validation failed: {str(e)}")
            return False

    def _validate_origin_secure(self, request_origin: str, token: str = None) -> bool:
        """
        Enhanced security validation for request origins.
        Works alongside existing validation methods to provide additional security checks.

        Args:
            request_origin: Origin header from the request
            token: Optional CSRF token for additional validation

        Returns:
            bool: True if the origin passes all security checks
        """
        # First perform basic format validation
        if not request_origin or not self._validate_origin_format(request_origin):
            return False

        try:
            parsed = urlparse(request_origin)

            # Check if this is a development environment
            is_dev = os.getenv('FLASK_ENV') == 'development'

            # Handle local development URLs first
            is_local = (
                parsed.netloc.startswith('localhost') or
                parsed.netloc.startswith('127.0.0.1') or
                parsed.netloc == '[::1]'
            )

            if is_local:
                # In development, we should allow local origins that are in our allowed list
                if is_dev and request_origin in self._allowed_origins:
                    return True

                # If not in development or not in allowed origins, reject
                if not is_dev:
                    self.logger.warning(
                        f"Local origin {
                            request_origin} rejected in non-development environment"
                    )
                return False

            # Handle ngrok URLs in development
            if is_dev and ('ngrok-free.app' in parsed.netloc or 'ngrok.io' in parsed.netloc):
                # First check direct match in allowed origins
                if request_origin in self._allowed_origins:
                    return True

                # Then check against dynamic patterns
                for pattern in self._dynamic_origins:
                    if re.match(pattern, request_origin):
                        return True
                return False

            # For all other origins, check against allowed list first
            if request_origin in self._allowed_origins:
                return True

            # Finally check against dynamic patterns
            for pattern in self._dynamic_origins:
                if re.match(pattern, request_origin):
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Origin security validation failed: {str(e)}")
            return False

    def set_csrf_cookie(self, response: Response, token: str) -> None:
        """
        Set CSRF token cookie with secure settings.
        Now integrated with the security configuration.
        """
        if not token:
            return

        # Get domain from request
        domain = request.host.split(':')[0] if request.host else None

        # Update cookie settings with current domain
        cookie_settings = self.COOKIE_SETTINGS.copy()
        cookie_settings['domain'] = domain
        cookie_settings['max_age'] = self._token_lifetime

        # Set the cookie with all security settings
        response.set_cookie(
            'csrf_token',
            token,
            **cookie_settings
        )

    def _validate_js_origin(self, signature: str) -> bool:
        """
        Validate JavaScript origin signature with relaxed timing window.
        """

        try:

            self.logger.debug(f"Validating signature: {signature}")

            raw_data = base64.urlsafe_b64decode(
                signature + '=' * (-len(signature) % 4))
            self.logger.debug(f"Decoded length: {len(raw_data)}")

            if len(raw_data) < 36:
                self.logger.warning(
                    f"Invalid signature length: {len(raw_data)}")
                return False

            timestamp_bytes = raw_data[:4]
            request_id = raw_data[4:36]
            request_id_hex = request_id.hex()

            self.logger.debug(f"Timestamp bytes: {timestamp_bytes.hex()}")
            self.logger.debug(f"Request ID: {request_id_hex}")

            # Verify timestamp with slightly relaxed window
            timestamp = struct.unpack("!I", timestamp_bytes)[0]
            current_time = int(time.time())
            time_diff = abs(current_time - timestamp)

            self.logger.debug(f"Extracted timestamp: {timestamp}")
            self.logger.debug(f"Current time: {current_time}")
            self.logger.debug(f"Time difference: {time_diff} seconds")

            # Increase window to 60 seconds to handle slight delays
            if time_diff > 60:
                self.logger.warning(
                    "Timestamp validation failed - outside time window")
                return False

            # Clean up expired request chains
            self._cleanup_request_chains()

            # Modify request reuse detection
            endpoint = request.endpoint if request else None
            request_key = f"{request_id_hex}:{endpoint}"

            # Increase the time window and track request count
            current_time = time.time()
            if request_key in self._request_chains:
                request_data = self._request_chains[request_key]
                # 5 second window
                if current_time - request_data['timestamp'] < 5:
                    request_data['count'] = request_data.get('count', 0) + 1
                    if request_data['count'] > 10:  # Allow up to 3 requests in window
                        self.logger.warning(
                            f"Excessive requests detected for endpoint: {endpoint}")
                        return False
                else:
                    # Reset counter for new time window
                    request_data['timestamp'] = current_time
                    request_data['count'] = 1
            else:
                self._request_chains[request_key] = {
                    'timestamp': current_time,
                    'count': 1
                }

            return True

        except Exception as e:
            self.logger.error(f"JS origin validation error: {
                              str(e)}", exc_info=True)
            return False

    def _cleanup_request_chains(self):
        """
        Cleans up expired request chains to prevent memory growth.
        """
        expired_keys = [
            key for key, data in self._request_chains.items()
            if data['count'] > 10
        ]

        for key in expired_keys:
            del self._request_chains[key]

    def _generate_secure_token(self, require_user_id=True) -> str:
        """
        Generate CSRF token with optional user_id requirement for authentication flows.

        Args:
            require_user_id (bool): Whether to require user_id in session

        Returns:
            str: Generated secure token
        """
        # Solo per rotte autenticate verifichiamo user_id
        if require_user_id and 'user_id' not in session:
            abort(401)

        if (require_user_id):

            # Validate JavaScript origin
            js_origin = request.headers.get('X-JavaScript-Origin')
            print("JS ORIGIN:", js_origin)
            if not js_origin or not self._validate_js_origin(js_origin):
                abort(403, "Invalid request origin")

            user_id = session['user_id']

            # Generate token components with additional entropy
            timestamp = int(time.time())
            random_bytes = secrets.token_bytes(32)
            request_id = secrets.token_hex(16)

            # Create token payload
            payload = {
                'user_id': user_id,
                'timestamp': timestamp,
                'request_id': request_id,
                'random': base64.b64encode(random_bytes).decode()
            }

            # Encrypt payload
            encrypted_payload = self.fernet.encrypt(
                json.dumps(payload).encode()
            )

            # Generate HMAC signature
            signature = hmac.new(
                self._signing_key,
                encrypted_payload,
                hashlib.sha256
            ).digest()

            # Combine components
            token = base64.urlsafe_b64encode(
                encrypted_payload + signature
            ).decode()

            # Store in cache with metadata
            if user_id not in self._token_cache:
                self._token_cache[user_id] = {}

            self._token_cache[user_id][token] = {
                'timestamp': timestamp,
                'uses': 0,
                'request_id': request_id
            }

            return token

        else:
            # Per login/oauth, generateiamo un token temporaneo
            user_id = session.get('user_id', 'temp-' + secrets.token_hex(16))
            # Generate token components
            timestamp = int(time.time())
            random_bytes = secrets.token_bytes(32)
            request_id = secrets.token_hex(16)

            # Create token payload
            payload = {
                'user_id': user_id,
                'timestamp': timestamp,
                'request_id': request_id,
                'random': base64.b64encode(random_bytes).decode(),
                'is_auth_flow': not require_user_id
            }

            # Encrypt payload
            encrypted_payload = self.fernet.encrypt(
                json.dumps(payload).encode()
            )

            # Generate signature
            signature = hmac.new(
                self._signing_key,
                encrypted_payload,
                hashlib.sha256
            ).digest()

            # Combine components
            token = base64.urlsafe_b64encode(
                encrypted_payload + signature
            ).decode()

            # Store in cache with metadata
            if user_id not in self._token_cache:
                self._token_cache[user_id] = {}

            self._token_cache[user_id][token] = {
                'timestamp': timestamp,
                'uses': 0,
                'request_id': request_id,
                'is_auth_flow': not require_user_id
            }

            return token

    def generate_token(self, require_user_id=True) -> Tuple[str, Response]:
        """
        Generate CSRF token and prepare secure response.
        Now returns both token and properly configured response.
        """
        token = self._generate_secure_token(
            require_user_id)  # Previous token generation logic

        response = make_response(jsonify({
            'token': token,
            'expires': int(time.time() + self._token_lifetime)
        }))

        # Set CSRF cookie with security settings
        self.set_csrf_cookie(response, token)

        return token, response

    def _validate_token(self, token: str) -> bool:
        """
        Validate CSRF token with enhanced security checks.
        """
        try:
            if not token:
                return False

            # Decode token
            try:
                raw_data = base64.urlsafe_b64decode(token)
            except:
                return False

            if len(raw_data) < 64:  # Minimum size for encrypted payload + signature
                return False

            # Split components
            encrypted_payload = raw_data[:-32]
            signature = raw_data[-32:]

            # Verify signature
            expected_sig = hmac.new(
                self._signing_key,
                encrypted_payload,
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(signature, expected_sig):
                return False

            # Decrypt and validate payload
            try:
                payload = json.loads(
                    self.fernet.decrypt(encrypted_payload).decode()
                )
            except:
                return False

            # Validate user binding
            if payload['user_id'] != session.get('user_id'):
                return False

            # Check expiration
            if time.time() - payload['timestamp'] > self._token_lifetime:
                return False

            # Validate token usage
            user_id = payload['user_id']
            if (user_id not in self._token_cache or
                    token not in self._token_cache[user_id]):
                return False

            token_data = self._token_cache[user_id][token]
            if token_data['uses'] >= self._max_uses_per_token:
                return False

            # Increment usage counter
            token_data['uses'] += 1
            return True

        except Exception as e:
            self.logger.error(f"Token validation error: {str(e)}")
            return False

    def validate_token_request(self, token: str) -> bool:
        """
        Validate token and request headers comprehensively.
        Enhanced validation including origin and referrer checks.
        """
        if not token:
            return False

        # Origin validation
        origin = request.headers.get('Origin')
        if origin:
            # Use the new secure validation method
            if not self._validate_origin_secure(origin, token):
                self.logger.warning(f"Invalid origin: {origin}")
                return False

        referrer = request.headers.get('Referer')

        # Referrer validation for same-origin requests
        if referrer:
            ref_url = urlparse(referrer)
            req_url = urlparse(request.url)
            if ref_url.netloc != req_url.netloc:
                self.logger.warning(f"Invalid referrer: {referrer}")
                return False

        # Existing token validation logic...
        return self._validate_token(token)

    def generate_nonce(self) -> str:
        """
        Generate secure nonce with request binding.
        """
        # Validate JavaScript origin
        js_origin = request.headers.get('X-JavaScript-Origin')
        if not js_origin or not self._validate_js_origin(js_origin):
            abort(403, "Invalid request origin")

        if len(self.used_nonces) >= self.MAX_NONCES:
            self._cleanup_oldest_nonces()

        # Generate nonce with request binding
        timestamp = int(time.time())
        random_bytes = secrets.token_bytes(32)
        request_id = secrets.token_hex(16)

        # Create nonce payload
        payload = {
            'timestamp': timestamp,
            'random': base64.b64encode(random_bytes).decode(),
            'request_id': request_id,
            'user_id': session.get('user_id')
        }

        # Encrypt payload
        encrypted_nonce = self.fernet.encrypt(
            json.dumps(payload).encode()
        ).decode()

        # Store with metadata
        self.used_nonces[encrypted_nonce] = {
            'expires': time.time() + self.NONCE_EXPIRATION,
            'request_id': request_id
        }

        return encrypted_nonce

    def validate_nonce(self, nonce: str) -> bool:
        """
        Validate nonce with request chain verification.
        """
        try:
            if not nonce or nonce not in self.used_nonces:
                return False

            nonce_data = self.used_nonces[nonce]
            current_time = time.time()

            # Check expiration
            if current_time > nonce_data['expires']:
                del self.used_nonces[nonce]
                return False

            # Decrypt and validate payload
            try:
                payload = json.loads(
                    self.fernet.decrypt(nonce.encode()).decode()
                )
            except:
                return False

            # Validate user binding
            if payload['user_id'] != session.get('user_id'):
                return False

            # Remove used nonce
            del self.used_nonces[nonce]
            return True

        except Exception as e:
            self.logger.error(f"Nonce validation error: {str(e)}")
            return False

    def csrf_protect(self, f: Callable) -> Callable:
        """
        Enhanced CSRF protection decorator for all routes.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            nonce = request.headers.get('X-CSRF-Nonce')
            if not nonce or not self.validate_nonce(nonce):
                abort(403, "Invalid CSRF nonce")
            # Then validate token for all requests

            token = request.headers.get('X-CSRF-Token')
            if not token or not self.validate_token_request(token):
                abort(403, "Invalid CSRF token")

                # Additional origin validation
            origin = request.headers.get('Origin')
            if origin and not self._validate_origin_secure(origin, token):
                abort(403, "Invalid request origin")

            return f(*args, **kwargs)
        return decorated_function

    def _cleanup_oldest_nonces(self) -> None:
        """
        Clean up expired nonces and request chains.
        """
        current_time = time.time()

        # Clean nonces
        self.used_nonces = {
            nonce: data
            for nonce, data in self.used_nonces.items()
            if data['expires'] > current_time
        }

        # Clean request chains
        self._request_chains = {
            req_id: data
            for req_id, data in self._request_chains.items()
            if data['expires'] > current_time
        }

        # Implement DOS protection
        if len(self.used_nonces) > self.MAX_NONCES:
            sorted_nonces = sorted(
                self.used_nonces.items(),
                key=lambda x: x[1]['expires']
            )
            self.used_nonces = dict(sorted_nonces[-self.MAX_NONCES//2:])
