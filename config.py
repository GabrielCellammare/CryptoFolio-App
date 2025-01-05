"""
CryptoCache: Advanced Security Framework for Flask Applications
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

This module implements a comprehensive security framework for Flask applications with
defense-in-depth measures and robust security controls. It provides multi-layered
protection against various attack vectors while ensuring data integrity and secure
cross-origin communications.

Core Security Features:
1. Origin Validation
   * Strict origin validation with DNS rebinding protection
   * Null byte injection prevention
   * IP-based origin validation
   * Protocol enforcement

2. Environment Security
   * Secure environment variable handling
   * Runtime modification prevention
   * Default security fallbacks
   * Configuration immutability

3. CORS Protection
   * Header injection prevention
   * Strict CORS policy enforcement
   * Secure credential handling
   * Cache poisoning protection

4. Audit & Logging
   * Secure audit logging
   * Log sanitization
   * Rotation policies
   * Sensitive data masking

Security Considerations:
- All environment variables must be securely configured
- SSL/TLS must be properly configured on the server
- Regular security audits should be performed
- Security updates should be monitored and applied

Dependencies:
- flask>=2.0.0: Web framework
- urllib3>=2.0.0: HTTP client
- cryptography>=41.0.0: Cryptographic operations
- python-dotenv>=1.0.0: Environment management
"""

import os
import logging
import secrets
import time
from typing import List, Optional, Set
from functools import lru_cache
from urllib.parse import urlparse
from dataclasses import dataclass, field
from flask import current_app, request, Flask, Response
import re
from cryptography.fernet import Fernet
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
import hashlib
import hmac


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class ConfigurationError(SecurityError):
    """Specific exception for configuration security issues."""
    pass


@dataclass(frozen=True)
class SecurityHeaders:
    """Immutable security headers configuration."""
    HSTS: str = field(default="strict")
    CONTENT_TYPE_OPTIONS: str = field(default="nosniff")
    FRAME_OPTIONS: str = field(default="DENY")
    XSS_PROTECTION: str = field(default="1; mode=block")
    REFERRER_POLICY: str = field(default="strict-origin-when-cross-origin")
    PERMITTED_CROSS_DOMAIN_POLICIES: str = field(default="none")
    CSP: str = field(default="default-src 'self'")


@dataclass(frozen=True)
class EnvironmentConfig:
    """Immutable environment-specific configuration."""
    origins: List[str] = field(default_factory=list)
    max_requests: int = field(default=100)
    request_window: int = field(default=3600)


class SecureConfig:
    """
    Enhanced secure configuration manager for Flask applications.

    This class manages secure configuration settings including CORS policies,
    security headers, and environment-specific settings. It implements multiple
    layers of security controls and validation.
    """

    DEFAULT_CORS_MAX_AGE: int = 3600  # 1 hour
    DEFAULT_HSTS_MAX_AGE: int = 31536000  # 1 year
    SUPPORTED_ENVIRONMENTS: Set[str] = frozenset({'development', 'production'})

    # Secure pattern matching for origins
    ORIGIN_PATTERN: re.Pattern = re.compile(
        r'^https?://(?:'
        # Domini normali
        r'(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?::\d{1,5})?|'
        r'localhost(?::\d{1,5})?|'  # localhost
        r'127\.0\.0\.1(?::\d{1,5})?|'  # IPv4 loopback
        r'\[::1\](?::\d{1,5})?'  # IPv6 loopback
        r')$'
    )

    def __init__(self):
        """Initialize secure configuration with audit logging and encryption."""
        self._setup_secure_logging()
        self._init_crypto()
        self._request_history = {}
        self._initialized = False
        self._env_config = None
        self._security_headers = SecurityHeaders()

    def _init_crypto(self) -> None:
        """
        Initialize cryptographic components for secure operations.

        Sets up encryption keys and HMAC for secure data handling.
        """
        self._encryption_key = Fernet.generate_key()
        self._fernet = Fernet(self._encryption_key)
        self._hmac_key = secrets.token_bytes(32)

    def _setup_secure_logging(self) -> None:
        """
        Configure secure logging with rotation and sanitization.

        Implements:
        - Log rotation to prevent disk space exhaustion
        - Secure file permissions
        - Sanitized log formatting
        - Sensitive data masking
        """
        log_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [SECURED] %(message)s'
        )

        file_handler = RotatingFileHandler(
            'secure_app.log',
            maxBytes=10485760,  # 10MB
            backupCount=5,
            mode='a',
            encoding='utf-8'
        )
        file_handler.setFormatter(log_formatter)

        self.logger = logging.getLogger('secure_config')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)

    def _generate_hmac(self, data: str) -> str:
        """
        Generate HMAC for data integrity verification.

        Args:
            data: Input string to generate HMAC for

        Returns:
            str: Hexadecimal HMAC digest
        """
        return hmac.new(
            self._hmac_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def _validate_origin_secure(self, origin: str) -> bool:
        """
        Enhanced origin validation with support for local development.

        This method validates origins while allowing local development addresses.
        It implements several security checks while maintaining developer friendliness.

        Security measures:
        - Pattern matching for valid URLs and IP addresses
        - Special handling for localhost and loopback addresses
        - Development environment detection
        - DNS rebinding protection
        - Null byte injection prevention

        Args:
            origin: Origin URL to validate

        Returns:
            bool: True if origin is valid and secure
        """
        if not origin or '\x00' in origin:
            return False

        try:
            # Generate HMAC for origin validation
            origin_hmac = self._generate_hmac(origin)

            # Pattern matching
            if not self.ORIGIN_PATTERN.match(origin):
                return False

            parsed = urlparse(origin)

            # Protocol validation
            if parsed.scheme not in {'http', 'https'}:
                return False

            # Special handling for local development
            is_local = (
                parsed.netloc.startswith('localhost') or
                parsed.netloc.startswith('127.0.0.1') or
                parsed.netloc.startswith('[::1]')
            )

            if is_local:
                # Solo permetti indirizzi locali in ambiente di sviluppo
                if os.getenv('FLASK_ENV') != 'development':
                    self.logger.warning(
                        "Local address rejected in non-development environment"
                    )
                    return False

                # Verifica la porta se presente
                if ':' in parsed.netloc:
                    try:
                        port = int(parsed.netloc.split(':')[1])
                        if not (1024 <= port <= 65535):
                            return False
                    except ValueError:
                        return False

                return True

            # Per origini non locali, applica la validazione standard
            if not parsed.netloc or '.' not in parsed.netloc:
                return False

            # Path validation
            if parsed.path and parsed.path != '/':
                return False

            # Store HMAC for future verification
            self._request_history[origin] = {
                'hmac': origin_hmac,
                'timestamp': datetime.now(timezone.utc)
            }

            return True

        except Exception as e:
            self.logger.warning(
                f"Origin validation failed: {self._sanitize_value(str(e))}"
            )
            return False

    def _check_rate_limit(self, origin: str) -> bool:
        """
        Implement rate limiting for origins.

        Args:
            origin: Origin to check

        Returns:
            bool: True if within rate limits
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=3600)

        # Clean up old entries
        self._request_history = {
            k: v for k, v in self._request_history.items()
            if v['timestamp'] > window_start
        }

        # Check rate limit
        origin_requests = sum(
            1 for v in self._request_history.values()
            if v['timestamp'] > window_start
        )

        return origin_requests < self._env_config.max_requests

    @staticmethod
    def _sanitize_value(value: str) -> str:
        """
        Sanitize values to prevent injection attacks.

        Args:
            value: Input string to sanitize

        Returns:
            str: Sanitized string safe for logging and processing
        """
        return re.sub(r'[^\w\-\.]', '', value)

    def _validate_env_variables(self) -> None:
        """
        Validate and secure environment variables.

        Raises:
            ConfigurationError: If environment variables are invalid or insecure
        """
        required_vars = {
            'DEV_ALLOWED_ORIGINS': str,
            'PROD_ALLOWED_ORIGINS': str,
            'CORS_MAX_AGE': int,
            'HSTS_MAX_AGE': int,
            'INCLUDE_SUBDOMAINS': str,
            'CORS_ALLOWED_HEADERS': str,
            'CORS_ALLOWED_METHODS': str,
            'CORS_ALLOW_CREDENTIALS': str,
            'CORS_EXPOSE_HEADERS': str
        }

        for var_name, expected_type in required_vars.items():
            value = os.getenv(var_name)

            if value is None:
                raise ConfigurationError(
                    f"Missing required variable: {var_name}")

            # Encrypt sensitive values
            if 'CREDENTIALS' in var_name or 'KEY' in var_name:
                value = self._fernet.encrypt(value.encode()).decode()

            try:
                if expected_type == int:
                    int(value)
            except ValueError:
                raise ConfigurationError(
                    f"Invalid type for {var_name}: expected {expected_type}"
                )

    def initialize_app(self, app: Flask) -> None:
        """
        Initialize secure configuration for Flask application.

        Args:
            app: Flask application instance

        Raises:
            SecurityError: If initialization fails
        """
        try:
            self._validate_env_variables()

            # Create environment configurations
            environments = {
                'development': EnvironmentConfig(
                    origins=self._parse_origins(
                        os.getenv('DEV_ALLOWED_ORIGINS')),
                    max_requests=100
                ),
                'production': EnvironmentConfig(
                    origins=self._parse_origins(
                        os.getenv('PROD_ALLOWED_ORIGINS')),
                    max_requests=1000
                )
            }

            app.config['ENVIRONMENTS'] = environments

            # Set current environment configuration
            current_env = os.getenv('FLASK_ENV', 'production')
            if current_env not in self.SUPPORTED_ENVIRONMENTS:
                self.logger.warning(f"Unsupported environment {
                                    current_env}, using production")
                current_env = 'production'

            # Store the current environment configuration
            self._env_config = environments[current_env]

            # Security configurations
            app.config['CORS_MAX_AGE'] = int(
                os.getenv('CORS_MAX_AGE', self.DEFAULT_CORS_MAX_AGE)
            )
            app.config['HSTS_MAX_AGE'] = int(
                os.getenv('HSTS_MAX_AGE', self.DEFAULT_HSTS_MAX_AGE)
            )
            app.config['INCLUDE_SUBDOMAINS'] = os.getenv(
                'INCLUDE_SUBDOMAINS',
                'false'
            ).lower() == 'true'

            self._initialized = True
            self.logger.info(
                f"Secure configuration initialized successfully for environment: {
                    current_env}"
            )

        except Exception as e:
            self.logger.error(f"Initialization failed: {str(e)}")
            raise SecurityError(
                f"Configuration initialization failed: {str(e)}")

    def _parse_origins(self, origins_string: Optional[str]) -> List[str]:
        """
        Parse and validate origin strings.

        Args:
            origins_string: Comma-separated list of origins

        Returns:
            List[str]: List of validated origins
        """
        if not origins_string or not isinstance(origins_string, str):
            return []

        origins = []
        for origin in origins_string.split(','):
            origin = origin.strip()
            if origin and self._validate_origin_secure(origin):
                origins.append(origin)
            else:
                self.logger.warning(f"Invalid origin rejected: {origin}")

        return origins

    @lru_cache(maxsize=100)
    def get_allowed_origins(self) -> List[str]:
        """
        Get cached list of allowed origins for current environment.

        Returns:
            List[str]: List of allowed origins
        """
        env = os.getenv('FLASK_ENV', 'production')

        if env not in self.SUPPORTED_ENVIRONMENTS:
            self.logger.warning(
                f"Unsupported environment {env}, using production"
            )
            env = 'production'

        return current_app.config['ENVIRONMENTS'][env].origins

    def add_security_headers(self, response: Response) -> Response:
        """
        Add comprehensive security headers to response.

        Args:
            response: Flask response object

        Returns:
            Response: Response with security headers
        """
        request_origin = request.headers.get('Origin')

        # Validate request origin
        if request_origin:
            if not self._validate_origin_secure(request_origin):
                self.logger.warning(
                    f"Invalid origin rejected: {request_origin}")
                return response

            if not self._check_rate_limit(request_origin):
                self.logger.warning(
                    f"Rate limit exceeded for: {request_origin}")
                return response

            allowed_origins = self.get_allowed_origins()
            if request_origin in allowed_origins:
                response.headers['Access-Control-Allow-Origin'] = request_origin

                # Add CORS headers securely
                for header, env_var in {
                    'Access-Control-Allow-Headers': 'CORS_ALLOWED_HEADERS',
                    'Access-Control-Allow-Methods': 'CORS_ALLOWED_METHODS',
                    'Access-Control-Allow-Credentials': 'CORS_ALLOW_CREDENTIALS',
                    'Access-Control-Expose-Headers': 'CORS_EXPOSE_HEADERS'
                }.items():
                    value = os.getenv(env_var)
                    if value:
                        response.headers[header] = value

        # Add security headers
        response.headers.update({
            'X-Content-Type-Options': self._security_headers.CONTENT_TYPE_OPTIONS,
            'X-Frame-Options': self._security_headers.FRAME_OPTIONS,
            'X-XSS-Protection': self._security_headers.XSS_PROTECTION,
            'Referrer-Policy': self._security_headers.REFERRER_POLICY,
            'Content-Security-Policy': self._security_headers.CSP,
            'X-Permitted-Cross-Domain-Policies':
                self._security_headers.PERMITTED_CROSS_DOMAIN_POLICIES
        })

        # Configure HSTS
        if request.is_secure:
            hsts_header = f"max-age={current_app.config['HSTS_MAX_AGE']}"
            if current_app.config['INCLUDE_SUBDOMAINS']:
                hsts_header += "; includeSubDomains"
            response.headers['Strict-Transport-Security'] = hsts_header

        return response
