import os
import logging
from typing import List, Dict, Optional
from functools import lru_cache
from urllib.parse import urlparse
from flask import current_app, request, Flask, Response


class ConfigurationError(Exception):
    """Custom exception for configuration errors."""
    pass


class Config:
    """
    Manages CORS and security configuration for the Flask application.

    This class provides methods to:
    - Configure allowed origins for different environments
    - Manage CORS headers
    - Implement security measures like HSTS

    Required environment variables:
    - DEV_ALLOWED_ORIGINS: allowed origins in development
    - PROD_ALLOWED_ORIGINS: allowed origins in production
    - CORS_MAX_AGE: preflight cache duration
    - HSTS_MAX_AGE: HSTS policy duration
    - INCLUDE_SUBDOMAINS: include subdomains in HSTS
    - CORS_ALLOWED_HEADERS: allowed CORS headers
    - CORS_ALLOWED_METHODS: allowed HTTP methods
    - CORS_ALLOW_CREDENTIALS: manage credentials
    - CORS_EXPOSE_HEADERS: exposed headers
    """

    # Constants for default values
    DEFAULT_CORS_MAX_AGE: int = 86400  # 24 hours
    DEFAULT_HSTS_MAX_AGE: int = 31536000  # 1 year
    SUPPORTED_ENVIRONMENTS: set = {'development', 'ngrok', 'production'}

    # Logging configuration
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    @classmethod
    def validate_env_variables(cls) -> None:
        """
        Validates the presence and format of required environment variables.

        Raises:
            ConfigurationError: If environment variables are missing or have invalid values.
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
                    f"Missing environment variable: {var_name}")

            try:
                if expected_type == int:
                    int(value)
            except ValueError:
                raise ConfigurationError(
                    f"Variable {
                        var_name} must be an integer, received: {value}"
                )

    @staticmethod
    def validate_origin(origin: str) -> bool:
        """
        Validates that the origin is a valid URL and meets security criteria.

        Args:
            origin: URL to validate

        Returns:
            bool: True if the origin is valid, False otherwise
        """
        if not origin:
            return False

        try:
            result = urlparse(origin)
            return all([
                result.scheme in ['http', 'https'],
                result.netloc,
                not result.path or result.path == '/'
            ])
        except Exception as e:
            Config.logger.warning(
                f"Error validating origin {origin}: {e}")
            return False

    @classmethod
    def parse_origins(cls, origins_string: Optional[str]) -> List[str]:
        """
        Converts a comma-separated string of origins into a list of valid origins.

        Args:
            origins_string: String containing comma-separated origins

        Returns:
            List[str]: List of valid origins
        """
        if not origins_string:
            return []

        if not isinstance(origins_string, str):
            cls.logger.error(f"origins_string must be a string, received: {
                             type(origins_string)}")
            return []

        origins = []
        for origin in origins_string.split(','):
            origin = origin.strip()
            if origin and cls.validate_origin(origin):
                origins.append(origin)
            else:
                cls.logger.warning(f"Invalid origin ignored: {origin}")

        return origins

    @classmethod
    def setup_environments_config(cls) -> Dict:
        """
        Configures environments by loading values from the .env file.

        Returns:
            Dict: Configuration for each environment
        """
        cls.validate_env_variables()

        return {
            'development': {
                'origins': cls.parse_origins(os.getenv('DEV_ALLOWED_ORIGINS'))
            },
            'ngrok': {
                'origins': []  # Populated dynamically
            },
            'production': {
                'origins': cls.parse_origins(os.getenv('PROD_ALLOWED_ORIGINS'))
            }
        }

    @classmethod
    def initialize_cors_config(cls, app: Flask) -> None:
        """
        Initializes the CORS configuration in the application.

        Args:
            app: Flask application instance
        """
        try:
            app.config['ENVIRONMENTS'] = cls.setup_environments_config()

            # Additional security configurations
            app.config['CORS_MAX_AGE'] = int(
                os.getenv('CORS_MAX_AGE', cls.DEFAULT_CORS_MAX_AGE)
            )
            app.config['HSTS_MAX_AGE'] = int(
                os.getenv('HSTS_MAX_AGE', cls.DEFAULT_HSTS_MAX_AGE)
            )
            app.config['INCLUDE_SUBDOMAINS'] = os.getenv(
                'INCLUDE_SUBDOMAINS', 'false'
            ).lower() == 'true'

            cls.logger.info("CORS configuration initialized successfully")

        except Exception as e:
            cls.logger.error(
                f"Error initializing CORS configuration: {e}")
            raise

    @classmethod
    @lru_cache(maxsize=1)
    def get_allowed_origins(cls) -> List[str]:
        """
        Retrieves the allowed origins based on the current environment.
        Uses caching to improve performance.

        Returns:
            List[str]: List of allowed origins
        """
        env = os.getenv('FLASK_ENV')
        if env not in cls.SUPPORTED_ENVIRONMENTS:
            cls.logger.warning(f"Unsupported environment: {
                               env}, using production")
            env = 'production'

        # Special handling for ngrok in development
        if env == 'development':
            ngrok_url = os.getenv('NGROK_URL')
            if ngrok_url and cls.validate_origin(ngrok_url):
                cls.logger.info(f"Added ngrok URL: {ngrok_url}")
                current_app.config['ENVIRONMENTS']['ngrok']['origins'] = [
                    ngrok_url]
                return (
                    current_app.config['ENVIRONMENTS']['development']['origins'] +
                    [ngrok_url]
                )

        return current_app.config['ENVIRONMENTS'].get(env, {}).get('origins', [])

    @classmethod
    def add_cors_headers(cls, response: Response) -> Response:
        """
        Adds appropriate CORS headers to the response.

        Args:
            response: Flask response object

        Returns:
            response: Response with added CORS headers
        """
        request_origin = request.headers.get('Origin')
        allowed_origins = cls.get_allowed_origins()

        cls.logger.debug(f"Request origin: {request_origin}")
        cls.logger.debug(f"Allowed origins: {allowed_origins}")

        if request_origin and request_origin in allowed_origins:
            # Standard CORS headers
            response.headers['Access-Control-Allow-Origin'] = request_origin
            response.headers['Access-Control-Allow-Headers'] = os.getenv(
                'CORS_ALLOWED_HEADERS'
            )
            response.headers['Access-Control-Allow-Methods'] = os.getenv(
                'CORS_ALLOWED_METHODS'
            )
            response.headers['Access-Control-Allow-Credentials'] = os.getenv(
                'CORS_ALLOW_CREDENTIALS'
            )
            response.headers['Access-Control-Expose-Headers'] = os.getenv(
                'CORS_EXPOSE_HEADERS'
            )

            if request.method == 'OPTIONS':
                response.headers['Access-Control-Max-Age'] = str(
                    current_app.config['CORS_MAX_AGE']
                )

        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'

        # HSTS configuration
        hsts_header = f"max-age={current_app.config['HSTS_MAX_AGE']}"
        if current_app.config['INCLUDE_SUBDOMAINS']:
            hsts_header += "; includeSubDomains"
        response.headers['Strict-Transport-Security'] = hsts_header

        return response
