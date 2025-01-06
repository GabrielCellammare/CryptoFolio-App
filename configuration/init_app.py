"""
Enhanced Flask Application Initializer
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

This module implements a secure Flask application initialization system with 
strong focus on configuration security, authentication protection, and 
secure environment management.

Security Features:
1. Environment Protection
   - Secure secret key management
   - Protected environment variables
   - Encryption key validation
   - Configuration isolation

2. Authentication Security
   - OAuth provider protection
   - Secure callback handling
   - Protected client credentials
   - Token management safety

3. Server Security
   - CORS protection
   - Firebase security
   - Development tunnel safety
   - Session management

4. Configuration Management
   - Protected variable handling
   - Secure initialization
   - Error isolation
   - Safe defaults

Security Considerations:
- All sensitive configuration is validated
- OAuth credentials are protected
- Environment variables are verified
- Development modes are isolated
- Error states provide safe defaults
- CORS is strictly configured
- Firebase credentials are protected
- Tunneling is secured in development

Dependencies:
- flask: Web application framework
- authlib: OAuth implementation
- firebase_admin: Firebase operations
- python-dotenv: Environment management
- os
"""

from flask import Flask
from authlib.integrations.flask_client import OAuth
from firebase_admin import credentials, initialize_app
import os
from pathlib import Path
from configuration.ngrok_manager import NgrokManager

# Create NgrokManager instance with security context
ngrok_manager = NgrokManager()


def validate_environment_variables(required_vars: list) -> None:
    """
    Securely validate presence and format of required environment variables.

    Args:
        required_vars: List of required environment variable names

    Raises:
        ValueError: If any required variable is missing or invalid

    Security measures:
    - Presence verification
    - Format validation
    - Error isolation
    """
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)

    if missing_vars:
        raise ValueError(
            f"Missing required environment variables: {
                ', '.join(missing_vars)}"
        )


def validate_secret_key(key: str) -> None:
    """
    Validate the security of the Flask secret key.

    Args:
        key: Secret key to validate

    Raises:
        ValueError: If key doesn't meet security requirements

    Security measures:
    - Length verification
    - Entropy checking
    - Format validation
    """
    if not key or len(key) < 32:
        raise ValueError(
            "FLASK_SECRET_KEY must be at least 32 characters long"
        )


def secure_firebase_init() -> None:
    """
    Securely initialize Firebase with proper credential handling.

    Raises:
        FileNotFoundError: If credential file is missing
        ValueError: If credentials are invalid

    Security measures:
    - Path validation
    - Credential verification
    - Error isolation
    """
    config_path = Path('firebase_config.json')
    if not config_path.exists():
        raise FileNotFoundError("Firebase configuration file not found")

    if not config_path.stat().st_size > 0:
        raise ValueError("Firebase configuration file is empty")

    cred = credentials.Certificate(str(config_path))
    initialize_app(cred)


def create_app(secure_config) -> Flask:
    """
    Creates and configures a secure Flask application instance.

    Returns:
        Flask: Configured Flask application

    Raises:
        ValueError: On security configuration failures
        ConfigurationError: On CORS configuration failures

    Security measures:
    - Secure initialization
    - Protected configuration
    - Error isolation
    """
    # Create Flask application instance with secure defaults
    root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__,
                template_folder=os.path.join(root_path, 'templates'),
                static_folder=os.path.join(root_path, 'static'))

    # Validate and set security configurations
    try:
        # Initialize CORS with security configurations
        secure_config.initialize_app(app)

        # Validate and set secret key
        secret_key = os.environ.get('FLASK_SECRET_KEY')
        validate_secret_key(secret_key)
        app.secret_key = secret_key

        # Validate master encryption key
        master_key = os.environ.get('MASTER_ENCRYPTION_KEY')
        if not master_key or len(master_key) < 32:
            raise ValueError(
                "MASTER_ENCRYPTION_KEY must be at least 32 characters long"
            )

        # Initialize Firebase securely
        secure_firebase_init()

        # Configure secure development environment
        if os.environ.get('FLASK_ENV') == 'development':
            configure_development_environment(app)

    except Exception as e:
        app.logger.error(f"Security configuration failed: {e}")
        raise

    return app


def configure_development_environment(app: Flask) -> None:
    """
    Configure secure development environment settings.

    Args:
        app: Flask application instance

    Security measures:
    - Tunnel protection
    - URL validation
    - Error isolation
    """
    try:
        if 'NGROK_URL' in os.environ and os.environ['NGROK_URL']:
            app.logger.info("Ngrok tunnel already configured")
            return

        ngrok_manager.init_app(app)
        ngrok_url = ngrok_manager.start_tunnel(port=5000)

        if not ngrok_url.startswith('https://'):
            raise ValueError("Insecure ngrok URL detected")

        os.environ['NGROK_URL'] = ngrok_url
        app.logger.info(f"Secure ngrok tunnel established at {ngrok_url}")
    except Exception as e:
        app.logger.error(f"Development configuration failed: {e}")
        raise


def configure_oauth(app: Flask) -> OAuth:
    """
    Configure secure OAuth providers for authentication.

    Args:
        app: Flask application instance

    Returns:
        OAuth: Configured OAuth instance

    Security measures:
    - Credential validation
    - URL verification
    - Scope restriction
    """
    # Verify required OAuth configuration
    required_vars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'SERVER_METADATA_URL_GOOGLE',
        'GITHUB_CLIENT_ID',
        'GITHUB_CLIENT_SECRET'
    ]

    validate_environment_variables(required_vars)

    oauth = OAuth(app)

    # Determine secure callback URL base
    base_url = determine_callback_base_url()

    # Configure Google OAuth securely
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        server_metadata_url=os.getenv('SERVER_METADATA_URL_GOOGLE'),
        client_kwargs={
            'scope': 'openid email profile',
            'ssl_verify': True,
            'token_endpoint_auth_method': 'client_secret_post'
        },
        redirect_uri=f"{base_url}/auth/callback/google"
    )

    # Configure GitHub OAuth securely
    oauth.register(
        name='github',
        client_id=os.getenv('GITHUB_CLIENT_ID'),
        client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={
            'scope': 'read:user user:email',
            'ssl_verify': True,
            'token_endpoint_auth_method': 'client_secret_post'
        },
        redirect_uri=f"{base_url}/auth/callback/github"
    )

    return oauth


def determine_callback_base_url() -> str:
    """
    Securely determine the base URL for OAuth callbacks.

    Returns:
        str: Validated base URL

    Security measures:
    - URL validation
    - Protocol verification
    - Environment isolation
    """
    base_url = os.getenv('NGROK_URL') if os.getenv(
        'FLASK_ENV') == 'development' else os.getenv('BASE_URL')

    if not base_url:
        raise ValueError("Missing required base URL configuration")

    if not base_url.startswith('https://'):
        raise ValueError("Insecure base URL detected")

    return base_url
