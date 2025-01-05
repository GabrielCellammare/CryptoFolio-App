from typing import Optional
from flask import Flask
from authlib.integrations.flask_client import OAuth
from firebase_admin import credentials, initialize_app
from dotenv import load_dotenv
from config import Config, ConfigurationError
import os

from ngrok_manager import NgrokManager

# Create NgrokManager instance
ngrok_manager = NgrokManager()


def create_app():
    """
    Creates and configures the Flask application with all necessary settings and initializations.

    Initializes:
    - CORS configuration
    - Secret key
    - Firebase connection
    - Encryption keys

    Returns:
        Flask: Configured Flask application instance

    Raises:
        ValueError: If required environment variables are missing
        ConfigurationError: If CORS configuration fails
        FirebaseError: If Firebase initialization fails
    """
    # Create Flask application instance
    app = Flask(__name__)

    # Initialize CORS configuration - this sets up all CORS-related settings
    try:
        Config.initialize_cors_config(app)
    except ConfigurationError as e:
        app.logger.error(f"Failed to initialize CORS configuration: {e}")
        raise

    # Set secret key
    app.secret_key = os.environ.get('FLASK_SECRET_KEY')
    if not app.secret_key:
        raise ValueError(
            "FLASK_SECRET_KEY must be set in environment variables")

    # Initialize Firebase
    try:
        cred = credentials.Certificate('firebase_config.json')
        initialize_app(cred)
    except Exception as e:
        app.logger.error(f"Firebase initialization error: {e}")
        raise

    # Verify master encryption key
    master_key = os.environ.get('MASTER_ENCRYPTION_KEY')
    if not master_key:
        raise ValueError(
            "MASTER_ENCRYPTION_KEY must be set in environment variables")

    # Initialize ngrok in development environment
    if os.environ.get('FLASK_ENV') == 'development':
        ngrok_manager.init_app(app)
        try:
            ngrok_url = ngrok_manager.start_tunnel(port=5000)
            os.environ['NGROK_URL'] = ngrok_url
            app.logger.info(f"ngrok tunnel established at: {ngrok_url}")
        except Exception as e:
            app.logger.error(f"Failed to establish ngrok tunnel: {e}")

    return app


# OAuth Configuration


def configure_oauth(app):
    """
    Configures OAuth providers (Google and GitHub) for user authentication.

    Args:
        app (Flask): Flask application instance

    Returns:
        OAuth: Configured OAuth instance

    Raises:
        ValueError: If required OAuth environment variables are missing
    """

    # Verify required environment variables
    required_vars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'SERVER_METADATA_URL_GOOGLE',
        'GITHUB_CLIENT_ID',
        'GITHUB_CLIENT_SECRET'
    ]

    for var in required_vars:
        if not os.getenv(var):
            raise ValueError(f"Missing required environment variable: {var}")

    oauth = OAuth(app)

    # Get the base URL for callbacks
    base_url = os.getenv('NGROK_URL') if os.getenv(
        'FLASK_ENV') == 'development' else os.getenv('BASE_URL')

    # Configure Google OAuth with dynamic callback URL
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        server_metadata_url=os.getenv('SERVER_METADATA_URL_GOOGLE'),
        client_kwargs={'scope': 'openid email profile'},
        redirect_uri=f"{base_url}/auth/callback/google"
    )

    # Configure GitHub OAuth with dynamic callback URL
    oauth.register(
        name='github',
        client_id=os.getenv('GITHUB_CLIENT_ID'),
        client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={'scope': 'read:user user:email'},
        redirect_uri=f"{base_url}/auth/callback/github"
    )

    return oauth
