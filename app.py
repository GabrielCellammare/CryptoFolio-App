from flask import current_app, request
from typing import List, Dict
import base64
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from authlib.integrations.flask_client import OAuth
from firebase_admin import credentials, firestore, initialize_app
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
from crypto_utils import AESCipher
from cryptocache import CryptoCache
import os

from portfolio_encryption import PortfolioEncryption
from secure_bye_array import SecureByteArray
from security import CSRFProtection

# Application initialization


# First, load environment variables before any initialization
load_dotenv()


def parse_origins(origins_string: str) -> List[str]:
    """
    Converte una stringa di origins separati da virgole in una lista.
    Rimuove spazi extra e valori vuoti.
    """
    if not origins_string:
        return []
    return [origin.strip() for origin in origins_string.split(',') if origin.strip()]


def setup_environments_config() -> Dict:
    """
    Configura gli ambienti caricando i valori dal file .env
    """
    return {
        'development': {
            'origins': parse_origins(os.getenv('DEV_ALLOWED_ORIGINS',
                                               'http://localhost:5173,http://localhost:3000,http://localhost:5000,http://127.0.0.1:5173,http://127.0.0.1:5000,http://127.0.0.1:3000'))
        },
        'ngrok': {
            'origins': []  # Verrà popolato dinamicamente
        },
        'production': {
            'origins': parse_origins(os.getenv('PROD_ALLOWED_ORIGINS', ''))
        }
    }


def initialize_cors_config(app):
    """
    Inizializza la configurazione CORS nell'applicazione
    """
    app.config['ENVIRONMENTS'] = setup_environments_config()

    # Configurazioni di sicurezza aggiuntive dal .env
    app.config['CORS_MAX_AGE'] = int(os.getenv('CORS_MAX_AGE', '3600'))
    app.config['HSTS_MAX_AGE'] = int(os.getenv('HSTS_MAX_AGE', '31536000'))
    app.config['INCLUDE_SUBDOMAINS'] = os.getenv(
        'INCLUDE_SUBDOMAINS', 'true').lower() == 'true'


def get_allowed_origins() -> List[str]:
    """
    Recupera gli origins permessi in base all'ambiente corrente
    """
    env = os.getenv('FLASK_ENV', 'development')

    # Gestione speciale per ngrok in development
    if env == 'development':
        ngrok_url = os.getenv('NGROK_URL')
        if ngrok_url:
            current_app.config['ENVIRONMENTS']['ngrok']['origins'] = [
                ngrok_url]
            return (
                current_app.config['ENVIRONMENTS']['development']['origins'] +
                [ngrok_url]
            )

    return current_app.config['ENVIRONMENTS'].get(env, {}).get('origins', [])


def add_cors_headers(response):
    """
    Aggiunge gli headers CORS appropriati alla risposta
    """
    request_origin = request.headers.get('Origin')
    allowed_origins = get_allowed_origins()

    if request_origin and request_origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = request_origin

        # Headers CORS dal .env
        response.headers['Access-Control-Allow-Headers'] = os.getenv(
            'CORS_ALLOWED_HEADERS',
            'Content-Type, X-CSRF-Token, X-CSRF-Nonce, X-Requested-With, X-Client-Version'
        )

        response.headers['Access-Control-Allow-Methods'] = os.getenv(
            'CORS_ALLOWED_METHODS',
            'GET, POST, PUT, DELETE, OPTIONS'
        )

        response.headers['Access-Control-Allow-Credentials'] = os.getenv(
            'CORS_ALLOW_CREDENTIALS',
            'true'
        )

        response.headers['Access-Control-Expose-Headers'] = os.getenv(
            'CORS_EXPOSE_HEADERS',
            'Content-Type'
        )

        if request.method == 'OPTIONS':
            response.headers['Access-Control-Max-Age'] = str(
                current_app.config['CORS_MAX_AGE']
            )

    # Headers di sicurezza
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    if current_app.config['INCLUDE_SUBDOMAINS']:
        response.headers['Strict-Transport-Security'] = (
            f"max-age={current_app.config['HSTS_MAX_AGE']}; includeSubDomains"
        )
    else:
        response.headers['Strict-Transport-Security'] = (
            f"max-age={current_app.config['HSTS_MAX_AGE']}"
        )

    return response


def create_app():
    # Create Flask application instance
    app = Flask(__name__)
    initialize_cors_config(app)
    app.after_request(add_cors_headers)
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
        print(f"Firebase initialization error: {e}")
        raise

    # Verify master encryption key
    master_key = os.environ.get('MASTER_ENCRYPTION_KEY')
    if not master_key:
        raise ValueError(
            "MASTER_ENCRYPTION_KEY must be set in environment variables")

    return app


# Create the Flask application
app = create_app()
csrf = CSRFProtection(app)

# Initialize other components after app creation
db = firestore.client()
crypto_cache = CryptoCache()
cipher = AESCipher(os.environ.get('MASTER_ENCRYPTION_KEY'))
portfolio_encryption = PortfolioEncryption(cipher)

# OAuth Configuration


def configure_oauth(app):
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

    # Configure Google OAuth
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        server_metadata_url=os.getenv('SERVER_METADATA_URL_GOOGLE'),
        client_kwargs={'scope': 'openid email profile'}
    )

    # Configure GitHub OAuth
    oauth.register(
        name='github',
        client_id=os.getenv('GITHUB_CLIENT_ID'),
        client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={'scope': 'read:user user:email'}
    )

    return oauth


# Initialize OAuth after app creation
oauth = configure_oauth(app)


# Decorator for requiring login


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Login route


@app.route('/auth/login/<provider>')
def login(provider):
    """
    Handle login requests for different OAuth providers

    Args:
        provider (str): The OAuth provider ('google' or 'github')
    """
    if provider not in ['google', 'github']:
        flash('Invalid authentication provider', 'error')
        return redirect(url_for('index'))

    # Store the CSRF token in session before OAuth redirect
    csrf_token = csrf.generate_token()
    session['oauth_csrf'] = csrf_token

    return oauth.create_client(provider).authorize_redirect(
        url_for('auth_callback', provider=provider, _external=True), state=csrf_token
    )


# Authentication routes


@app.route('/auth/callback/<provider>')
def auth_callback(provider):
    """
    Handle OAuth callback for different providers (Google and GitHub)
    Implements secure user creation with proper email handling and encryption
    """
    try:
        if request.args.get('state') != session.get('oauth_csrf'):
            raise ValueError("Invalid CSRF state")

        # Create OAuth client for the specified provider
        client = oauth.create_client(provider)
        token = client.authorize_access_token()

        # Initialize variables we'll need for both providers
        user_id = None
        user_email = None
        username = None

        state = request.args.get('state')
        stored_state = session.get('oauth_csrf')

        print(f"Received state: {state}")
        print(f"Stored state: {stored_state}")
        print(f"Session contents: {dict(session)}")

        if state != stored_state:
            raise ValueError("Invalid CSRF state")

        # Handle Google authentication
        if provider == 'google':
            user_info = client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo').json()
            user_id = user_info.get('sub')
            user_email = user_info.get('email')
            username = user_info.get('name')

        # Handle GitHub authentication
        elif provider == 'github':
            # Get basic user info
            user_info = client.get('https://api.github.com/user').json()
            user_id = str(user_info.get('id'))
            username = user_info.get('name') or user_info.get('login')

            # Explicitly fetch email from GitHub's email endpoint
            try:
                email_response = client.get(
                    'https://api.github.com/user/emails')
                if email_response.status_code == 200:
                    email_data = email_response.json()
                    primary_email = next(
                        (email for email in email_data if email.get('primary')),
                        None
                    )
                    if primary_email:
                        user_email = primary_email.get('email')
                    else:
                        verified_email = next(
                            (email for email in email_data if email.get('verified')),
                            None
                        )
                        if verified_email:
                            user_email = verified_email.get('email')
            except Exception as email_error:
                print(f"Error fetching GitHub email: {email_error}")

        # Verify we have all required information
        if not all([user_id, user_email, username]):
            missing_fields = []
            if not user_id:
                missing_fields.append('user ID')
            if not user_email:
                missing_fields.append('email')
            if not username:
                missing_fields.append('username')
            raise ValueError(f"Missing required user information: {
                             ', '.join(missing_fields)}")

        # Generate salt and store user security info
        secure_salt = cipher.generate_salt()  # Returns SecureByteArray
        security_ref = db.collection('user_security').document(user_id)

        # Convert SecureByteArray to bytes before encoding
        salt_bytes = secure_salt.to_bytes()
        encoded_salt = base64.b64encode(salt_bytes).decode()

        # Store or update security information
        if not security_ref.get().exists:
            security_ref.set({
                'salt': encoded_salt,  # Now using properly encoded salt
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP
            })
        else:
            security_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        # Create or update user in Firebase
        user_ref = db.collection('users').document(user_id)

        if not user_ref.get().exists:
            # Encrypt sensitive information using the original SecureByteArray salt
            encrypted_email = cipher.encrypt(
                user_email,
                user_id,
                secure_salt  # Use the SecureByteArray directly here
            ).decode()

            # Create new user document
            user_ref.set({
                'username': username,
                'email': encrypted_email,
                'preferred_currency': 'USD',
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'provider': provider
            })
        else:
            # Update existing user's last login
            user_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        # Set session information
        session['user_id'] = user_id
        session['provider'] = provider

        # Create audit log for successful login
        db.collection('audit_logs').add({
            'user_id': user_id,
            'action': 'login',
            'provider': provider,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        })

        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:

        # Log the error securely
        error_ref = db.collection('error_logs').add({
            'error_type': 'authentication_error',
            'provider': provider,
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr
        })

        print(f"Authentication error: {e}")
        return jsonify({'error': 'Authentication failed', 'details': str(e)}), 401

    finally:
        # Clean up any remaining secure objects
        if 'secure_salt' in locals():
            secure_salt.secure_zero()
        session.pop('oauth_csrf', None)


@app.route('/auth/logout')
@csrf.csrf_protect
def logout():
    session.clear()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))

# Portfolio Management


def calculate_portfolio_metrics(portfolio_item, current_price, currency='USD'):
    """
    Calculate various metrics for a portfolio item with currency conversion

    Args:
        portfolio_item: Dictionary containing portfolio item data
        current_price: Current price of the cryptocurrency
        currency: Target currency (default: USD)

    Returns:
        Dictionary containing calculated metrics
    """
    try:
        # Assicuriamoci che i valori siano numerici
        amount = float(portfolio_item.get('amount', 0))
        purchase_price = float(portfolio_item.get('purchase_price', 0))

        # Assicuriamoci che current_price sia numerico
        current_price = float(current_price) if current_price else 0.0

        # Non abbiamo più bisogno della conversione di valuta qui perché
        # i prezzi arrivano già nella valuta corretta da get_crypto_prices

        current_value = amount * current_price
        purchase_value = amount * purchase_price

        # Evitiamo la divisione per zero
        profit_loss = current_value - purchase_value
        if purchase_value > 0:
            profit_loss_percentage = (current_value / purchase_value - 1) * 100
        else:
            profit_loss_percentage = 0

        return {
            'current_price': current_price,
            'current_value': current_value,
            'profit_loss': profit_loss,
            'profit_loss_percentage': profit_loss_percentage,
            'currency': currency
        }

    except Exception as e:
        print(f"Error in calculate_portfolio_metrics: {e}")
        # Ritorniamo valori di default in caso di errore
        return {
            'current_price': 0,
            'current_value': 0,
            'profit_loss': 0,
            'profit_loss_percentage': 0,
            'currency': currency
        }

# Main routes


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
@csrf.csrf_protect
def dashboard():
    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    security_ref = db.collection('user_security').document(user_id)

    try:
        user_data = user_ref.get().to_dict()
        security_data = security_ref.get().to_dict()

        if not security_data or 'salt' not in security_data:
            flash('Security configuration error. Please contact support.', 'error')
            # Genera token e nonce per il template
            csrf_token = csrf.generate_token()
            csrf_nonce = csrf.generate_nonce()

            return render_template('dashboard.html',
                                   portfolio=[],
                                   environment="development",
                                   total_value=0,
                                   currency='USD',
                                   csrf_token=csrf_token,
                                   csrf_nonce=csrf_nonce,
                                   last_update=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                   username=user_data.get('username'))

        salt = base64.b64decode(security_data['salt'])
        currency = user_data.get('preferred_currency', 'USD')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        portfolio_ref = db.collection('users').document(
            user_id).collection('portfolio')
        portfolio = []
        total_value = 0

        for doc in portfolio_ref.stream():
            try:
                encrypted_item = doc.to_dict()
                if not encrypted_item:
                    continue

                encrypted_item['id'] = doc.id

                # Decrypt portfolio item with enhanced error handling
                item = portfolio_encryption.decrypt_portfolio_item(
                    encrypted_item, user_id, salt)

                # Verify essential data after decryption
                if not item or not item.get('crypto_id'):
                    print(f"Invalid portfolio item data for {doc.id}")
                    continue

                # Get current price with error handling
                try:
                    crypto_prices = crypto_cache.get_crypto_prices(
                        [item['crypto_id']], currency)

                    current_price = (crypto_prices.get(item['crypto_id'], {})
                                     .get(currency.lower(), 0)
                                     if isinstance(crypto_prices, dict)
                                     else 0)
                except Exception as price_error:
                    print(f"Error fetching price for {
                          item['crypto_id']}: {price_error}")
                    current_price = 0

                # Calculate metrics with validated data
                metrics = calculate_portfolio_metrics(
                    item, current_price, currency)

                item.update(metrics)
                total_value += metrics['current_value']
                portfolio.append(item)

            except Exception as item_error:
                print(f"Error processing portfolio item {
                      doc.id}: {item_error}")
                db.collection('error_logs').add({
                    'error_type': 'portfolio_processing_error',
                    'item_id': doc.id,
                    'user_id': user_id,
                    'error_message': str(item_error),
                    'timestamp': firestore.SERVER_TIMESTAMP
                })
                continue

        csrf_token = csrf.generate_token()
        csrf_nonce = csrf.generate_nonce()
        return render_template('dashboard.html',
                               portfolio=portfolio,
                               total_value=total_value,
                               environment="development",
                               currency=currency,
                               csrf_token=csrf_token,
                               csrf_nonce=csrf_nonce,
                               last_update=current_time,
                               username=user_data.get('username'))

    except Exception as e:
        print(f"Dashboard error: {e}")
        db.collection('error_logs').add({
            'error_type': 'dashboard_error',
            'user_id': session.get('user_id'),
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return render_template('dashboard.html',
                               portfolio=[],
                               total_value=0,
                               currency='USD',
                               last_update=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                               username=user_data.get('username'))
# API Routes


@app.route('/api/cryptocurrencies')
@login_required
@csrf.csrf_protect
def get_cryptocurrencies():
    try:
        cryptos = crypto_cache.get_available_cryptocurrencies()
        return jsonify({'status': 'success', 'data': cryptos})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/portfolio/add', methods=['POST'])
@login_required
@csrf.csrf_protect
def add_portfolio():
    """
    Add a new portfolio item with secure encryption handling.
    Ensures proper conversion between SecureByteArray and bytes for all encrypted fields.
    """
    secure_salt = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        required_fields = ['crypto_id', 'symbol',
                           'amount', 'purchase_price', 'purchase_date']
        if not all(field in data for field in required_fields):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        user_id = session['user_id']

        # Retrieve the user's salt from security collection
        security_ref = db.collection('user_security').document(user_id)
        security_data = security_ref.get()

        if not security_data.exists:
            return jsonify({'status': 'error', 'message': 'Security credentials not found'}), 400

        # Convert stored base64 salt back to SecureByteArray
        encoded_salt = security_data.to_dict()['salt']
        secure_salt = SecureByteArray(base64.b64decode(encoded_salt))

        # Encrypt sensitive data using portfolio encryption handler
        encrypted_data = portfolio_encryption.encrypt_portfolio_item(
            data,
            user_id,
            secure_salt
        )

        # Store encrypted portfolio item
        portfolio_ref = db.collection('users').document(
            user_id).collection('portfolio')
        new_doc = portfolio_ref.add({
            'crypto_id': encrypted_data['crypto_id'],
            'symbol': encrypted_data['symbol'].upper(),
            'amount': encrypted_data['amount'],
            'purchase_price': encrypted_data['purchase_price'],
            'purchase_date': encrypted_data['purchase_date'],
            'created_at': firestore.SERVER_TIMESTAMP
        })

        # Create audit log for the addition
        audit_ref = db.collection('audit_logs').add({
            'user_id': user_id,
            'action': 'add_portfolio',
            'document_id': new_doc[1].id,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        })

        return jsonify({
            'status': 'success',
            'message': 'Cryptocurrency added successfully',
            'document_id': new_doc[1].id
        }), 201

    except Exception as e:
        # Log the error securely without exposing sensitive details
        error_ref = db.collection('error_logs').add({
            'error_type': 'portfolio_addition_error',
            'user_id': session.get('user_id'),
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'status': 'error', 'message': str(e)}), 500

    finally:
        # Clean up secure objects
        if secure_salt is not None:
            secure_salt.secure_zero()


@app.route('/api/portfolio/update/<doc_id>', methods=['PUT'])
@login_required
@csrf.csrf_protect
def update_portfolio(doc_id):
    """
    Update an existing portfolio item with secure encryption handling.
    Maintains encryption security while allowing partial updates of sensitive fields.
    """
    secure_salt = None
    try:
        data = request.get_json()
        required_fields = ['amount', 'purchase_price', 'purchase_date']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        user_id = session['user_id']

        # Retrieve user's salt from security collection
        security_ref = db.collection('user_security').document(user_id)
        security_data = security_ref.get()

        if not security_data.exists:
            return jsonify({'error': 'Security credentials not found'}), 400

        # Convert stored base64 salt to SecureByteArray
        encoded_salt = security_data.to_dict()['salt']
        secure_salt = SecureByteArray(base64.b64decode(encoded_salt))

        # Verify document ownership
        portfolio_ref = db.collection('users').document(
            user_id).collection('portfolio').document(doc_id)
        portfolio_doc = portfolio_ref.get()

        if not portfolio_doc.exists:
            return jsonify({'error': 'Portfolio item not found'}), 404

        # Create update data with only the fields that should be updated
        update_data = {
            'amount': data['amount'],
            'purchase_price': data['purchase_price'],
            'purchase_date': data['purchase_date']
        }

        # Encrypt the update data using portfolio encryption handler
        encrypted_update = portfolio_encryption.encrypt_portfolio_item(
            update_data,
            user_id,
            secure_salt
        )

        # Add timestamp to the update
        encrypted_update['updated_at'] = firestore.SERVER_TIMESTAMP

        # Update the document with encrypted data
        portfolio_ref.update(encrypted_update)

        # Create audit log for the update
        audit_ref = db.collection('audit_logs').add({
            'user_id': user_id,
            'action': 'update_portfolio',
            'document_id': doc_id,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        })

        return jsonify({
            'message': 'Portfolio item updated successfully',
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        # Log the error securely without exposing sensitive details
        error_ref = db.collection('error_logs').add({
            'user_id': session.get('user_id'),
            'action': 'update_portfolio',
            'error': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'error': 'An error occurred while updating the portfolio'}), 500

    finally:
        # Clean up secure objects
        if secure_salt is not None:
            secure_salt.secure_zero()


@app.route('/api/portfolio/delete/<doc_id>', methods=['DELETE'])
@login_required
@csrf.csrf_protect
def delete_portfolio(doc_id):
    """
    Securely delete a portfolio item while maintaining an encrypted backup.
    This implementation ensures that sensitive data remains protected during the deletion process
    and backup creation, while maintaining a complete audit trail.
    """
    secure_salt = None
    try:
        user_id = session['user_id']

        # First, verify user's security credentials and retrieve salt
        security_ref = db.collection('user_security').document(user_id)
        security_data = security_ref.get()

        if not security_data.exists:
            return jsonify({'error': 'Security credentials not found'}), 400

        # Convert the stored base64 salt to a SecureByteArray for encryption operations
        encoded_salt = security_data.to_dict()['salt']
        secure_salt = SecureByteArray(base64.b64decode(encoded_salt))

        # Get reference to the portfolio item and verify ownership
        portfolio_ref = db.collection('users').document(
            user_id).collection('portfolio').document(doc_id)
        portfolio_doc = portfolio_ref.get()

        if not portfolio_doc.exists:
            return jsonify({'error': 'Portfolio item not found'}), 404

        # Retrieve the current data before deletion
        portfolio_data = portfolio_doc.to_dict()

        # Create a backup with additional metadata
        backup_data = {
            'original_id': doc_id,
            'user_id': user_id,
            'portfolio_data': portfolio_data,
            'deletion_date': firestore.SERVER_TIMESTAMP,
            'deletion_metadata': {
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string,
                'deletion_reason': request.args.get('reason', 'Not specified')
            }
        }

        # Store encrypted backup in the deleted_portfolios collection
        backup_ref = db.collection('deleted_portfolios').document()
        backup_ref.set(backup_data)

        # Before deleting, fetch any associated files or additional data
        # that might need to be cleaned up
        try:
            associated_files_ref = db.collection(
                'portfolio_files').where('portfolio_id', '==', doc_id)
            associated_files = associated_files_ref.get()

            # Delete any associated files
            for file_doc in associated_files:
                file_doc.reference.delete()
        except Exception as file_error:
            # Log file deletion errors but continue with main deletion
            print(f"Error cleaning up associated files: {file_error}")

        # Delete the main portfolio document
        portfolio_ref.delete()

        # Create a detailed audit log for the deletion
        audit_log_data = {
            'user_id': user_id,
            'action': 'delete_portfolio',
            'document_id': doc_id,
            'backup_id': backup_ref.id,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'deletion_metadata': {
                'reason': request.args.get('reason', 'Not specified'),
                'associated_files_cleaned': bool(associated_files) if 'associated_files' in locals() else False
            }
        }

        audit_ref = db.collection('audit_logs').add(audit_log_data)

        # Return success response with backup reference
        return jsonify({
            'message': 'Portfolio item deleted successfully',
            'backup_id': backup_ref.id,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        # Log the error securely without exposing sensitive details
        error_log_data = {
            'user_id': session.get('user_id'),
            'action': 'delete_portfolio',
            'error': str(e),
            'document_id': doc_id,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'error_type': 'portfolio_deletion_error'
        }

        error_ref = db.collection('error_logs').add(error_log_data)

        return jsonify({
            'error': 'An error occurred while deleting the portfolio item',
            'error_reference': error_ref.id
        }), 500

    finally:
        # Clean up any secure objects
        if secure_salt is not None:
            secure_salt.secure_zero()

# Currency Preference Routes

# Add these routes to app.py


@app.route('/api/preferences/currency', methods=['GET'])
@login_required
@csrf.csrf_protect
def get_currency_preference():
    user_ref = db.collection('users').document(session['user_id'])
    user_data = user_ref.get().to_dict()
    return jsonify({'currency': user_data.get('preferred_currency', 'USD')})


@app.route('/api/preferences/currency', methods=['PUT'])
@login_required
@csrf.csrf_protect
def update_currency_preference():
    try:
        data = request.get_json()
        currency = data.get('currency', 'USD').upper()

        if currency not in ['USD', 'EUR']:
            return jsonify({'error': 'Invalid currency'}), 400

        user_ref = db.collection('users').document(session['user_id'])
        user_ref.update({'preferred_currency': currency})

        return jsonify({'message': 'Currency preference updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/csrf/nonce', methods=['GET'])
@login_required
def refresh_csrf_nonce():
    """
    Generate and return a new CSRF nonce.
    This route is called by the frontend to get a fresh nonce for each request that modifies data.

    Returns:
        JSON response containing:
        - new nonce value
        - expiration timestamp
        - status message
    """
    try:
        # Generate a new nonce using the CSRF protection instance
        new_nonce = csrf.generate_nonce()

        # Get the expiration time for this nonce
        expiration_time = csrf.used_nonces.get(new_nonce)

        # Convert timestamp to ISO format for frontend
        expiration_iso = datetime.fromtimestamp(
            expiration_time).isoformat() if expiration_time else None

        # Return the new nonce in the response
        response_data = {
            'status': 'success',
            'nonce': new_nonce,
            'expires': expiration_iso
        }

        # Create an audit log entry for nonce generation
        db.collection('audit_logs').add({
            'user_id': session.get('user_id'),
            'action': 'nonce_refresh',
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        })

        return jsonify(response_data)

    except Exception as e:
        # Log the error securely
        db.collection('error_logs').add({
            'error_type': 'nonce_generation_error',
            'user_id': session.get('user_id'),
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })

        return jsonify({
            'status': 'error',
            'message': 'Failed to generate security token'
        }), 500


if __name__ == '__main__':
    app.run(debug=True)
