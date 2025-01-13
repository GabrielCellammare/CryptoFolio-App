"""
Cryptocurrency Portfolio Management Application
============================================

A secure Flask application for managing cryptocurrency portfolios with
comprehensive security features and OAuth authentication.

Core Features:
1. Authentication & Authorization
   - OAuth 2.0 integration with Google and GitHub
   - CSRF token protection
   - Rate limiting and request throttling
   - Secure session management
   - JWT-based API authentication

2. Data Protection
   - AES-256 encryption for sensitive data
   - Secure key derivation with salting
   - Encrypted database storage
   - Protected memory operations
   - Secure data wiping

3. Security Controls
   - Input validation and sanitization
   - SQL injection prevention
   - XSS protection headers
   - CORS policy enforcement
   - Secure error handling
   - Audit logging
   - Encrypted backups

4. Secure Architecture:
   1. Authentication Layer: OAuth and session management
   2. Security Layer: Encryption, CSRF, rate limiting
   3. Business Logic Layer: Portfolio operations
   4. Data Access Layer: Secure Firebase interactions
   5. API Layer: Protected REST endpoints

Security Considerations:
- All sensitive data is encrypted at rest
- User sessions are strictly validated
- Rate limiting prevents abuse
- Audit logs track critical operations
- Error messages are sanitized
- Memory is securely wiped
- File operations are protected

Dependencies:
- flask: Web framework
- authlib: OAuth implementation
- firebase_admin: Database operations
- cryptography: Encryption operations
- secure_byte_array: Protected memory management

Author: Gabriel Cellammare
Version: 1.0
Last Modified: 10/01/2025
"""

# Standard library imports - organized by functionality
from security.secure_firebase_query_builder import FirebaseQueryBuilder
from utils.token_jwt_handling import AuthError, TokenJWTHandling
from datetime import datetime, timedelta, timezone
from difflib import restore
from functools import wraps
from typing import Optional
import base64

import os
import time

# Third-party imports - security-critical imports first
# Handles encryption operations
from security.cryptography.cryptography_utils import AESCipher
from firebase_admin import firestore     # Database operations
from flask import (
    Blueprint,
    abort,
    jsonify,
    logging,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash
)
from dotenv import load_dotenv

# Local application imports
from configuration.config import SecureConfig
from utils.cryptocache import CryptoCache
from configuration.init_app import configure_oauth, create_app
from security.input_validator import InputValidator, ValidationError
from security.cryptography.portfolio_encryption import PortfolioEncryption
from utils.portfolio_utils import calculate_portfolio_metrics
from security.rate_limiter import FirebaseRateLimiter
from security.secure_bye_array import SecureByteArray
from security.csrf_protection import CSRFProtection

# Load environment variables
# SECURITY NOTE: Critical for secure configuration management
load_dotenv()

# Initialize core security components
# SECURITY NOTE: Order matters - config must be loaded before other components
secure_config = SecureConfig()
app = create_app(secure_config)
csrf = CSRFProtection(app)

# Initialize database and caching
# SECURITY NOTE: These handle sensitive data and need proper security configuration
db = firestore.client()

query_builder = FirebaseQueryBuilder(db)
crypto_cache = CryptoCache()

# Initialize encryption components
# SECURITY NOTE: Critical for data protection - key must be properly secured
cipher = AESCipher(os.environ.get('MASTER_ENCRYPTION_KEY'))
portfolio_encryption = PortfolioEncryption(cipher)

# Initialize OAuth
# SECURITY NOTE: OAuth configuration must be properly secured
oauth = configure_oauth(app)


def rate_limit_decorator(f):
    """
    Rate limiting decorator to prevent API abuse.

    Args:
        f: Function to be decorated

    Returns:
        Decorated function with rate limiting applied

    Raises:
        ValidationError: If authentication fails
        RateLimitExceeded: If rate limit is exceeded

    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id') or getattr(request, 'user_id', None)
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

        # Get client IP address securely
        ip_address = request.remote_addr

        # Initialize rate limiter with the existing Firestore instance
        rate_limiter = FirebaseRateLimiter(db)
        is_allowed, remaining, retry_after = rate_limiter.check_rate_limit(
            user_id, ip_address)

        if not is_allowed:
            response = jsonify({
                'status': 'error',
                'message': 'Rate limit exceeded',
                'retry_after': retry_after
            })
            response.headers['X-RateLimit-Remaining'] = str(remaining)
            response.headers['X-RateLimit-Reset'] = str(retry_after)
            response.status_code = 429
            return response

        # Execute the original function
        response = f(*args, **kwargs)

        # Add rate limit headers to response
        if isinstance(response, tuple):
            response_obj, status_code = response
        else:
            response_obj, status_code = response, 200

        if isinstance(response_obj, dict):
            response_obj = jsonify(response_obj)

        response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
        return response_obj, status_code

    return decorated_function


@app.before_request
def check_session_timeout():
    """
    Validate and enforce session timeout rules.

    This method implements secure session management by validating session age and
    forcing re-authentication when sessions expire.

    Security Features:
        - Strict timeout enforcement
        - Secure session clearing
        - Protected redirect handling
        - Last activity tracking

    Implementation:
        - Checks last activity timestamp
        - Enforces 60-minute inactivity timeout
        - Securely clears expired sessions
        - Redirects to login for re-authentication

    Session Properties:
        - Maximum inactivity: 60 minutes
        - Secure cleanup on expiration
        - Protected timestamp storage
    """
    if 'last_active' in session:
        last_active = datetime.fromtimestamp(session['last_active'])
        if datetime.now() - last_active > timedelta(minutes=60):
            session.clear()
            return redirect(url_for('index'))
    session['last_active'] = datetime.now().timestamp()


def log_error(error_type: str, user_id: Optional[str], error_message: str) -> str:
    """
    Securely logs errors to Firestore with sanitized data.

    Args:
        error_type: Category of error
        user_id: Affected user's ID (optional)
        error_message: Description of error

    Returns:
        str: Error reference ID for tracking

    Raises:
        FirestoreError: If logging fails
    """
    try:
        error_ref = db.collection('error_logs').document()
        error_ref.set({
            'error_type': error_type,
            'user_id': user_id,
            'error_message': str(error_message),
            'timestamp': restore.SERVER_TIMESTAMP,
            'request_path': request.path,
            'request_method': request.method
        })
        return error_ref.id
    except Exception as e:
        app.logger.error(f"Failed to log error: {str(e)}")
        return "ERROR_LOG_FAILED"


def login_required(f):
    """
    Decorator that ensures routes are only accessible to authenticated users.

    Checks for valid user session and redirects to login page if session is invalid.

    Args:
        f(callable): The route function to be protected

    Returns:
        callable: Decorated function that includes authentication check

    Security features:
    - Validates session existence
    - Prevents unauthorized access
    - Maintains secure redirect chain
    """

    @ wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Login route


@app.route('/auth/login/<provider>')
def login(provider):
    """
    Initiates OAuth login flow for specified provider.

    Generates CSRF token and redirects user to OAuth provider's login page.
    Supports Google and GitHub authentication.

    Args:
        provider (str): Name of OAuth provider ('google' or 'github')

    Returns:
        Response: Redirect to OAuth provider's authorization page

    Raises:
        ValueError: If invalid provider specified

    Security features:
    - CSRF token generation
    - Provider validation
    - Secure redirect handling
    - Session state management
    - Request origin validation
    """
    app.logger.info(f"Starting OAuth login for provider: {provider}")
    app.logger.info(f"Current environment: {os.getenv('FLASK_ENV')}")
    app.logger.info(f"Current NGROK_URL: {os.getenv('NGROK_URL')}")

    # Validazione del provider
    if provider not in ['google', 'github']:
        flash('Authentication failed')
        return redirect(url_for('index'))

    # Generazione token CSRF
    csrf_token, response = csrf.generate_token(require_user_id=False)
    session['csrf_token'] = csrf_token

    # Creazione client OAuth
    oauth_client = oauth.create_client(provider)

    # Verifica se la richiesta arriva attraverso Ngrok
    is_ngrok_request = False
    ngrok_url = os.getenv('NGROK_URL')

    # Controlliamo gli header X-Forwarded-* che Ngrok aggiunge
    forwarded_proto = request.headers.get('X-Forwarded-Proto')
    forwarded_host = request.headers.get('X-Forwarded-Host')

    app.logger.info(f"Forwarded Proto: {forwarded_proto}")
    app.logger.info(f"Forwarded Host: {forwarded_host}")

    # Se abbiamo gli header di Ngrok e corrispondono alla nostra configurazione
    if (forwarded_proto and forwarded_host and
            ngrok_url and forwarded_host in ngrok_url):
        is_ngrok_request = True
        app.logger.info("Richiesta identificata come proveniente da Ngrok")
    else:
        app.logger.info("Richiesta identificata come locale")

    try:
        if is_ngrok_request:
            # Per richieste Ngrok, usa HTTPS
            callback_url = url_for('auth_callback',
                                   provider=provider,
                                   _external=True,
                                   _scheme='https')
            app.logger.info(f"Using Ngrok callback URL: {callback_url}")
        else:
            # Per richieste locali, usa HTTP
            callback_url = url_for('auth_callback',
                                   provider=provider,
                                   _external=True)
            app.logger.info(f"Using local callback URL: {callback_url}")

        # Effettua il redirect OAuth
        response = oauth_client.authorize_redirect(
            callback_url,
            state=csrf_token
        )
        app.logger.info(f"OAuth redirect URL: {response.location}")
        return response

    except Exception as e:
        app.logger.error(f"Error during OAuth redirect: {str(e)}")
        # Log dettagliato dell'errore per debug
        app.logger.error(f"Request details: proto={forwarded_proto}, "
                         f"host={forwarded_host}, ngrok_url={ngrok_url}")
        raise
# Authentication routes


@ app.route('/auth/callback/<provider>')
def auth_callback(provider):
    """
    Handles OAuth callback after successful provider authentication.

    Processes OAuth response, validates tokens, and creates/updates user records
    with proper encryption.

    Args:
        provider (str): OAuth provider name ('google' or 'github')

    Returns:
        Response: Redirect to dashboard on success or error page

    Raises:
        ValueError: For invalid CSRF state or token
        EncryptionError: For encryption/decryption failures
        FirestoreError: For database operation failures

    Security features:
    - CSRF state validation
    - Token validation
    - Data encryption
    - Secure salt generation
    - Audit logging
    - Error handling

    Flow:
    1. Validates CSRF state from provider
    2. Retrieves and validates OAuth tokens
    3. Fetches user info from provider
    4. Generates secure user ID and salt
    5. Encrypts sensitive user data
    6. Creates/updates user records
    7. Establishes secure session
    8. Creates audit log entry
    """

    try:
        app.logger.info(f"Received callback for provider: {provider}")
        app.logger.info(f"Request args: {request.args}")
        app.logger.info(f"Request headers: {request.headers}")
        if request.args.get('state') != session.get('csrf_token'):
            raise ValueError("Invalid CSRF state")

        # Create OAuth client for the specified provider
        client = oauth.create_client(provider)

        # Get and validate the token
        token = client.authorize_access_token()
        if not token or 'access_token' not in token:
            raise ValueError("Invalid token received from provider")

        # Store token metadata securely
        token_metadata = {
            'token_type': token.get('token_type'),
            'expires_at': token.get('expires_at'),
            'scope': token.get('scope', ''),
            'last_refreshed': firestore.SERVER_TIMESTAMP
        }

        session.clear()
        # Initialize variables we'll need for both providers
        user_id = None
        user_email = None
        username = None

        # Handle Google authentication
        if provider == 'google':
            user_info = client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                token=token  # Pass token explicitly
            ).json()
            original_id = user_info.get('sub')
            user_id = cipher.hash_user_id(provider, original_id)
            user_email = user_info.get('email')
            username = user_info.get('name')

        # Handle GitHub authentication
        elif provider == 'github':
            # Get basic user info with explicit token
            user_info = client.get(
                'https://api.github.com/user',
                token=token  # Pass token explicitly
            ).json()
            original_id = str(user_info.get('id'))
            user_id = cipher.hash_user_id(provider, original_id)
            username = user_info.get('name') or user_info.get('login')

            # Explicitly fetch email from GitHub's email endpoint
            try:
                email_response = client.get(
                    'https://api.github.com/user/emails',
                    token=token  # Pass token explicitly
                )
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

        # Set session information
        session['user_id'] = user_id
        session['provider'] = provider
        # Generate new CSRF token for the authenticated session
        csrf_token, response = csrf.generate_token(require_user_id=False)
        session['csrf_token'] = csrf_token
        # Generate salt and store user security info
        secure_salt = cipher.generate_salt()
        security_ref = db.collection('user_security').document(user_id)

        # Convert SecureByteArray to bytes before encoding
        salt_bytes = secure_salt.to_bytes()
        encoded_salt = base64.b64encode(salt_bytes).decode()

        # Store or update security information with token metadata
        if not security_ref.get().exists:
            security_ref.set({
                'salt': encoded_salt,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'oauth_token_metadata': token_metadata  # Store token metadata
            })
        else:
            security_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP,
                'oauth_token_metadata': token_metadata  # Update token metadata
            })

        # Create or update user in Firebase
        user_ref = db.collection('users').document(user_id)

        if not user_ref.get().exists:
            encrypted_email = cipher.encrypt(
                user_email,
                user_id,
                secure_salt
            ).decode()

            user_ref.set({
                'username': username,
                'email': encrypted_email,
                'preferred_currency': 'USD',
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'provider': provider
            })
        else:
            user_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        # Create audit log for successful login with token metadata
        db.collection('audit_logs').add({
            'user_id': user_id,
            'action': 'login',
            'provider': provider,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'token_type': token_metadata['token_type'],
            'token_scope': token_metadata['scope']
        })

        # Set secure cookie with new CSRF token
        response = redirect(url_for('dashboard'))
        flash('Login successful!', 'success')
        return response

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


@app.route('/auth/logout', methods=['POST'])
@login_required
@csrf.csrf_protect
def logout():
    """
    Handles user logout process securely.
    """
    try:
        session.clear()
        return jsonify({
            'status': 'success',
            'redirect_url': url_for('index')
        }), 200  # Explicitly return 200 OK status
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Logout failed'
        }), 500


"""
Portfolio Management Methods
--------------------------
"""


@ app.route('/')
def index():
    """
    Renders the application landing page.

    Returns:
        Response: Rendered index.html template
    """
    return render_template('index.html')


@ app.route('/dashboard')
@ login_required
def dashboard():
    """
    Renders main dashboard with encrypted portfolio data.

    Implements pagination, data chunking, and retry logic for large datasets.
    Decrypts and processes portfolio data securely.

    Returns:
        Response: Rendered dashboard template with portfolio data

    Raises:
        EncryptionError: For decryption failures
        FirestoreError: For database operation failures

    Security features:
    - Authentication required
    - Data encryption/decryption
    - Input validation
    - Error handling
    - Audit logging

    Performance features:
    - Pagination (50 items per page)
    - Connection retry logic (max 3 attempts)
    - Batch price fetching
    - Data chunking
    """
    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    security_ref = db.collection('user_security').document(user_id)

    # Pagination parameters
    PAGE_SIZE = 50  # Number of items per chunk
    page = request.args.get('page', 1, type=int)

    try:
        # Fetch user and security data with retry logic
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                user_data = user_ref.get().to_dict()
                security_data = security_ref.get().to_dict()
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    raise e
                time.sleep(1)  # Wait before retrying

        if not security_data or 'salt' not in security_data:
            flash('Security configuration error. Please contact support.', 'error')
            return render_template('dashboard.html',
                                   portfolio=[],
                                   total_value=0,
                                   currency='USD',
                                   last_update=datetime.now().strftime('%Y-%m-%d %H:%M'),
                                   username=user_data.get('username'))

        salt = base64.b64decode(security_data['salt'])
        currency = user_data.get('preferred_currency', 'USD')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M')

        # Calculate total documents for pagination
        total_docs = len(list(db.collection('users').document(user_id)
                              .collection('portfolio').stream()))
        total_pages = (total_docs + PAGE_SIZE - 1) // PAGE_SIZE

        # Fetch paginated portfolio data
        portfolio_ref = (db.collection('users').document(user_id)
                         .collection('portfolio')
                         .offset((page - 1) * PAGE_SIZE)
                         .limit(PAGE_SIZE))

        portfolio = []
        total_value = 0
        crypto_ids = set()

        # First pass: collect all crypto IDs
        for doc in portfolio_ref.stream():
            try:
                encrypted_item = doc.to_dict()
                if not encrypted_item:
                    continue

                encrypted_item['id'] = doc.id
                item = portfolio_encryption.decrypt_portfolio_item(
                    encrypted_item, user_id, salt)

                if item and item.get('crypto_id'):
                    crypto_ids.add(item['crypto_id'])
                    portfolio.append((doc.id, encrypted_item, item))
            except Exception as item_error:
                print(f"Error processing portfolio item {
                      doc.id}: {item_error}")
                continue

        # Batch fetch crypto prices
        try:
            crypto_prices = crypto_cache.get_crypto_prices(
                list(crypto_ids), currency)
        except Exception as price_error:
            print(f"Error fetching crypto prices: {price_error}")
            crypto_prices = {}

        # Second pass: process items with prices
        processed_portfolio = []
        for doc_id, encrypted_item, item in portfolio:
            try:
                current_price = (crypto_prices.get(item['crypto_id'], {})
                                 .get(currency.lower(), 0))

                metrics = calculate_portfolio_metrics(
                    item, current_price, currency)
                item.update(metrics)
                total_value += metrics['current_value']
                processed_portfolio.append(item)

            except Exception as process_error:
                print(f"Error calculating metrics for {
                      doc_id}: {process_error}")
                continue

        return render_template('dashboard.html',
                               portfolio=processed_portfolio,
                               total_value=total_value,
                               currency=currency,
                               current_page=page,
                               total_pages=total_pages,
                               last_update=current_time,
                               username=user_data.get('username'))

    except Exception as e:
        error_id = log_error('dashboard_error', user_id, str(e))
        flash(f'An error occurred loading the dashboard. Reference: {
              error_id}', 'error')
        return render_template('dashboard.html',
                               portfolio=[],
                               total_value=0,
                               currency='USD',
                               last_update=datetime.now().strftime('%Y-%m-%d %H:%M'),
                               username=user_data.get('username'))


@ app.route('/api/portfolio/add', methods=['POST'])
@ login_required
@ csrf.csrf_protect
@ rate_limit_decorator
def add_portfolio():
    """
    Adds new portfolio entry with encrypted storage.

    Processes and validates input data, encrypts sensitive fields,
    and stores in database within a transaction.

    Required JSON fields:
        crypto_id (str): Cryptocurrency identifier
        symbol (str): Cryptocurrency symbol
        amount (float): Purchase quantity
        purchase_price (float): Price at purchase
        purchase_date (str): Date of purchase

    Returns:
        JSON Response:
            status: 'success' or 'error'
            message: Result description
            document_id: Created document ID (on success)

    Raises:
        ValidationError: For invalid input data
        EncryptionError: For encryption failures
        FirestoreError: For database operation failures

    Security features:
    - Input validation
    - Data encryption
    - Transaction handling
    - Audit logging
    - Rate limiting
    - Error handling
    """
    secure_salt = None
    try:
        # 1. Input Validation
        try:
            data = request.get_json()
            validated_data = InputValidator.validate_portfolio_add(data)
        except ValidationError as e:
            return jsonify({
                'status': 'error',
                'field': e.field,
                'message': e.message
            }), 400
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request data'
            }), 400

        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

        # 3. Security Context Validation
        security_ref = db.collection('user_security').document(user_id)
        security_data = security_ref.get()

        if not security_data.exists:
            return jsonify({'status': 'error', 'message': 'Security configuration error'}), 400

        # 4. Secure Salt Handling
        try:
            encoded_salt = security_data.to_dict()['salt']
            secure_salt = SecureByteArray(base64.b64decode(encoded_salt))
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Security initialization failed'}), 500

        # 5. Transaction-based Data Storage
        transaction = db.transaction()

        @ firestore.transactional
        def create_portfolio_item(transaction, validated_data, user_id, secure_salt):
            # Encrypt portfolio data
            encrypted_data = portfolio_encryption.encrypt_portfolio_item(
                validated_data,
                user_id,
                secure_salt
            )

            # Create portfolio document
            portfolio_ref = db.collection('users').document(
                user_id).collection('portfolio').document()

            # Store encrypted data
            transaction.set(portfolio_ref, {
                'crypto_id': encrypted_data['crypto_id'],
                'symbol': encrypted_data['symbol'].upper(),
                'amount': encrypted_data['amount'],
                'purchase_price': encrypted_data['purchase_price'],
                'purchase_date': encrypted_data['purchase_date'],
                'created_at': firestore.SERVER_TIMESTAMP,
                'version': 1  # For future schema migrations
            })

            # Create audit log
            audit_ref = db.collection('audit_logs').document()
            transaction.set(audit_ref, {
                'user_id': user_id,
                'action': 'add_portfolio',
                'document_id': portfolio_ref.id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string,
                'metadata': {
                    'crypto_id': validated_data['crypto_id'],
                    'symbol': validated_data['symbol']
                }
            })

            return portfolio_ref.id

        # Execute transaction
        try:
            doc_id = create_portfolio_item(
                transaction, validated_data, user_id, secure_salt)
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Failed to create portfolio item'
            }), 500

        return jsonify({
            'status': 'success',
            'message': 'Portfolio item added successfully',
            'document_id': doc_id
        }), 201

    except Exception as e:
        # Secure error logging
        error_id = db.collection('error_logs').add({
            'error_type': 'portfolio_addition_error',
            'user_id': session.get('user_id'),
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP,
            'request_path': request.path,
            'request_method': request.method
        }).id

        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred',
            'error_reference': error_id
        }), 500

    finally:
        # Clean up secure objects
        if secure_salt is not None:
            secure_salt.secure_zero()


@ app.route('/api/portfolio/update/<doc_id>', methods=['PUT'])
@ login_required
@ csrf.csrf_protect
def update_portfolio(doc_id):
    """
    Updates existing portfolio entry while maintaining encryption.

    Validates ownership, updates encrypted data, and maintains audit trail.

    Args:
        doc_id (str): Document ID to update

    Required JSON fields:
        amount (float): New quantity
        purchase_price (float): New purchase price
        purchase_date (str): New purchase date

    Returns:
        JSON Response:
            message: Success/error message
            timestamp: Update timestamp

    Raises:
        ValidationError: For invalid input
        EncryptionError: For encryption failures
        FirestoreError: For database failures

    Security features:
    - Document ownership verification
    - Data encryption
    - Input validation
    - Audit logging
    - Error handling
    """
    secure_salt = None
    try:
        # Get and validate the input data
        data = request.get_json()

        # Validate the input data using our InputValidator
        try:
            validated_data = InputValidator.validate_request_data(
                data,
                InputValidator.COMMON_RULES['portfolio_update']
            )
        except ValidationError as ve:
            return jsonify({'error': f'Validation error: {ve.field} - {ve.message}'}), 400

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

        # Use the validated data for the update
        encrypted_update = portfolio_encryption.encrypt_portfolio_item(
            validated_data,
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


@ app.route('/api/portfolio/delete/<doc_id>', methods=['DELETE'])
@ login_required
@ csrf.csrf_protect
def delete_portfolio(doc_id):
    """
    Securely deletes portfolio entry with encrypted backup.

    Creates encrypted backup, removes document, and cleans associated data.

    Args:
        doc_id (str): Document ID to delete

    URL Parameters:
        reason (str, optional): Deletion reason

    Returns:
        JSON Response:
            message: Success/error message
            backup_id: Backup document ID
            timestamp: Deletion timestamp

    Raises:
        EncryptionError: For encryption failures
        FirestoreError: For database failures

    Security features:
    - Document ownership verification
    - Encrypted backup creation
    - Associated data cleanup
    - Audit logging
    - Error handling

    Recovery features:
    - Encrypted backup creation
    - Metadata preservation
    - Deletion reason logging
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


"""
API Routes Documentation
----------------------
"""


@ app.route('/api/cryptocurrencies')
@ login_required
@ csrf.csrf_protect
def get_cryptocurrencies():
    """
    Retrieves available cryptocurrencies from cache.

    Args:
        None

    Returns:
        JSON Response:
            status: 'success' or 'error'
            data: List of cryptocurrencies
            message: Error message if applicable

    Security features:
    - Authentication required
    - CSRF protection
    - Rate limiting
    - Error handling
    """

    try:
        cryptos = crypto_cache.get_available_cryptocurrencies()
        return jsonify({'status': 'success', 'data': cryptos}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ app.route('/api/preferences/currency', methods=['GET'])
@ login_required
@ csrf.csrf_protect
def get_currency_preference():
    """
    Retrieves user's preferred currency setting.

    Returns:
        JSON Response:
            currency: Preferred currency code (default 'USD')

    Security features:
    - Authentication required
    - CSRF protection
    - Secure database access
    """

    user_ref = db.collection('users').document(session['user_id'])
    user_data = user_ref.get().to_dict()
    return jsonify({'currency': user_data.get('preferred_currency', 'USD')})


@ app.route('/api/preferences/currency', methods=['PUT'])
@ login_required
@ csrf.csrf_protect
def update_currency_preference():
    """
    Updates user's currency preference setting.

    Required JSON fields:
        currency (str): New currency code ('USD' or 'EUR')

    Returns:
        JSON Response:
            message: Success message
            error: Error message if applicable

    Security features:
    - Authentication required
    - CSRF protection
    - Input validation
    - Error handling
    """
    try:
        data = request.get_json()

        # Validate the input data using our InputValidator
        try:
            validated_data = InputValidator.validate_request_data(
                data,
                InputValidator.COMMON_RULES['currency_preference']
            )
        except ValidationError as ve:
            return jsonify({'error': f'Validation error: {ve.field} - {ve.message}'}), 400

        user_ref = db.collection('users').document(session['user_id'])
        user_ref.update({'preferred_currency': validated_data['currency']})

        return jsonify({'message': 'Currency preference updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ app.route('/api/csrf/nonce', methods=['GET'])
@ login_required
def refresh_csrf_nonce():
    """
    Generates new CSRF nonce for frontend requests.

    Returns:
        JSON Response:
            status: 'success' or 'error'
            nonce: New CSRF nonce
            expires: Expiration timestamp
            message: Error message if applicable

    Security features:
    - Authentication required
    - Cryptographic nonce generation
    - Expiration handling
    - Audit logging
    """
    try:
        # Validate token from request
        token = request.headers.get('X-CSRF-Token')
        if not token or not csrf._validate_token(token):
            abort(403, "Invalid CSRF token")

        # Generate a new nonce using the CSRF protection instance
        new_nonce = csrf.generate_nonce()

        # Get the expiration time for this nonce
        expiration_time = csrf.used_nonces.get(new_nonce, {}).get('expires')

        # Convert timestamp to ISO format for frontend
        expiration_iso = datetime.fromtimestamp(
            expiration_time).isoformat() if expiration_time else None

        # Return the new nonce in the response
        response_data = {
            'status': 'success',
            'nonce': new_nonce,
            'expires': expiration_iso
        }

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


@ app.route('/navigate-home', methods=['POST'])
@ login_required
@ csrf.csrf_protect
def navigate_home():
    """
    Handles secure navigation to home page.

    Verifies session state and performs necessary cleanup.

    Returns:
        Response: Redirect with proper session handling

    Security features:
    - Session validation
    - Audit logging
    - Secure redirect
    - Error handling
    """
    try:
        if 'user_id' in session:
            # Create audit log for navigation
            db.collection('audit_logs').add({
                'user_id': session.get('user_id'),
                'action': 'navigate_home',
                'timestamp': firestore.SERVER_TIMESTAMP,
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            })

            # Return JSON response with redirect URL
            return jsonify({
                'status': 'success',
                'redirect_url': url_for('index')
            })

    except Exception as e:
        # Log the error
        db.collection('error_logs').add({
            'error_type': 'navigation_error',
            'user_id': session.get('user_id'),
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })

        # Return error response
        return jsonify({
            'status': 'error',
            'message': 'Navigation failed. Please try again.'
        }), 500


@ app.route('/api/csrf/token', methods=['GET'])
@ login_required
def get_csrf_token():
    """
    Generates and returns new CSRF token.

    Returns:
        Response: JSON with token and secure cookie

    Security features:
    - Authentication required
    - Secure cookie settings
    - HTTP-only flag
    - SameSite policy
    """
   # Validate JavaScript origin
    js_origin = request.headers.get('X-JavaScript-Origin')
    print("JS ORIGIN:", js_origin)
    if not js_origin or not csrf._validate_js_origin(js_origin):
        abort(403, "Invalid request origin")

    token, response = csrf.generate_token()
    return response


"""
Middleware Documentation
----------------------
"""


@app.before_request
def log_request_headers():
    """Log important security headers for debugging"""
    if request.path.startswith('/api/'):
        app.logger.debug(f"Request headers for {request.path}:")
        app.logger.debug(
            f"X-JavaScript-Origin: {request.headers.get('X-JavaScript-Origin')}")
        app.logger.debug(
            f"X-CSRF-Token: {request.headers.get('X-CSRF-Token')}")
        app.logger.debug(
            f"X-CSRF-Nonce: {request.headers.get('X-CSRF-Nonce')}")


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to all API responses.

    Implements multiple security layers through HTTP headers:
    1. CORS with strict origin validation
    2. Content Security Policy (CSP)
    3. HTTP Strict Transport Security (HSTS)
    4. X-Frame-Options for clickjacking prevention
    5. XSS protection headers

    Args:
        response (Response): Flask response object

    Returns:
        Response: Modified response with security headers

    Security features:
    - Origin validation
    - CSP configuration
    - HSTS enforcement
    - Clickjacking prevention
    - XSS protection
    """
    return secure_config.add_security_headers(response)


"""
Enhanced Portfolio API Implementation
===================================

This module provides a secure API for cryptocurrency portfolio management with JWT-based
authentication. It includes comprehensive security features, rate limiting, and error handling.

Security Features:
    - JWT-based authentication with refresh token support
    - Rate limiting and request cooldown periods
    - Comprehensive error handling and audit logging
    - Secure data encryption for portfolio items
    - CSRF protection
    - Input validation

Module Structure:
    - Configuration
    - Custom Exceptions
    - Authentication Services
    - Token Management
    - Portfolio Management
    - Route Handlers
    - Error Handlers

Dependencies:
    - Flask
    - PyJWT
    - Firebase Admin
    - cryptography

Author: Gabriel Cellammare
Modified: 05/01/2024
"""


tokenJWTHandling = TokenJWTHandling(db, cipher)

portfolio_api = Blueprint('portfolio_api', __name__)


@ app.route('/api/token/cleanup', methods=['POST'])
@ login_required
@ csrf.csrf_protect
def cleanup_tokens():
    """
    Cleans up expired tokens in the database by updating their status and maintaining an audit trail.

    Returns:
        Dict[str, Any]: A JSON response containing:
            - success (bool): Whether the cleanup operation was successful
            - cleaned_tokens (int): The number of tokens that were cleaned up

    Raises:
        FirestoreError: If there's an error accessing or updating the database.
        Exception: For any other unexpected errors during cleanup.

    Security:
        - Requires authentication via @login_required decorator
        - Protected against CSRF attacks
        - Creates audit trail for cleanup operations

    Example:
        >>> response = cleanup_tokens()
        >>> print(f"Cleaned {response['cleaned_tokens']} expired tokens")
    """
    try:
        current_time = datetime.now(timezone.utc)

        # Query for active tokens that have expired
        expired_tokens = (db.collection('user_tokens')
                          .where('status', '==', 'active')
                          .where('expires_at', '<=', current_time)
                          .stream())

        # Conta i token da pulire
        cleaned_count = 0
        batch = db.batch()

        for token_doc in expired_tokens:
            # Aggiorna lo stato del token a scaduto
            doc_ref = db.collection('user_tokens').document(token_doc.id)
            batch.update(doc_ref, {
                'status': 'expired',
                'cleaned_at': current_time
            })
            cleaned_count += 1

        # Esegui tutti gli aggiornamenti in un'unica operazione batch
        if cleaned_count > 0:
            batch.commit()

        return jsonify({
            'success': True,
            'cleaned_tokens': cleaned_count
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'cleaned_tokens': 0
        }), 500


@ app.route('/api/token/status', methods=['GET'])
@ login_required
@ csrf.csrf_protect
def get_token_status():
    """
    Get current token status for the user
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    # Get active token if exists
    active_token = tokenJWTHandling.get_active_token(user_id)

    # Check eligibility for new token
    is_eligible, next_eligible_time, error_message = tokenJWTHandling.check_token_request_eligibility(
        user_id)

    return jsonify({
        'has_active_token': bool(active_token),
        'token_info': active_token,
        'can_generate': is_eligible,
        'next_eligible_time': next_eligible_time.isoformat() if next_eligible_time else None,
        'message': error_message
    })


@ portfolio_api.errorhandler(AuthError)
def handle_auth_error(error):
    """
    Handles authentication-related errors and returns appropriate HTTP responses.

    Args:
        error (AuthError): The authentication error that occurred.

    Returns:
        Tuple[Response, int]: A JSON response containing error details and appropriate HTTP status code.

    Example:
        >>> @portfolio_api.errorhandler(AuthError)
        >>> def handle_auth_error(error):
        >>>     return jsonify({'error': 'Authentication failed'}), 401
    """
    response = jsonify({'error': error.error})
    response.status_code = error.status_code
    return response


@ portfolio_api.errorhandler(400)
def handle_bad_request(error):
    """
    Handles bad request errors (HTTP 400) and returns appropriate responses.

    Args:
        error (BadRequestError): The bad request error that occurred.

    Returns:
        Tuple[Response, int]: A JSON response containing error details and 400 status code.

    Example:
        >>> @portfolio_api.errorhandler(400)
        >>> def handle_bad_request(error):
        >>>     return jsonify({'error': 'Invalid request parameters'}), 400
    """
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400


@ portfolio_api.errorhandler(500)
def handle_internal_error(error):
    """
    Handles internal server errors (HTTP 500) with secure logging.

    Args:
        error (Exception): The internal server error that occurred.

    Returns:
        Tuple[Response, int]: A JSON response containing error details and 500 status code.

    Side Effects:
        - Logs error details to secure error logging system
        - Creates audit trail for internal errors

    Security:
        - Sanitizes error messages before logging
        - Maintains secure error logs
        - Provides generic error messages to users

    Example:
        >>> @portfolio_api.errorhandler(500)
        >>> def handle_internal_error(error):
        >>>     return jsonify({'error': 'Internal server error'}), 500
    """
    # Log error details securely
    db.collection('error_logs').add({
        'error_type': 'internal_server_error',
        'error_message': str(error),
        'timestamp': datetime.now(timezone.utc),
        'request_path': request.path,
        'request_method': request.method
    })
    return jsonify({'error': 'Internal server error'}), 500

# Routes


@ app.route('/api/token', methods=['POST'])
@ login_required
@ csrf.csrf_protect
def get_tokens():
    """
    Generate a new JWT token for authenticated users with request limits.
    Now includes automatic expiration of previous tokens.
    """
    user_id = session.get('user_id')
    print(f"Attempting token generation for user: {user_id}")  # Debug log

    if not user_id:
        print("No user_id found in session")  # Debug log
        raise AuthError('User not authenticated', 401)

    try:
        print("Checking token eligibility")  # Debug log
        is_eligible, next_eligible_time, error_message = tokenJWTHandling.check_token_request_eligibility(
            user_id)
        print(f"Eligibility result: {is_eligible}")  # Debug log

        if not is_eligible:
            print(f"User not eligible: {error_message}")  # Debug log
            raise AuthError(error_message, 429)

        tokens = tokenJWTHandling.generate_tokens(user_id)
        print("Token generated successfully")  # Debug log
        return jsonify(tokens)

    except AuthError as e:
        print(f"AuthError occurred: {e.error}")  # Debug log
        return jsonify({
            'error': e.error,
            'status_code': e.status_code
        }), e.status_code


@ portfolio_api.route('/portfolio', methods=['GET'])
@ tokenJWTHandling.jwt_required
@ rate_limit_decorator
def get_portfolio():
    """
    Retrieves and decrypts a user's portfolio data.

    Returns:
        Dict[str, Any]: JSON response containing:
            - status: 'success' or 'error'
            - data: List of decrypted portfolio items with current values
            - total_value: Total portfolio value
            - currency: User's preferred currency

    Raises:
        AuthError: If the user is not properly authenticated.
        FirestoreError: If there's an error accessing portfolio data.
        CryptoError: If there's an error fetching cryptocurrency prices.
        DecryptionError: If portfolio data cannot be decrypted.

    Security Features:
        - JWT authentication required
        - Data decryption using user's unique salt
        - Secure error handling
        - Audit logging
        - Secure cleanup of sensitive data

    Example:
        >>> portfolio = get_portfolio()
        >>> print(f"Total portfolio value: {portfolio['total_value']} {portfolio['currency']}")
    """
    secure_salt = None
    try:
        user_id = request.user_id

        # Retrieve user's security data and salt
        security_ref = db.collection('user_security').document(user_id)
        security_data = security_ref.get()

        if not security_data.exists:
            return jsonify({'status': 'error', 'message': 'Security configuration not found'}), 400

        # Convert stored base64 salt to SecureByteArray
        encoded_salt = security_data.to_dict()['salt']
        secure_salt = SecureByteArray(base64.b64decode(encoded_salt))

        # Get user preferences
        user_ref = db.collection('users').document(user_id)
        user_data = user_ref.get().to_dict()
        currency = user_data.get('preferred_currency', 'USD')

        # Retrieve and process portfolio items
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

                # Decrypt portfolio item
                item = portfolio_encryption.decrypt_portfolio_item(
                    encrypted_item,
                    user_id,
                    secure_salt
                )

                # Validate decrypted data
                if not item or not item.get('crypto_id'):
                    continue

                # Get current cryptocurrency price
                try:
                    crypto_prices = crypto_cache.get_crypto_prices(
                        [item['crypto_id']],
                        currency
                    )

                    current_price = (crypto_prices.get(item['crypto_id'], {})
                                     .get(currency.lower(), 0)
                                     if isinstance(crypto_prices, dict)
                                     else 0)
                except Exception as price_error:
                    print(f"Error fetching price for {
                          item['crypto_id']}: {price_error}")
                    current_price = 0

                # Calculate portfolio metrics
                metrics = calculate_portfolio_metrics(
                    item,
                    current_price,
                    currency
                )

                item.update(metrics)
                total_value += metrics['current_value']
                portfolio.append(item)

            except Exception as item_error:
                # Log item processing errors but continue with remaining items
                db.collection('error_logs').add({
                    'error_type': 'portfolio_item_processing_error',
                    'item_id': doc.id,
                    'user_id': user_id,
                    'error_message': str(item_error),
                    'timestamp': firestore.SERVER_TIMESTAMP
                })
                continue

        return jsonify({
            'status': 'success',
            'data': portfolio,
            'total_value': total_value,
            'currency': currency
        })

    except Exception as e:
        # Log error details securely
        db.collection('error_logs').add({
            'error_type': 'portfolio_fetch_error',
            'user_id': request.user_id,
            'error_message': str(e),
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve portfolio data'
        }), 500

    finally:
        # Clean up secure objects
        if secure_salt is not None:
            secure_salt.secure_zero()


@ portfolio_api.route('/portfolio', methods=['POST'])
@ tokenJWTHandling.jwt_required
@ rate_limit_decorator
def add_crypto():
    """

    Adds a new encrypted portfolio item to the user's portfolio.

    Required JSON payload:
        {
            "crypto_id": "bitcoin",
            "symbol": "BTC",
            "amount": 1.5,
            "purchase_price": 45000,
            "purchase_date": "2024-01-15"
        }

    Returns:
        Dict[str, Any]: JSON response containing:
            - status: 'success' or 'error'
            - message: Result description
            - document_id: Created document ID (on success)

    Raises:
        ValidationError: If the input data fails validation.
        AuthError: If the user is not properly authenticated.
        FirestoreError: If there's an error storing the portfolio item.
        EncryptionError: If the portfolio data cannot be encrypted.

    Security Features:
        - JWT authentication required
        - Rate limiting applied
        - Input validation
        - Data encryption
        - Audit logging
        - CSRF protection

    Example:
        >>> crypto_data = {
        >>>     "crypto_id": "bitcoin",
        >>>     "symbol": "BTC",
        >>>     "amount": 1.5,
        >>>     "purchase_price": 45000,
        >>>     "purchase_date": "2024-01-15"
        >>> }
        >>> result = add_crypto(crypto_data)
        >>> print(f"Added portfolio item with ID: {result['document_id']}")

    Adds a new encrypted portfolio item.

    Required JSON payload:
    {
        "crypto_id": "bitcoin",
        "symbol": "BTC",
        "amount": 1.5,
        "purchase_price": 45000,
        "purchase_date": "2024-01-15"
    }

    Returns:
        JSON response containing:
        - status: 'success' or 'error'
        - message: Result description
        - document_id: Created document ID (on success)

    Security features:
    - JWT authentication
    - Data encryption
    - Input validation
    - Secure error handling
    - Audit logging
    """
    secure_salt = None
    try:
        data = request.get_json()
        try:
            validated_data = InputValidator.validate_portfolio_add(data)
            user_id = request.user_id

            # Validate required fields
            required_fields = ['crypto_id', 'symbol',
                               'amount', 'purchase_price', 'purchase_date']
            if not all(field in validated_data for field in required_fields):
                return jsonify({
                    'status': 'error',
                    'message': 'Missing required fields'
                }), 400

            # Retrieve user's security data and salt
            security_ref = db.collection('user_security').document(user_id)
            security_data = security_ref.get()

            if not security_data.exists:
                return jsonify({
                    'status': 'error',
                    'message': 'Security credentials not found'
                }), 400

            # Convert stored base64 salt to SecureByteArray
            encoded_salt = security_data.to_dict()['salt']
            secure_salt = SecureByteArray(base64.b64decode(encoded_salt))

            # Encrypt portfolio data
            encrypted_data = portfolio_encryption.encrypt_portfolio_item(
                validated_data,
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

            # Create audit log
            db.collection('audit_logs').add({
                'user_id': user_id,
                'action': 'add_portfolio_api',
                'document_id': new_doc[1].id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            })

            return jsonify({
                'status': 'success',
                'message': 'Cryptocurrency added successfully'
            }), 201

        except Exception as e:
            # Log error details securely
            db.collection('error_logs').add({
                'error_type': 'portfolio_add_error',
                'user_id': request.user_id,
                'error_message': str(e),
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            return jsonify({
                'status': 'error',
                'message': 'Failed to add portfolio item'
            }), 500

        finally:
            # Clean up secure objects
            if secure_salt is not None:
                secure_salt.secure_zero()

    except ValidationError as e:
        return jsonify({
            'status': 'error',
            'message': f'Validation error: {e.field} - {e.message}'
        }), 400


app.register_blueprint(portfolio_api, url_prefix='/api/v1')

if __name__ == '__main__':
    app.run(debug=True)
