"""
Cryptocurrency Portfolio Management Application

This Flask application provides a secure platform for managing cryptocurrency portfolios.
It includes OAuth authentication, encrypted data storage, CSRF protection, and real-time
cryptocurrency price tracking.

Main features:
- User authentication via Google and GitHub OAuth
- Encrypted portfolio data storage using AES
- Real-time cryptocurrency price tracking
- CSRF protection for all forms and API endpoints
- Audit logging for security events
- Error handling and logging
"""

from typing import Dict, Any, Optional, Tuple
import time
from flask import Blueprint, jsonify, request, session
import base64
from flask import Blueprint, make_response, render_template, request, jsonify, session, redirect, url_for, flash
from firebase_admin import firestore
from functools import wraps
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import jwt
from config import Config
from cryptography_utils import AESCipher
from cryptocache import CryptoCache
import os

from init_app import configure_oauth, create_app
from input_validator import InputValidator, ValidationError
from portfolio_encryption import PortfolioEncryption
from portfolio_utils import calculate_portfolio_metrics
from secure_bye_array import SecureByteArray
from security import CSRFProtection


# Application initialization


# First, load environment variables before any initialization
load_dotenv()


# Create the Flask application
app = create_app()
csrf = CSRFProtection(app)

# Initialize other components after app creation
db = firestore.client()
crypto_cache = CryptoCache()
cipher = AESCipher(os.environ.get('MASTER_ENCRYPTION_KEY'))
portfolio_encryption = PortfolioEncryption(cipher)

# Initialize OAuth after app creation
oauth = configure_oauth(app)

# Middleware
# Register the CORS headers handler - this will be called automatically after each request


@app.after_request
def add_cors_headers(response):
    """
    Adds CORS headers to all API responses.
    Called automatically by Flask after each request.

    Args:
        response (Response): Flask response object to modify

    Returns:
        Response: Modified response with CORS headers added

    Security features:
    - Configures allowed origins, methods and headers
    - Implements security headers like Content-Security-Policy
    """
    return Config.add_cors_headers(response)

# Decorator for requiring login


def login_required(f):
    """
    Decorator to protect routes that require user authentication.
    Redirects to login page if user is not authenticated.

    Args:
        f (function): Route handler function to protect

    Returns:
        function: Decorated function that checks for authentication
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Login route


@app.route('/auth/login/<provider>')
def login(provider):
    """
    Handles login requests for different OAuth providers.
    Generates and stores CSRF token before OAuth redirect.

    Args:
        provider (str): OAuth provider name ('google' or 'github')

    Returns:
        Response: Redirect to OAuth provider's authorization page

    Raises:
        ValueError: If invalid provider specified
    """
    if provider not in ['google', 'github']:
        flash('Invalid authentication provider', 'error')
        return redirect(url_for('index'))

    # Store the CSRF token in session before OAuth redirect
    csrf_token = csrf.generate_token()

    return oauth.create_client(provider).authorize_redirect(
        url_for('auth_callback', provider=provider, _external=True), state=csrf_token
    )


# Authentication routes


@app.route('/auth/callback/<provider>')
def auth_callback(provider):
    """
    Handles OAuth callback for authentication providers.
    Processes user data, creates/updates user records, and manages session.

    Args:
        provider (str): OAuth provider name ('google' or 'github')

    Returns:
        Response: Redirect to dashboard on success or error page on failure

    Security:
    - Validates CSRF state
    - Validates and stores OAuth tokens
    - Encrypts sensitive user data
    - Creates audit logs
    - Implements secure error handling
    """

    try:
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

        # Initialize variables we'll need for both providers
        user_id = None
        user_email = None
        username = None

        state = request.args.get('state')
        stored_state = session.get('csrf_token')

        print(f"Received state: {state}")
        print(f"Stored state: {stored_state}")
        print(f"Session contents: {dict(session)}")

        if state != stored_state:
            raise ValueError("Invalid CSRF state")

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

        # Set session information
        session['user_id'] = user_id
        session['provider'] = provider

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
@login_required
@csrf.csrf_protect
def logout():
    """
    Handles user logout requests.
    Clears all session data and redirects to landing page.

    Returns:
        Response: Redirect to index page with success message

    Security features:
    - CSRF protection for logout request
    - Complete session data cleanup
    - Audit logging of logout events
    - Secure redirect handling
    """
    session.clear()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))

# Main routes


@app.route('/')
def index():
    """
    Renders the application landing page.

    Returns:
        Response: Rendered index.html template
    """
    return render_template('index.html')


@app.route('/dashboard')
@login_required
@csrf.csrf_protect
def dashboard():
    """
    Renders the main dashboard view for authenticated users.
    Retrieves and decrypts user's portfolio data, calculates current values and metrics.

    Returns:
        Response: Rendered dashboard.html template with:
        - Portfolio data with current values and performance metrics
        - Total portfolio value
        - User's preferred currency
        - CSRF tokens for security
        - Last update timestamp
        - Username for display

    Security features:
    - Requires authentication
    - CSRF protection
    - Decrypts portfolio data securely
    - Handles security configuration errors
    - Creates audit logs
    - Secure error handling with fallback display
    - Protects sensitive user data

    Performance features:
    - Uses cached cryptocurrency prices
    - Efficient batch processing of portfolio items
    - Handles invalid or corrupted data gracefully
    """

    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    security_ref = db.collection('user_security').document(user_id)

    try:
        user_data = user_ref.get().to_dict()
        security_data = security_ref.get().to_dict()

        if not security_data or 'salt' not in security_data:
            flash('Security configuration error. Please contact support.', 'error')
            # Genera token e nonce per il template

            return render_template('dashboard.html',
                                   portfolio=[],
                                   environment="development",
                                   total_value=0,
                                   currency='USD',
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

        return render_template('dashboard.html',
                               portfolio=portfolio,
                               total_value=total_value,
                               environment="development",
                               currency=currency,
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
    """
    Retrieves list of available cryptocurrencies from cache.
    Requires authentication to access.

    Returns:
        JSON response containing:
        - status: 'success' or 'error'
        - data: List of available cryptocurrencies
        - message: Error message (if applicable)

    Security features:
    - Requires authentication
    - CSRF protection
    - Secure error handling
    """

    try:
        cryptos = crypto_cache.get_available_cryptocurrencies()
        return jsonify({'status': 'success', 'data': cryptos}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/portfolio/add', methods=['POST'])
@login_required
@csrf.csrf_protect
def add_portfolio():
    """
    Adds a new portfolio item with encrypted data storage.

    Required JSON payload fields:
        - crypto_id (str): Cryptocurrency identifier
        - symbol (str): Cryptocurrency symbol
        - amount (float): Quantity purchased
        - purchase_price (float): Price at purchase
        - purchase_date (str): Date of purchase

    Returns:
        JSON response with:
        - status: 'success' or 'error'
        - message: Description of result
        - document_id: ID of created document (on success)

    Security features:
    - Requires authentication
    - CSRF protection
    - Encrypts sensitive data
    - Creates audit logs
    - Secure error handling
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

        # 2. Rate Limiting Check
        if not check_rate_limit(user_id):
            return jsonify({'status': 'error', 'message': 'Rate limit exceeded'}), 429

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

        @firestore.transactional
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


@app.route('/api/portfolio/update/<doc_id>', methods=['PUT'])
@login_required
@csrf.csrf_protect
def update_portfolio(doc_id):
    """
    Updates an existing portfolio item while maintaining encryption.

    Args:
        doc_id (str): Document ID of portfolio item to update

    Required JSON payload fields:
        - amount (float): New quantity
        - purchase_price (float): New purchase price
        - purchase_date (str): New purchase date

    Returns:
        JSON response with:
        - message: Success/error message
        - timestamp: Update timestamp

    Security features:
    - Requires authentication
    - CSRF protection
    - Maintains encryption
    - Verifies document ownership
    - Creates audit logs
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


@app.route('/api/portfolio/delete/<doc_id>', methods=['DELETE'])
@login_required
@csrf.csrf_protect
def delete_portfolio(doc_id):
    """
    Securely delete a portfolio item while maintaining an encrypted backup.
    This implementation ensures that sensitive data remains protected during the deletion process
    and backup creation, while maintaining a complete audit trail.
    Verifies ownership, creates backup, and cleans up associated data.

    Args:
        doc_id (str): Document ID of portfolio item to delete

    URL Parameters:
        reason (str, optional): Reason for deletion

    Returns:
        JSON response containing:
        - message: Success/error message
        - backup_id: ID of created backup document
        - timestamp: Deletion timestamp
        - error_reference: Error log ID (if error occurs)

    Security features:
    - Requires authentication
    - CSRF protection
    - Verifies document ownership
    - Creates encrypted backup
    - Maintains audit trail
    - Cleans up associated files
    - Secure error handling
    - Protects sensitive data during deletion

    Recovery features:
    - Encrypted backup creation
    - Metadata preservation
    - Associated file tracking
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

# Currency Preference Routes

# Add these routes to app.py


@app.route('/api/preferences/currency', methods=['GET'])
@login_required
@csrf.csrf_protect
def get_currency_preference():
    """
    Gets user's preferred currency setting.
    Requires authentication to access.

    Returns:
        JSON response containing:
        - currency: User's preferred currency code (defaults to 'USD')

    Security features:
    - Requires authentication
    - CSRF protection
    - Secure database access
    """
    user_ref = db.collection('users').document(session['user_id'])
    user_data = user_ref.get().to_dict()
    return jsonify({'currency': user_data.get('preferred_currency', 'USD')})


@app.route('/api/preferences/currency', methods=['PUT'])
@login_required
@csrf.csrf_protect
def update_currency_preference():
    """
    Updates user's preferred currency setting.
    Requires authentication to access.

    Required JSON payload fields:
        - currency (str): New currency preference code ('USD' or 'EUR')

    Returns:
        JSON response containing:
        - message: Success message
        - error: Error message (if applicable)

    Security features:
    - Requires authentication
    - CSRF protection
    - Input validation
    - Secure database updates
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


@app.route('/api/csrf/nonce', methods=['GET'])
@login_required
@csrf.csrf_protect
def refresh_csrf_nonce():
    """
    Generates and returns a new CSRF nonce for frontend requests.

    Returns:
        JSON response containing:
        - status: 'success' or 'error'
        - nonce: New CSRF nonce value
        - expires: Nonce expiration timestamp
        - message: Error message (if applicable)

    Security features:
    - Requires authentication
    - Generates cryptographically secure nonce
    - Sets expiration time
    - Creates audit logs
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


@app.route('/navigate-home', methods=['POST'])
@login_required
@csrf.csrf_protect
def navigate_home():
    """
    Handles secure navigation to home page.

    This route:
    1. Verifies the user's session state
    2. Performs any necessary cleanup
    3. Redirects to the appropriate page based on authentication status

    Returns:
        Response: Redirect to appropriate page with proper session handling
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


@app.route('/api/csrf/token', methods=['GET'])
@login_required
@csrf.csrf_protect
def get_csrf_token():
    token = csrf.generate_token()
    response = make_response(jsonify({'token': token}))
    response.set_cookie('csrf_token', token, secure=True,
                        httponly=True, samesite='Lax')
    return response


"""
Enhanced Portfolio API Implementation
Provides secure JWT-based authentication and comprehensive API endpoints
for cryptocurrency portfolio management.

Features:
- JWT-based authentication with refresh token support
- Rate limiting
- Comprehensive error handling
- Detailed logging
- Input validation
"""


# Configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWT_TOKEN_EXPIRATION = timedelta(days=7)
JWT_REQUEST_COOLDOWN = timedelta(hours=12)
MAX_DAILY_TOKENS = 2
portfolio_api = Blueprint('portfolio_api', __name__)

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
rate_limit_store: Dict[str, Dict[str, Any]] = {}


class AuthError(Exception):
    """Custom exception for authentication errors"""

    def __init__(self, error: str, status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


def get_user_token_history(user_id: str, since: datetime) -> list:
    """
    Retrieve user's token generation history from Firestore
    """
    token_docs = (db.collection('user_tokens')
                  .where('user_id', '==', user_id)
                  .where('created_at', '>=', since)
                  # Only consider active tokens
                  .where('status', '==', 'active')
                  .order_by('created_at', direction='DESCENDING')
                  .stream())

    return [doc.to_dict() for doc in token_docs]


def check_token_request_eligibility(user_id: str) -> Tuple[bool, Optional[datetime], Optional[str]]:
    """
    Enhanced eligibility check using Firestore database
    """
    current_time = datetime.now(timezone.utc)
    day_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get active tokens from database
    token_history = get_user_token_history(user_id, day_start)

    if not token_history:
        return True, None, None

    # Check daily token limit
    if len(token_history) >= MAX_DAILY_TOKENS:
        next_day = day_start + timedelta(days=1)
        return False, next_day, f'Daily limit reached. Next eligible: {next_day.isoformat()}'

    # Check cooldown period
    latest_token = token_history[0]
    last_request_time = latest_token['created_at']
    next_eligible_time = last_request_time + JWT_REQUEST_COOLDOWN

    if current_time < next_eligible_time:
        return False, next_eligible_time, f'Please wait until {next_eligible_time.isoformat()}'

    return True, None, None


@app.route('/api/token/cleanup', methods=['POST'])
@login_required
@csrf.csrf_protect
def cleanup_tokens():
    """
    Endpoint to clean up expired tokens and return the number of tokens cleaned
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


def get_active_token(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve the most recent active token for a user
    """
    current_time = datetime.now(timezone.utc)

    # Query for active tokens
    tokens = (db.collection('user_tokens')
              .where('user_id', '==', user_id)
              .where('status', '==', 'active')
              .where('expires_at', '>', current_time)
              .order_by('expires_at', direction='DESCENDING')
              .limit(1)
              .stream())

    token_list = list(tokens)
    return token_list[0].to_dict() if token_list else None


def expire_previous_tokens(user_id: str) -> None:
    """
    Expires all active tokens for a given user in the database.
    This ensures only one token is active at a time per user.

    Args:
        user_id: The unique identifier of the user

    The function uses a batch operation to update all tokens efficiently
    and maintains an audit trail of token expiration.
    """
    current_time = datetime.now(timezone.utc)

    # Query for all active tokens belonging to the user
    active_tokens = (db.collection('user_tokens')
                     .where('user_id', '==', user_id)
                     .where('status', '==', 'active')
                     .stream())

    # Create a batch operation for efficiency
    batch = db.batch()

    expired_count = 0
    for token_doc in active_tokens:
        doc_ref = db.collection('user_tokens').document(token_doc.id)

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
        db.collection('audit_logs').add({
            'user_id': user_id,
            'action': 'expire_tokens',
            'tokens_expired': expired_count,
            'reason': 'new_token_generated',
            'timestamp': current_time,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        })


@app.route('/api/token/status', methods=['GET'])
@login_required
@csrf.csrf_protect
def get_token_status():
    """
    Get current token status for the user
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    # Get active token if exists
    active_token = get_active_token(user_id)

    # Check eligibility for new token
    is_eligible, next_eligible_time, error_message = check_token_request_eligibility(
        user_id)

    return jsonify({
        'has_active_token': bool(active_token),
        'token_info': active_token,
        'can_generate': is_eligible,
        'next_eligible_time': next_eligible_time.isoformat() if next_eligible_time else None,
        'message': error_message
    })


def generate_tokens(user_id: str) -> Dict[str, Any]:
    """
    Enhanced token generation with improved storage and tracking.
    Now includes automatic expiration of previous tokens.
    """

    # Check if user is eligible for a new token
    is_eligible, next_eligible_time, error_message = check_token_request_eligibility(
        user_id)

    if not is_eligible:
        raise AuthError(error_message, 429)

    # Expire all previous active tokens before generating a new one
    expire_previous_tokens(user_id)

    current_time = datetime.now(timezone.utc)
    token_exp = current_time + JWT_TOKEN_EXPIRATION

    # Generate new JWT with creation timestamp
    access_token = jwt.encode({
        'exp': token_exp,
        'iat': current_time,
        'created_at': current_time.isoformat(),
        'user_id': user_id,
        'type': 'access'
    }, JWT_SECRET_KEY, algorithm='HS256')

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
    db.collection('user_tokens').add(token_doc)

    # Calculate next token request time
    next_token_time = current_time + JWT_REQUEST_COOLDOWN

    return {
        'access_token': access_token,
        'token_created_at': current_time.isoformat(),
        'expires_in': int(JWT_TOKEN_EXPIRATION.total_seconds()),
        'expires_at': token_exp.isoformat(),
        'next_token_request': next_token_time.isoformat()
    }


def get_token_creation_time(token: str) -> Optional[datetime]:
    """
    Retrieve token creation time from JWT claims
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        created_at = payload.get('created_at')
        return datetime.fromisoformat(created_at) if created_at else None
    except (jwt.InvalidTokenError, ValueError):
        return None


def check_rate_limit(user_id: str) -> bool:
    """
    Check if user has exceeded rate limit

    Args:
        user_id: The user's unique identifier

    Returns:
        Boolean indicating if rate limit is exceeded
    """
    current_time = time.time()

    if user_id not in rate_limit_store:
        rate_limit_store[user_id] = {
            'requests': 1,
            'window_start': current_time
        }
        return True

    user_limits = rate_limit_store[user_id]

    # Reset if window has expired
    if current_time - user_limits['window_start'] > RATE_LIMIT_WINDOW:
        rate_limit_store[user_id] = {
            'requests': 1,
            'window_start': current_time
        }
        return True

    # Check if limit exceeded
    if user_limits['requests'] >= RATE_LIMIT_REQUESTS:
        return False

    # Increment request count
    user_limits['requests'] += 1
    return True


def jwt_required(f):
    """Enhanced decorator to verify JWT tokens with Firebase check"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            raise AuthError('Missing or invalid token format', 401)

        token = auth_header.split(' ')[1]

        try:
            # Verify JWT signature and expiration
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])

            # Verify token type
            if payload.get('type') != 'access':
                raise AuthError('Invalid token type', 401)

            user_id = payload['user_id']

            # Check token in Firebase
            token_docs = (db.collection('user_tokens')
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

            # Check rate limit
            if not check_rate_limit(user_id):
                raise AuthError('Rate limit exceeded', 429)

            # Add user_id to request
            request.user_id = user_id

            return f(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            raise AuthError('Token expired', 401)
        except jwt.InvalidTokenError:
            raise AuthError('Invalid token', 401)
        except Exception as e:
            # Log error securely
            db.collection('error_logs').add({
                'error_type': 'token_verification_error',
                'error_message': str(e),
                'timestamp': datetime.now(timezone.utc),
                'request_path': request.path,
                'request_method': request.method
            })
            raise AuthError('Token verification failed', 401)

    return decorated

# Error Handlers


@portfolio_api.errorhandler(AuthError)
def handle_auth_error(error):
    """Handle authentication errors"""
    response = jsonify({'error': error.error})
    response.status_code = error.status_code
    return response


@portfolio_api.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request errors"""
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400


@portfolio_api.errorhandler(429)
def handle_rate_limit(error):
    """Handle rate limit errors"""
    return jsonify({'error': 'Rate limit exceeded'}), 429


@portfolio_api.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors"""
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


@app.route('/api/token', methods=['POST'])
@login_required
@csrf.csrf_protect
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
        is_eligible, next_eligible_time, error_message = check_token_request_eligibility(
            user_id)
        print(f"Eligibility result: {is_eligible}")  # Debug log

        if not is_eligible:
            print(f"User not eligible: {error_message}")  # Debug log
            raise AuthError(error_message, 429)

        tokens = generate_tokens(user_id)
        print("Token generated successfully")  # Debug log
        return jsonify(tokens)

    except AuthError as e:
        print(f"AuthError occurred: {e.error}")  # Debug log
        return jsonify({
            'error': e.error,
            'status_code': e.status_code
        }), e.status_code


@portfolio_api.route('/portfolio', methods=['GET'])
@jwt_required
def get_portfolio():
    """
    Retrieves and decrypts user's portfolio data.

    Returns:
        JSON response containing:
        - status: 'success' or 'error'
        - data: List of decrypted portfolio items with current values
        - total_value: Total portfolio value
        - currency: User's preferred currency

    Security features:
    - JWT authentication
    - Data decryption using user's salt
    - Secure error handling
    - Audit logging
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


@portfolio_api.route('/portfolio', methods=['POST'])
@jwt_required
def add_crypto():
    """
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
            if not all(field in data for field in required_fields):
                return jsonify({
                    'status': 'error',
                    'message': 'Missing required fields'
                }), 400

            # Validate numeric fields
            try:
                amount = float(data['amount'])
                purchase_price = float(data['purchase_price'])
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid numeric values'
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
                'message': 'Cryptocurrency added successfully',
                'document_id': new_doc[1].id
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


app.register_blueprint(portfolio_api, url_prefix='/api/v1')  # Add this line

if __name__ == '__main__':
    app.run(debug=True)
