# security.py contiene la classe CSRFProtection che implementa la protezione CSRF per le applicazioni Flask.
from flask import Flask, render_template, jsonify
from functools import wraps
from flask import session, request, abort, jsonify
import secrets
import time
from datetime import datetime, timedelta


class CSRFProtection:
    def __init__(self, app=None):
        if app:
            self.init_app(app)

        # Dizionario per tenere traccia dei nonce utilizzati
        # Struttura: {nonce: expiration_timestamp}
        self.used_nonces = {}

        # Durata di validità del nonce (5 minuti)
        self.NONCE_EXPIRATION = 300

    def init_app(self, app):
        # Configura le impostazioni di sicurezza di Flask
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
        )

        # Registra i gestori per la pulizia dei nonce scaduti
        @app.before_request
        def cleanup_expired_nonces():
            current_time = time.time()
            self.used_nonces = {
                nonce: exp_time
                for nonce, exp_time in self.used_nonces.items()
                if exp_time > current_time
            }

        # Middleware per aggiungere gli header di sicurezza
        @app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            return response

    def generate_token(self):
        """Genera un nuovo token CSRF"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return session['csrf_token']

    def generate_nonce(self):
        """Genera un nuovo nonce per una singola richiesta"""
        nonce = secrets.token_urlsafe(16)
        self.used_nonces[nonce] = time.time() + self.NONCE_EXPIRATION
        return nonce

    def validate_token(self, token):
        """Valida il token CSRF"""
        return token and session.get('csrf_token') and token == session['csrf_token']

    def validate_nonce(self, nonce):
        """Valida il nonce e lo marca come utilizzato"""
        if not nonce or nonce not in self.used_nonces:
            return False

        # Verifica che il nonce non sia scaduto
        if time.time() > self.used_nonces[nonce]:
            del self.used_nonces[nonce]
            return False

        # Rimuovi il nonce dopo l'uso (one-time use)
        del self.used_nonces[nonce]
        return True

    def csrf_protect(self, f):
        """Decoratore per proteggere le route con CSRF"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                token = request.headers.get('X-CSRF-Token')
                nonce = request.headers.get('X-CSRF-Nonce')

                if not self.validate_token(token):
                    abort(403, description="Invalid CSRF token")

                if not self.validate_nonce(nonce):
                    abort(403, description="Invalid or expired nonce")

            return f(*args, **kwargs)
        return decorated_function
