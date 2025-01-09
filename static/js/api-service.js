/**
 * @fileoverview Enhanced API Service Module
 * 
 * This module provides a secure service for handling API communications with comprehensive 
 * security features including CSRF protection, rate limiting, and request retry logic.
 * The implementation follows security best practices and includes robust error handling,
 * token management, and request sanitization.
 * 
 * Key Security Features:
 * - CSRF Protection with token and nonce
 * - Rate Limiting
 * - Request Retry with Exponential Backoff
 * - Secure Token Management
 * - HTTPS Enforcement in Production
 * - Request Timeout Handling
 * - XSS Prevention Headers
 * 
 * @version 1.0.0
 * @license MIT
 */
// Configuration constants for better maintainability and security

import { endpointManager } from './secure-endpoints.js';
const CONFIG = Object.freeze({
    ENDPOINTS: {
        CSRF_TOKEN: '/api/csrf/token',
        CSRF_NONCE: '/api/csrf/nonce'
    },
    TIMING: {
        REQUEST_TIMEOUT: 30000,
        TOKEN_REFRESH_THRESHOLD: 24 * 60 * 60 * 1000, // 24 hours before expiry
        TOKEN_CHECK_INTERVAL: 60000, // Check every minute
        CSRF_REFRESH_INTERVAL: 55 * 60 * 1000, // CSRF token refresh interval
        TOKEN_EXPIRATION_BUFFER: 5 * 60 * 1000 // 5 minutes buffer
    },
    RETRY: {
        MAX_ATTEMPTS: 3,
        BACKOFF_FACTOR: 1.5
    },
    RATE_LIMIT: {
        MAX_REQUESTS_PER_MINUTE: 60
    },
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'access_token',
        TOKEN_EXPIRY: 'token_expiry',
        NEXT_TOKEN_REQUEST: 'next_token_request'
    },
    MESSAGES: {
        RATE_LIMIT: 'Rate limit reached for today.',
        TOKEN_EXPIRED: 'Your token has expired. Please generate a new one.',
        COOLDOWN: 'Please wait before requesting a new token.'
    }
});

/**
 * SecurityManager class handles all security-related operations including
 * token management and credential verification.
 */
class SecurityManager {
    #credentials;
    #lastRefresh;
    #tokenEndpoint;
    #nonceEndpoint;
    #tokenCache;
    #initialized;
    #initializationPromise;

    // Cache dei token e nonce con relativi metadati

    constructor(tokenEndpoint, nonceEndpoint) {
        this.#tokenEndpoint = tokenEndpoint;
        this.#nonceEndpoint = nonceEndpoint;
        this.#credentials = { token: null, nonce: null };
        this.#lastRefresh = 0;
        this.#tokenCache = new Map();
        this.#initialized = false;
        this.#initializationPromise = null;
    }


    async initialize() {
        // Only initialize once
        if (this.#initialized) {
            return;
        }

        // If already initializing, return the existing promise
        if (this.#initializationPromise) {
            return this.#initializationPromise;
        }

        this.#initializationPromise = (async () => {
            try {
                // Fetch initial token
                const initialToken = await this.#fetchInitialToken();
                this.#credentials.token = initialToken;
                this.#tokenCache.set(initialToken, {
                    timestamp: Date.now()
                });

                // Fetch initial nonce
                await this.#fetchNonce();

                this.#initialized = true;
                this.#initializationPromise = null;

                // Set up automatic refresh
                this.#setupAutoRefresh();
            } catch (error) {
                this.#initializationPromise = null;
                throw error;
            }
        })();

        return this.#initializationPromise;
    }

    #setupAutoRefresh() {
        // Refresh security credentials periodically
        setInterval(async () => {
            try {
                const now = Date.now();
                if (now - this.#lastRefresh > CONFIG.TIMING.CSRF_REFRESH_INTERVAL) {
                    await this.#fetchToken();
                    await this.#fetchNonce();
                    this.#lastRefresh = now;
                }
            } catch (error) {
                console.error('Failed to refresh security credentials:', error);
            }
        }, CONFIG.TIMING.TOKEN_CHECK_INTERVAL);
    }

    async #generateOriginSignature() {
        const timestamp = Math.floor(Date.now() / 1000);

        // Use ArrayBuffer for consistent binary handling
        const buffer = new ArrayBuffer(36); // 4 + 32 bytes
        const view = new DataView(buffer);

        // Write timestamp in network byte order (big-endian)
        view.setUint32(0, timestamp, false);

        // Generate and write request ID
        const requestId = crypto.getRandomValues(new Uint8Array(32));
        new Uint8Array(buffer, 4).set(requestId);

        // Use native base64url encoding
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    async #fetchInitialToken() {
        // Initial token fetch only needs origin validation
        const originSignature = await this.#generateOriginSignature();

        const response = await fetch(this.#tokenEndpoint, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'X-JavaScript-Origin': originSignature,
                'X-Requested-With': 'XMLHttpRequest',
                'Cache-Control': 'no-cache',
                'Origin': window.location.origin
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch initial CSRF token');
        }

        const data = await response.json();
        return data.token;
    }

    /**
     * Fetches a new CSRF token from the server
     * @returns {Promise<string>} The new CSRF token
     * @throws {Error} If token fetch fails
     */
    async #fetchToken() {
        try {
            // Check if we need initial token
            if (!this.#credentials.token) {
                const initialToken = await this.#fetchInitialToken();
                this.#credentials.token = initialToken;
                this.#tokenCache.set(initialToken, {
                    timestamp: Date.now()
                });
                return initialToken;
            }
            // Cerca un token valido nella cache
            for (const [token, data] of this.#tokenCache.entries()) {
                if (Date.now() - data.timestamp < 3000000) {
                    return token;
                }
            }

            // Se non trovato, richiedi nuovo token
            const originSignature = await this.#generateOriginSignature();
            const response = await fetch(this.#tokenEndpoint, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-JavaScript-Origin': originSignature,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache',
                    'Origin': window.location.origin
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch CSRF token');
            }

            const data = await response.json();
            this.#credentials.token = data.token
            const token = data.token;

            // Salva il token nella cache
            this.#tokenCache.set(token, {
                timestamp: Date.now()
            });
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
            throw new Error('Security token fetch failed');
        }

        return token;
    }

    /**
     * Fetches a new nonce from the server
     * @returns {Promise<string>} The new nonce
     * @throws {Error} If nonce fetch fails
     */
    async #fetchNonce() {
        try {
            if (!this.#credentials.token) {
                await this.#fetchToken();
            }

            // Richiedi sempre un nuovo nonce
            const response = await fetch(this.#nonceEndpoint, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-CSRF-Token': this.#credentials.token,
                    'X-JavaScript-Origin': await this.#generateOriginSignature(),
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache',
                    'Origin': window.location.origin
                }
            });

            if (!response.ok) {
                window.location.reload();
                throw new Error('Failed to fetch CSRF nonce');
            }

            const data = await response.json();
            this.#credentials.nonce = data.nonce
            return data.nonce;

        } catch (error) {
            console.error('Failed to fetch nonce:', error);
            throw new Error('Security nonce fetch failed');
        }
    }


    #cleanupCache() {
        const now = Date.now();
        // Rimuovi token scaduti (dopo 1 ora)
        for (const [token, data] of this.#tokenCache.entries()) {
            if (now - data.timestamp > 3600000) {
                this.#tokenCache.delete(token);
            }
        }
    }

    /**
     * Gets current security credentials, refreshing if necessary
     * @returns {Promise<Object>} Current security credentials
     */
    async getSecurityCredentials() {
        if (!this.#initialized) {
            await this.initialize();
        }

        const now = Date.now();
        const needsRefresh = now - this.#lastRefresh >
            (CONFIG.TIMING.CSRF_REFRESH_INTERVAL - CONFIG.TIMING.TOKEN_EXPIRATION_BUFFER) ||
            !this.#credentials.token ||
            !this.#credentials.nonce;

        if (needsRefresh) {
            try {
                await this.#fetchToken();
                this.#lastRefresh = now;
            } catch (error) {
                console.error('Failed to refresh security credentials:', error);
                throw error;
            }
        }

        try {
            await this.#fetchNonce();
        } catch (error) {
            console.error('Failed to fetch nonce:', error);
            throw error;
        }

        return { ...this.#credentials };
    }

    async getOriginSignature() {
        return this.#generateOriginSignature();
    }

}

/**
 * RateLimiter class handles request rate limiting using a sliding window approach
 */
class RateLimiter {
    #requests;
    #maxRequests;
    #windowSeconds;
    #lastReset;
    #remainingRequests;
    #resetTime;
    #protectedEndpoints;

    constructor(maxRequests = 100, windowSeconds = 3600) {
        this.#maxRequests = maxRequests;
        this.#windowSeconds = windowSeconds;
        this.#requests = new Map();
        this.#lastReset = Date.now();
        this.#remainingRequests = maxRequests;
        this.#resetTime = null;

        // Define endpoints that require strict rate limiting
        this.#protectedEndpoints = new Set([
            '/api/portfolio/add'  // Only this endpoint has backend rate limiting
        ]);
    }


    /**
     * Checks if the current request would exceed rate limits
     * @param {string} url - The endpoint being accessed
     * @throws {Error} If rate limit would be exceeded
     */
    checkRateLimit(url) {
        // Only apply strict rate limiting to protected endpoints
        const isProtectedEndpoint = this.#protectedEndpoints.has(new URL(url, window.location.origin).pathname);

        if (!isProtectedEndpoint) {
            return; // Skip rate limiting for non-protected endpoints
        }

        const now = Date.now();

        // Clear expired entries
        for (const [timestamp] of this.#requests) {
            if (timestamp < now - (this.#windowSeconds * 1000)) {
                this.#requests.delete(timestamp);
            }
        }

        if (this.#requests.size >= this.#maxRequests) {
            const oldestRequest = Math.min(...this.#requests.keys());
            const retryAfter = Math.ceil((oldestRequest + (this.#windowSeconds * 1000) - now) / 1000);

            throw {
                status: 429,
                message: 'Rate limit exceeded. Please try again later.',
                retryAfter: retryAfter
            };
        }

        this.#requests.set(now, true);
    }

    /**
     * Updates rate limit info based on response headers
     * @param {Response} response - The fetch response object
     */
    updateFromHeaders(response) {
        const remaining = response.headers.get('X-RateLimit-Remaining');
        const reset = response.headers.get('X-RateLimit-Reset');

        if (remaining !== null) {
            this.#remainingRequests = parseInt(remaining);
        }

        if (reset !== null) {
            this.#resetTime = parseInt(reset) * 1000 + Date.now();
        }

        // Update UI with rate limit information
        this.#updateRateLimitUI();
    }

    /**
     * Updates the UI with current rate limit status
     * @private
     */
    #updateRateLimitUI() {
        const container = document.getElementById('rateLimitInfo');
        if (!container) {
            return;
        }

        if (this.#remainingRequests <= this.#maxRequests * 0.2) { // Less than 20% remaining
            container.innerHTML = `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    Rate limit warning: ${this.#remainingRequests} requests remaining
                    ${this.#resetTime ? `<br>Resets in: ${this.#formatTimeRemaining(this.#resetTime - Date.now())}` : ''}
                </div>
            `;
        }
    }

    /**
     * Formats milliseconds into a human-readable string
     * @private
     */
    #formatTimeRemaining(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);

        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        }
        return `${seconds}s`;
    }

    /**
     * Handles rate limit errors from the backend
     * @param {Object} errorData - Error data from backend
     * @throws {Error} Rate limit error with retry information
     */
    handleRateLimitError(errorData) {
        const retryAfter = errorData.retry_after || 3600; // Default to 1 hour if not specified
        const container = document.getElementById('rateLimitInfo');

        if (container) {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Rate limit exceeded. Please wait ${this.#formatTimeRemaining(retryAfter * 1000)} before adding new cryptocurrencies.
                </div>
            `;
        }

        // Update internal state
        this.#remainingRequests = 0;
        this.#resetTime = Date.now() + (retryAfter * 1000);

        throw new Error('Rate limit exceeded');
    }
}

/**
 * Main API Service implementation with enhanced security and error handling
 */
class ApiServiceImpl {
    #securityManager;
    #rateLimiter;
    #environment;
    #allowedOrigins;


    constructor() {
        this.#environment = document.querySelector('meta[name="environment"]')?.content || 'development';

        this.#securityManager = new SecurityManager(
            CONFIG.ENDPOINTS.CSRF_TOKEN,
            CONFIG.ENDPOINTS.CSRF_NONCE
        );

        this.#rateLimiter = new RateLimiter(CONFIG.RATE_LIMIT.MAX_REQUESTS_PER_MINUTE);
        // Add NGROK support to allowed origins
        this.#allowedOrigins = new Set([
            window.location.origin,
            ...this.#getNgrokOrigins()
        ]);
    }

    async initialize() {
        await this.#securityManager.initialize();
    }

    /**
     * Get NGROK origins from current URL if in development
     * @private
     */
    #getNgrokOrigins() {
        if (this.#environment !== 'development') {
            return [];
        }

        const origins = [];
        const hostname = window.location.hostname;

        // Check if current host is NGROK
        if (hostname.includes('ngrok-free.app') || hostname.includes('ngrok.app')) {
            origins.push(`https://${hostname}`);
        }

        return origins;
    }

    /**
     * Makes a secure fetch request with retry logic and security headers
     * @param {string} url The URL to fetch
     * @param {Object} options Fetch options
     * @returns {Promise<Object>} The response data
     */
    /**
 * Makes secure HTTP requests with comprehensive security controls and error handling
 * @param {string} url - The endpoint URL
 * @param {Object} options - Fetch options
 * @returns {Promise<any>} - The parsed response data
 */
    async safeFetch(url, options = {}) {

        // Ensure security manager is initialized before making any requests
        await this.#securityManager.initialize();
        // Generate unique request identifier for tracing
        const requestId = crypto.randomUUID();
        // Track concurrent requests to prevent race conditions
        const requestKey = `${url}:${options.method || 'GET'}`;

        try {
            // First, validate the URL structure for security
            const urlObj = new URL(url, window.location.origin);
            if (this.#environment === 'production' && urlObj.protocol !== 'https:') {
                throw new Error('HTTPS required in production environment');
            }

            // Apply rate limiting before proceeding
            this.#rateLimiter.checkRateLimit(url);



            // Ensure we have fresh security credentials
            const credentials = await this.#securityManager.getSecurityCredentials();


            const originSignature = await this.#securityManager.getOriginSignature();

            // Construct secure request headers
            const securityHeaders = {
                'X-CSRF-Token': credentials.token,
                'X-CSRF-Nonce': credentials.nonce,
                'X-JavaScript-Origin': originSignature,
                'X-Request-ID': requestId,
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': window.location.origin,
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache'
            };

            // Prepare the final request configuration
            const secureOptions = {
                ...options,
                credentials: 'same-origin', // Ensure cookies are sent
                headers: {
                    ...options.headers,
                    ...securityHeaders
                }
            };

            // Execute request with retry logic
            const response = await this.#withRetry(async () => {
                // Add small delay between retries to prevent overwhelming server
                await new Promise(resolve => setTimeout(resolve, 100));

                const fetchResponse = await fetch(url, secureOptions);

                // Handle rate limiting for specific endpoints
                if (url.includes('/api/portfolio/add')) {
                    this.#rateLimiter.updateFromHeaders(fetchResponse);

                    if (fetchResponse.status === 429) {
                        const errorData = await fetchResponse.json();
                        this.#rateLimiter.handleRateLimitError(errorData);
                    }
                }

                // Special handling for token cleanup
                if (fetchResponse.status === 403) {
                    if (url.includes('/api/token/cleanup')) {
                        console.warn('Token cleanup deferred - continuing operation');
                        return { status: 'warning', message: 'Token cleanup deferred' };
                    }

                    // For other 403s, we need to refresh security credentials
                    if (fetchResponse.headers.get('X-CSRF-Valid') === 'false') {
                        await this.#securityManager.resetCredentials();
                        throw { status: 403, description: 'Invalid CSRF token/nonce' };
                    }
                }

                // Handle general request failures
                if (!fetchResponse.ok) {
                    const error = new Error(`Request failed: ${fetchResponse.status}`);
                    error.status = fetchResponse.status;
                    error.response = fetchResponse;
                    throw error;
                }

                // Parse and return the response
                const contentType = fetchResponse.headers.get('Content-Type');
                if (contentType && contentType.includes('application/json')) {
                    return fetchResponse.json();
                }
                return fetchResponse.text();
            });

            return response;

        } catch (error) {
            // Enhanced error handling with specific cases
            if (error.status === 403 && error.description?.includes('Invalid CSRF')) {
                console.warn('Retrying request with fresh security credentials');
                await this.#securityManager.resetCredentials();
                return this.safeFetch(url, options);
            }

            if (error.status === 429) {
                const retryAfter = error.response?.headers?.get('Retry-After');
                throw new Error(`Rate limit exceeded. Please retry after ${retryAfter || 'some time'}.`);
            }

            // Log failed requests for debugging
            console.error('Request failed:', {
                url,
                method: options.method || 'GET',
                status: error.status,
                message: error.message,
                requestId
            });

            // Rethrow with additional context
            throw new Error(`Request failed: ${error.message}`);
        }
    }
    /**
     * Validates HTTPS usage in production
     * @private
     */
    #validateHttps(url) {
        const fullUrl = new URL(url, window.location.origin);
        if (this.#environment === 'production' && !fullUrl.protocol.startsWith('https')) {
            throw new Error('HTTPS required in production environment');
        }
    }

    /**
     * Implements retry logic with exponential backoff
     * @private
     */
    async #withRetry(operation) {
        let lastError;
        for (let attempt = 0; attempt < CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error;
                if (!this.#shouldRetry(error)) throw error;

                const delay = Math.pow(CONFIG.RETRY.BACKOFF_FACTOR, attempt) * 1000;
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        throw lastError;
    }

    /**
     * Determines if an error should trigger a retry
     * @private
     */
    #shouldRetry(error) {
        const nonRetryableStatus = [400, 401, 403, 422];
        return !(error.status && nonRetryableStatus.includes(error.status));
    }

    // Public API Methods
    async fetchCryptocurrencies() {
        return this.safeFetch('/api/cryptocurrencies');
    }

    async getCurrentCurrency() {
        return this.safeFetch('/api/preferences/currency');
    }

    async updateCurrencyPreference(currency) {
        return this.safeFetch('/api/preferences/currency', {
            method: 'PUT',
            body: JSON.stringify({ currency })
        });
    }

    async addCrypto(cryptoData) {

        return this.safeFetch('/api/portfolio/add', {
            method: 'POST',
            body: JSON.stringify(cryptoData)
        });
    }

    async updateCrypto(cryptoId, updateData) {
        const encodedId = encodeURIComponent(cryptoId);
        return this.safeFetch(`/api/portfolio/update/${encodedId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
    }

    async deleteCrypto(cryptoId) {
        const encodedId = encodeURIComponent(cryptoId);
        return this.safeFetch(`/api/portfolio/delete/${encodedId}`, {
            method: 'DELETE'
        });
    }

    async navigateToHome() {
        return this.safeFetch('/navigate-home', {
            method: 'POST'
        });
    }

}

// Create and export the singleton instance
export const ApiService = new ApiServiceImpl();

// Initialize function for global access
window.initializeSecureTokens = async function () {
    try {
        console.log('Security tokens initialized successfully');
        await ApiService.initialize();
    } catch (error) {
        console.error('Failed to initialize security tokens:', error);
        throw error;
    }
}