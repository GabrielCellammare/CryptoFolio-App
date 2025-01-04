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
const CONFIG = Object.freeze({
    ENDPOINTS: {
        TOKEN: '/api/token',
        TOKEN_STATUS: '/api/token/status',
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

    constructor(tokenEndpoint, nonceEndpoint) {
        this.#tokenEndpoint = tokenEndpoint;
        this.#nonceEndpoint = nonceEndpoint;
        this.#credentials = { token: null, nonce: null };
        this.#lastRefresh = 0;
    }

    /**
     * Fetches a new CSRF token from the server
     * @returns {Promise<string>} The new CSRF token
     * @throws {Error} If token fetch fails
     */
    async #fetchToken() {
        try {
            const response = await fetch(this.#tokenEndpoint, {
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache'
                }
            });

            if (!response.ok) {
                throw new Error(`Token fetch failed: ${response.status}`);
            }

            const data = await response.json();
            this.#credentials.token = data.token;
            return data.token;
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
            throw new Error('Security token fetch failed');
        }
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

            const response = await fetch(this.#nonceEndpoint, {
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': this.#credentials.token,
                    'Cache-Control': 'no-cache'
                }
            });

            if (!response.ok) {
                throw new Error(`Nonce fetch failed: ${response.status}`);
            }

            const data = await response.json();
            this.#credentials.nonce = data.nonce;
            return data.nonce;
        } catch (error) {
            console.error('Failed to fetch nonce:', error);
            throw new Error('Security nonce fetch failed');
        }
    }

    /**
     * Gets current security credentials, refreshing if necessary
     * @returns {Promise<Object>} Current security credentials
     */
    async getSecurityCredentials() {
        const now = Date.now();
        const needsRefresh = now - this.#lastRefresh >
            (CONFIG.TIMING.CSRF_REFRESH_INTERVAL - CONFIG.TIMING.TOKEN_EXPIRATION_BUFFER) ||
            !this.#credentials.token ||
            !this.#credentials.nonce;

        if (needsRefresh) {
            await this.#fetchToken();
            this.#lastRefresh = now;
        }

        await this.#fetchNonce();
        return { ...this.#credentials };
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
    #initialized;
    #environment;

    constructor() {
        this.#initialized = false;
        this.#environment = document.querySelector('meta[name="environment"]')?.content || 'development';

        this.#securityManager = new SecurityManager(
            CONFIG.ENDPOINTS.CSRF_TOKEN,
            CONFIG.ENDPOINTS.CSRF_NONCE
        );

        this.#rateLimiter = new RateLimiter(CONFIG.RATE_LIMIT.MAX_REQUESTS_PER_MINUTE);
    }

    /**
     * Initializes the API service and security credentials
     * @returns {Promise<void>}
     */
    async initialize() {
        if (this.#initialized) return;

        try {
            await this.#securityManager.getSecurityCredentials();
            this.#initialized = true;
            console.log('API Service initialized successfully');
        } catch (error) {
            console.error('Failed to initialize API Service:', error);
            throw error;
        }
    }

    /**
     * Checks token status and determines if refresh is needed
     * @returns {Promise<Object>} Token status information
     */
    async checkTokenStatus() {
        const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
        const expiryStr = localStorage.getItem(CONFIG.STORAGE_KEYS.TOKEN_EXPIRY);
        const nextRequestStr = localStorage.getItem(CONFIG.STORAGE_KEYS.NEXT_TOKEN_REQUEST);

        if (!token || !expiryStr) {
            return { needsRefresh: true };
        }

        const expiry = new Date(expiryStr);
        const now = new Date();

        if (expiry.getTime() - now.getTime() < CONFIG.TIMING.TOKEN_REFRESH_THRESHOLD) {
            if (nextRequestStr) {
                const nextRequest = new Date(nextRequestStr);
                if (now < nextRequest) {
                    const waitTime = this.#formatWaitTime(nextRequest.getTime() - now.getTime());
                    return {
                        needsRefresh: false,
                        error: `${CONFIG.MESSAGES.COOLDOWN} Try again in ${waitTime}`
                    };
                }
            }
            return { needsRefresh: true };
        }

        return { needsRefresh: false };
    }

    /**
     * Formats wait time into human-readable string
     * @param {number} milliseconds Time to format
     * @returns {string} Formatted time string
     */
    #formatWaitTime(milliseconds) {
        const hours = Math.floor(milliseconds / (1000 * 60 * 60));
        const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((milliseconds % (1000 * 60)) / 1000);

        const parts = [];
        if (hours > 0) parts.push(`${hours} ${hours === 1 ? 'hour' : 'hours'}`);
        if (minutes > 0) parts.push(`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`);
        if (seconds > 0) parts.push(`${seconds} ${seconds === 1 ? 'second' : 'seconds'}`);

        return parts.join(' and ');
    }

    /**
     * Makes a secure fetch request with retry logic and security headers
     * @param {string} url The URL to fetch
     * @param {Object} options Fetch options
     * @returns {Promise<Object>} The response data
     */
    async safeFetch(url, options = {}) {
        try {
            if (!this.#initialized) {
                await this.initialize();
            }

            this.#validateHttps(url);
            this.#rateLimiter.checkRateLimit(url);

            const credentials = await this.#securityManager.getSecurityCredentials();
            const requestId = crypto.randomUUID();

            const secureOptions = {
                ...options,
                credentials: 'same-origin',
                headers: {
                    ...options.headers,
                    'X-CSRF-Token': credentials.token,
                    'X-CSRF-Nonce': credentials.nonce,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json',
                    'X-Request-ID': requestId,
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                mode: 'same-origin',
                referrerPolicy: 'same-origin'
            };

            const response = await this.#withRetry(async () => {
                const response = await fetch(url, secureOptions);

                // Update rate limiter with header information
                if (url.includes('/api/portfolio/add')) {
                    this.#rateLimiter.updateFromHeaders(response);
                }

                // Handle rate limit errors
                if (response.status === 429) {
                    const errorData = await response.json();
                    this.#rateLimiter.handleRateLimitError(errorData);
                }

                if (!response.ok) {
                    const error = new Error(`HTTP error! status: ${response.status}`);
                    error.status = response.status;
                    throw error;
                }

                return response.json();
            });

            return response;

        } catch (error) {
            // Handle CSRF token errors as before
            if (error.status === 403 && error.description?.includes('Invalid CSRF token')) {
                this.#initialized = false;
                return this.safeFetch(url, options);
            }

            if (error.status === 429) {
                throw new Error('Rate limit exceeded. Please try again later.');
            }

            // Handle other errors as before
            throw error;
        }
    }

    /**
     * Executes a single request attempt with timeout handling
     * @private
     */
    async #executeRequest(url, options) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMING.REQUEST_TIMEOUT);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });

            this.#handleRateLimitHeaders(response);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * Handles rate limit headers from response
     * @private
     */
    #handleRateLimitHeaders(response) {
        const remaining = response.headers.get('X-RateLimit-Remaining');
        const resetTime = response.headers.get('X-RateLimit-Reset');

        if (remaining && resetTime) {
            if (parseInt(remaining) < 10) {
                console.warn(`Rate limit warning: ${remaining} requests remaining`);
            }
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
        await this.initialize();
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
        await ApiService.initialize();
        console.log('Security tokens initialized successfully');
    } catch (error) {
        console.error('Failed to initialize security tokens:', error);
        throw error;
    }
}