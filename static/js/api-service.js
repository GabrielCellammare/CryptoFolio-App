/**
 * ApiService.js
 * A secure service module for handling API communications with comprehensive security features
 * including CSRF protection, rate limiting, and request retry logic.
 */

// SecurityManager handles all security-related operations
class SecurityManager {
    constructor() {
        this.tokenEndpoint = '/api/csrf/token';
        this.nonceEndpoint = '/api/csrf/nonce';
        this.credentials = { token: null, nonce: null };
        this.lastRefresh = 0;
        this.REFRESH_INTERVAL = 5 * 60 * 1000; //Intervallo Nonce
        this.TOKEN_EXPIRATION_BUFFER = 30 * 1000; // 30 seconds buffer
    }

    async getToken() {
        try {
            const response = await fetch(this.tokenEndpoint, {
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });

            if (!response.ok) {
                throw new Error(`Token fetch failed: ${response.status}`);
            }

            const data = await response.json();
            this.credentials.token = data.token;
            return data.token;
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
            throw new Error('Security token fetch failed');
        }
    }

    async getNonce() {
        try {
            if (!this.credentials.token) {
                await this.getToken();
            }

            const response = await fetch(this.nonceEndpoint, {
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': this.credentials.token
                }
            });

            if (!response.ok) {
                throw new Error(`Nonce fetch failed: ${response.status}`);
            }

            const data = await response.json();
            this.credentials.nonce = data.nonce;
            return data.nonce;
        } catch (error) {
            console.error('Failed to fetch nonce:', error);
            throw new Error('Security nonce fetch failed');
        }
    }

    async getSecurityCredentials() {
        const now = Date.now();
        if (now - this.lastRefresh > (this.REFRESH_INTERVAL - this.TOKEN_EXPIRATION_BUFFER) ||
            !this.credentials.token ||
            !this.credentials.nonce) {
            // Get token first
            await this.getToken();
            // Then get nonce

            this.lastRefresh = now;
        }
        await this.getNonce();
        return { ...this.credentials };
    }
}

// RateLimiter handles request rate limiting
class RateLimiter {
    constructor(maxRequestsPerMinute) {
        this.maxRequests = maxRequestsPerMinute;
        this.requests = [];
    }

    checkRateLimit() {
        const now = Date.now();
        const oneMinuteAgo = now - 60000;
        this.requests = this.requests.filter(timestamp => timestamp > oneMinuteAgo);

        if (this.requests.length >= this.maxRequests) {
            throw new Error('Rate limit exceeded. Please try again later.');
        }

        this.requests.push(now);
    }
}

// Main API Service implementation
class ApiServiceImpl {
    constructor() {
        this.config = {
            MAX_REQUESTS_PER_MINUTE: 60,
            REQUEST_TIMEOUT: 30000,
            MAX_RETRIES: 3,
            BACKOFF_FACTOR: 1.5,
            API_VERSION: '1.0',
            ENVIRONMENT: document.querySelector('meta[name="environment"]')?.content || 'development'
        };

        this.securityManager = new SecurityManager();
        this.rateLimiter = new RateLimiter(this.config.MAX_REQUESTS_PER_MINUTE);
        this.initialized = false;
    }

    async initialize() {
        if (this.initialized) return;

        try {
            await this.securityManager.getSecurityCredentials();
            this.initialized = true;
            console.log('API Service initialized successfully');
        } catch (error) {
            console.error('Failed to initialize API Service:', error);
            throw error;
        }
    }

    validateHttps(url) {
        const fullUrl = new URL(url, window.location.origin);
        if (this.config.ENVIRONMENT === 'production' && !fullUrl.protocol.startsWith('https')) {
            throw new Error('HTTPS required in production environment');
        }
    }

    async withRetry(operation) {
        let lastError;
        for (let attempt = 0; attempt < this.config.MAX_RETRIES; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error;
                if (!this.shouldRetry(error)) throw error;
                const delay = Math.pow(this.config.BACKOFF_FACTOR, attempt) * 1000;
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        throw lastError;
    }

    shouldRetry(error) {
        const nonRetryableStatus = [400, 401, 403, 422];
        return !(error.status && nonRetryableStatus.includes(error.status));
    }

    async safeFetch(url, options = {}) {

        try {
            if (!this.initialized) {
                await this.initialize();
            }

            this.validateHttps(url);
            this.rateLimiter.checkRateLimit();

            const credentials = await this.securityManager.getSecurityCredentials();
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
                    'X-Request-ID': requestId
                },
                timeout: this.config.REQUEST_TIMEOUT,
                mode: 'same-origin',
                referrerPolicy: 'same-origin'
            };

            return this.withRetry(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.config.REQUEST_TIMEOUT);

                try {
                    const response = await fetch(url, {
                        ...secureOptions,
                        signal: controller.signal
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    return data;
                } finally {
                    clearTimeout(timeoutId);
                }
            });
        } catch {
            if (error.status === 403 && error.description?.includes('Invalid CSRF token')) {
                // Force token refresh
                await this.securityManager.getToken();
                await this.securityManager.getNonce();
                if (!this.initialized) {
                    await this.initialize();
                }

                this.validateHttps(url);
                this.rateLimiter.checkRateLimit();

                const credentials = await this.securityManager.getSecurityCredentials();
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
                        'X-Request-ID': requestId
                    },
                    timeout: this.config.REQUEST_TIMEOUT,
                    mode: 'same-origin',
                    referrerPolicy: 'same-origin'
                };

                return this.withRetry(async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), this.config.REQUEST_TIMEOUT);

                    try {
                        const response = await fetch(url, {
                            ...secureOptions,
                            signal: controller.signal
                        });

                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }

                        const data = await response.json();
                        return data;
                    } finally {
                        clearTimeout(timeoutId);
                    }
                });
            }

        }
    }

    // API Methods
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
        return this.safeFetch(`/api/portfolio/update/${encodeURIComponent(cryptoId)}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
    }

    async navigateToHome() {
        // We want to ensure we have fresh security credentials before navigation
        await this.initialize();  // This refreshes our security tokens

        return this.safeFetch('/navigate-home', {
            method: 'POST',
            // No need to specify headers or credentials as safeFetch handles these
        });
    }

    async deleteCrypto(cryptoId) {
        return this.safeFetch(`/api/portfolio/delete/${encodeURIComponent(cryptoId)}`, {
            method: 'DELETE'
        });
    }
}

// Create and export the singleton instance
export const ApiService = new ApiServiceImpl();

// Export the initialization function for global access
window.initializeSecureTokens = async function () {
    try {
        await ApiService.initialize();
        console.log('Security tokens initialized successfully');
    } catch (error) {
        console.error('Failed to initialize security tokens:', error);
        throw error;
    }
};