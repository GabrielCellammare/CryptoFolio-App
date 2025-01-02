/**
 * ApiService.js
 * A secure service module for handling API communications with comprehensive security features
 * including CSRF protection, rate limiting, and request retry logic.
 */

// SecurityManager handles all security-related operations
class SecurityManager {
    constructor(tokenEndpoint, nonceEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        this.nonceEndpoint = nonceEndpoint;
        this.credentials = { token: null, nonce: null };
        this.lastRefresh = 0;
        this.REFRESH_INTERVAL = 55 * 60 * 1000; //Intervallo CSRF token refresh
        this.TOKEN_EXPIRATION_BUFFER = 5 * 60 * 1000; // 5 minutes buffer
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
            endpoints: {
                token: '/api/token',
                tokenStatus: '/api/token/status',           // For JWT access token generation
                csrfToken: '/api/csrf/token',       // For CSRF token
                csrfNonce: '/api/csrf/nonce'        // For CSRF nonce
            },
            MAX_REQUESTS_PER_MINUTE: 60,
            REQUEST_TIMEOUT: 30000,

            MAX_RETRIES: 3,
            BACKOFF_FACTOR: 1.5,
            API_VERSION: '1.0',
            ENVIRONMENT: document.querySelector('meta[name="environment"]')?.content || 'development',
            TOKEN_STORAGE_KEY: 'access_token',
            TOKEN_EXPIRY_KEY: 'token_expiry',
            NEXT_TOKEN_REQUEST_KEY: 'next_token_request',
            TOKEN_REFRESH_THRESHOLD: 24 * 60 * 60 * 1000, // 24 ore prima della scadenza
            TOKEN_CHECK_INTERVAL: 60000, // Controlla ogni minuto


            // Costanti per i messaggi
            MESSAGES: {
                RATE_LIMIT: 'Hai raggiunto il limite di richieste token per oggi. ',
                TOKEN_EXPIRED: 'Il tuo token è scaduto. Generane uno nuovo.',
                COOLDOWN: 'Devi attendere prima di richiedere un nuovo token. '
            }


        };
        this.rateLimitResetTime = null;
        // Initialize SecurityManager with updated endpoints
        this.securityManager = new SecurityManager(
            this.config.endpoints.csrfToken,
            this.config.endpoints.csrfNonce
        );
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
    async checkTokenStatus() {
        const token = localStorage.getItem(this.config.TOKEN_STORAGE_KEY);
        const expiryStr = localStorage.getItem(this.config.TOKEN_EXPIRY_KEY);
        const nextRequestStr = localStorage.getItem(this.config.NEXT_TOKEN_REQUEST_KEY);

        if (!token || !expiryStr) {
            return { needsRefresh: true };
        }

        const expiry = new Date(expiryStr);
        const now = new Date();

        // Check if token is expired or will expire in the next hour
        // Verifica se il token sta per scadere nelle prossime 24 ore
        if (expiry.getTime() - now.getTime() < this.config.TOKEN_REFRESH_THRESHOLD) {
            // Controlla se possiamo richiedere un nuovo token
            if (nextRequestStr) {
                const nextRequest = new Date(nextRequestStr);
                if (now < nextRequest) {
                    // Calcola il tempo rimanente in un formato leggibile
                    const waitTime = this.formatWaitTime(nextRequest.getTime() - now.getTime());
                    return {
                        needsRefresh: false,
                        error: `${this.config.MESSAGES.COOLDOWN}Riprova tra ${waitTime}`
                    };
                }
            }
            return { needsRefresh: true };
        }

        return { needsRefresh: false };
    }

    // Aggiorniamo anche il metodo formatWaitTime per una migliore leggibilità
    formatWaitTime(milliseconds) {
        const hours = Math.floor(milliseconds / (1000 * 60 * 60));
        const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((milliseconds % (1000 * 60)) / 1000);

        let formattedTime = '';

        if (hours > 0) {
            formattedTime += `${hours} ${hours === 1 ? 'ora' : 'ore'}`;
            if (minutes > 0) formattedTime += ` e ${minutes} ${minutes === 1 ? 'minuto' : 'minuti'}`;
        } else if (minutes > 0) {
            formattedTime += `${minutes} ${minutes === 1 ? 'minuto' : 'minuti'}`;
            if (seconds > 0) formattedTime += ` e ${seconds} ${seconds === 1 ? 'secondo' : 'secondi'}`;
        } else {
            formattedTime += `${seconds} ${seconds === 1 ? 'secondo' : 'secondi'}`;
        }

        return formattedTime;
    }

    // Aggiungiamo un metodo per aggiornare periodicamente il timer
    startWaitTimeUpdater() {
        // Fermiamo eventuali timer esistenti
        if (this._waitTimeInterval) {
            clearInterval(this._waitTimeInterval);
        }

        // Aggiorniamo il timer ogni secondo
        this._waitTimeInterval = setInterval(() => {
            const nextRequestStr = localStorage.getItem(this.apiService.config.NEXT_TOKEN_REQUEST_KEY);
            if (nextRequestStr) {
                const nextRequest = new Date(nextRequestStr);
                const now = new Date();

                if (now < nextRequest) {
                    const waitTime = this.formatWaitTime(nextRequest.getTime() - now.getTime());
                    this.showInfo(this.config.messages.WAIT_MESSAGE.replace('{time}', waitTime));
                } else {
                    // Se il tempo è scaduto, fermiamo l'intervallo e riabilitiamo il pulsante
                    clearInterval(this._waitTimeInterval);
                    this.elements.regenerateButton.disabled = false;
                    const alerts = this.elements.container.querySelectorAll('.alert-info');
                    alerts.forEach(alert => alert.remove());
                }
            }
        }, 1000);
    }

    async handleTokenGeneration() {
        try {
            const tokenStatus = await this.checkTokenStatus();

            if (!tokenStatus.needsRefresh) {
                if (tokenStatus.error) {
                    throw new Error(tokenStatus.error);
                }
                return false;
            }

            const response = await this.safeFetch(this.config.endpoints.token, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response || !response.access_token) {
                throw new Error('Invalid token response');
            }


            // Salva le informazioni del token
            localStorage.setItem(this.config.TOKEN_STORAGE_KEY, response.access_token);
            localStorage.setItem(this.config.TOKEN_EXPIRY_KEY, response.expires_at);

            if (response.next_token_request) {
                localStorage.setItem(this.config.NEXT_TOKEN_REQUEST_KEY, response.next_token_request);
            }

            return true;

        } catch (error) {
            console.error('Token generation failed:', error);
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

                    const remainingRequests = response.headers.get('X-RateLimit-Remaining');
                    const resetTime = response.headers.get('X-RateLimit-Reset');

                    if (remainingRequests && resetTime) {
                        this.rateLimitResetTime = new Date(resetTime);
                        if (parseInt(remainingRequests) < 10) {
                            console.warn(`Rate limit warning: ${remainingRequests} requests remaining`);
                        }
                    }

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    return data;
                } catch (error) {
                    if (error.status === 429) {
                        const retryAfter = error.headers.get('Retry-After');
                        throw new Error(`Rate limit exceeded. Please try again in ${retryAfter} seconds`);
                    }
                    throw error;
                }
                finally {
                    clearTimeout(timeoutId);
                }
            });
        } catch (error) {
            if (error.status === 403 && error.description?.includes('Invalid CSRF token')) {
                // Force token refresh
                this.credentials = { token: null, nonce: null };
                this.initialized = false;
                return this.safeFetch(url, options);

            }

        } throw error;
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