/**
 * Service for handling all API communications with enhanced security features
 */
export const ApiService = {
    // Configurazione di base
    config: {
        MAX_REQUESTS_PER_MINUTE: 60,
        REQUEST_TIMEOUT: 30000, // 30 secondi
        MAX_RETRIES: 3,
        BACKOFF_FACTOR: 1.5, // Per exponential backoff
        API_VERSION: '1.0',
        ENVIRONMENT: document.querySelector('meta[name="environment"]')?.content || 'development'
    },

    // Contatore per il rate limiting lato client
    requestCounter: {
        count: 0,
        resetTime: Date.now() + 60000
    },

    /**
     * Gestione centralizzata dei token CSRF
     */
    csrfManager: {
        getToken() {
            const token = document.querySelector('meta[name="csrf-token"]')?.content;
            if (!token) {
                throw new Error('CSRF token not found');
            }
            return token;
        },

        getNonce() {
            const nonce = document.querySelector('meta[name="csrf-nonce"]')?.content;
            if (!nonce) {
                throw new Error('CSRF nonce not found');
            }
            return nonce;
        },

        async refreshNonce() {
            try {
                const response = await fetch('/api/csrf/nonce', {
                    headers: {
                        'X-CSRF-Token': this.getToken()
                    }
                });
                const data = await response.json();
                const metaTag = document.querySelector('meta[name="csrf-nonce"]');
                if (metaTag) {
                    metaTag.content = data.nonce;
                }
            } catch (error) {
                console.error('Failed to refresh nonce:', error);
                throw new Error('Unable to refresh security token');
            }
        }
    },

    /**
     * Implementa il rate limiting lato client
     * @throws {Error} Se il limite di richieste è superato
     */
    checkRateLimit() {
        const now = Date.now();
        if (now > this.requestCounter.resetTime) {
            this.requestCounter.count = 0;
            this.requestCounter.resetTime = now + 60000;
        }
        if (this.requestCounter.count >= this.config.MAX_REQUESTS_PER_MINUTE) {
            throw new Error('Too many requests. Please try again later.');
        }
        this.requestCounter.count++;
    },

    /**
     * Verifica che l'URL sia HTTPS in produzione
     * @param {string} url - URL da verificare
     */
    validateHttps(url) {
        const fullUrl = new URL(url, window.location.origin);
        if (this.config.ENVIRONMENT === 'production' && !fullUrl.protocol.startsWith('https')) {
            throw new Error('HTTPS required in production');
        }
    },

    /**
     * Implementa retry logic con exponential backoff
     * @param {Function} operation - Funzione da riprovare
     */
    async withRetry(operation) {
        let lastError;
        for (let attempt = 0; attempt < this.config.MAX_RETRIES; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error;
                if (!this.shouldRetry(error)) {
                    throw error;
                }
                const delay = Math.pow(this.config.BACKOFF_FACTOR, attempt) * 1000;
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        throw lastError;
    },

    /**
     * Determina se un errore dovrebbe attivare un retry
     * @param {Error} error - L'errore da valutare
     */
    shouldRetry(error) {
        // Non ritentare per errori di validazione o autenticazione
        const nonRetryableStatus = [400, 401, 403, 422];
        return !(error.status && nonRetryableStatus.includes(error.status));
    },

    /**
     * Wrapper sicuro per le chiamate fetch con tutte le misure di sicurezza
     * @param {string} url - URL della richiesta
     * @param {Object} options - Opzioni della richiesta
     */
    async safeFetch(url, options = {}) {
        // Verifica HTTPS
        this.validateHttps(url);

        // Rate limiting
        this.checkRateLimit();

        // Preparazione headers di sicurezza
        const securityHeaders = this.prepareSecurityHeaders(options.method);

        // Configurazione di base della sicurezza
        const secureOptions = {
            ...options,
            headers: {
                ...securityHeaders,
                ...options.headers
            },
            credentials: 'same-origin',
            timeout: this.config.REQUEST_TIMEOUT,
            mode: 'same-origin',
            referrerPolicy: 'same-origin'
        };

        // Logging della richiesta
        const requestId = crypto.randomUUID();
        await this.logRequest(url, secureOptions, requestId);

        return this.withRetry(async () => {
            const response = await fetch(url, secureOptions);

            // Gestione risposta
            await this.handleResponse(response, url, requestId);

            // Se la richiesta modifica dati, aggiorna il nonce
            if (['POST', 'PUT', 'DELETE'].includes(options.method)) {
                await this.csrfManager.refreshNonce();
            }

            return response.json();
        });
    },

    /**
     * Prepara gli headers di sicurezza per la richiesta
     * @param {string} method - Metodo HTTP della richiesta
     */
    prepareSecurityHeaders(method) {
        const headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Client-Version': this.config.API_VERSION,
            'Content-Type': 'application/json',
        };

        if (['POST', 'PUT', 'DELETE'].includes(method)) {
            const token = this.csrfManager.getToken();
            const nonce = this.csrfManager.getNonce();

            console.log('CSRF Token:', token);
            console.log('CSRF Nonce:', nonce);

            headers['X-CSRF-Token'] = token;
            headers['X-CSRF-Nonce'] = nonce;
        }

        return headers;
    },

    /**
     * Gestisce la risposta della richiesta
     * @param {Response} response - Risposta fetch
     * @param {string} url - URL della richiesta
     * @param {string} requestId - ID della richiesta per il logging
     */
    async handleResponse(response, url, requestId) {
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            await this.logError(url, response.status, error, requestId);
            throw new Error(
                error.message ||
                `HTTP error! status: ${response.status} - ${response.statusText}`
            );
        }
    },

    /**
     * Logger centralizzato per monitoraggio
     */
    async logRequest(url, options, requestId) {
        const logData = {
            timestamp: new Date().toISOString(),
            requestId,
            url,
            method: options.method || 'GET',
            userAgent: navigator.userAgent,
            environment: this.config.ENVIRONMENT
        };

        console.log('API Request:', logData);

        if (this.config.ENVIRONMENT === 'production') {
            try {
                await fetch('/api/logs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(logData)
                });
            } catch (error) {
                console.error('Logging error:', error);
            }
        }
    },

    async logResponse(url, response, requestId) {
        const logData = {
            timestamp: new Date().toISOString(),
            requestId,
            url,
            status: response.status,
            success: true
        };

        console.log('API Response:', logData);
    },

    async logError(url, status, error, requestId) {
        const logData = {
            timestamp: new Date().toISOString(),
            requestId,
            url,
            status,
            error: error.message || 'Unknown error',
            success: false
        };

        console.error('API Error:', logData);
    },

    // Metodi API esistenti modificati per utilizzare safeFetch
    async fetchCryptocurrencies() {
        return this.safeFetch('/api/cryptocurrencies');
    },

    async addCrypto(cryptoData) {
        return this.safeFetch('/api/portfolio/add', {
            method: 'POST',
            body: JSON.stringify(cryptoData)
        });
    },

    async updateCrypto(cryptoId, updateData) {
        return this.safeFetch(`/api/portfolio/update/${encodeURIComponent(cryptoId)}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
    },

    async updateCurrencyPreference(currency) {
        return this.safeFetch('/api/preferences/currency', {
            method: 'PUT',
            body: JSON.stringify({ currency })
        });
    },

    async deleteCrypto(cryptoId) {
        return this.safeFetch(`/api/portfolio/delete/${encodeURIComponent(cryptoId)}`, {
            method: 'DELETE'
        });
    },

    async getCurrentCurrency() {
        try {
            const data = await this.safeFetch('/api/preferences/currency');
            console.log('Currency data received:', data);
            return data;
        } catch (error) {
            console.error('Error in getCurrentCurrency:', error);
            throw error;
        }
    }
};