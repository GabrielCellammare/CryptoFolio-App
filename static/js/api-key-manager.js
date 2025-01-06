import { ApiService } from "./api-service.js";

/**
 * Manages JWT API tokens with secure handling and cooldown enforcement
 * @class ApiKeyManager
 */
export default class ApiKeyManager {
    // Core configuration object
    #config = {
        endpoints: {
            token: '/api/token',
            status: '/api/token/status',
            cleanup: '/api/token/cleanup'
        },
        timeouts: {
            display: 30_000,
            copy: 3_000,
            cooldown: 12 * 60 * 60 * 1000
        },
        messages: {
            tokenExpiring: 'Your token will expire in {days} days',
            tokenGenerated: 'New token generated successfully',
            waitMessage: 'You can generate a new token in {time}',
            tokenCreation: 'Token created on {date} at {time}',
            noToken: 'No token generated',
            dailyLimitReached: 'Daily token limit reached. Please try again tomorrow.'
        }
    };

    // Private state management
    #state = {
        isVisible: false,
        isLoading: false,
        tokenInfo: null,
        waitTimeInterval: null,
        persistentAlerts: new Set()
    };

    // DOM elements container
    #elements = {};

    constructor() {
        this.handleToggleDisplay = this.#handleToggleDisplay.bind(this);
        this.handleCopy = this.#handleCopy.bind(this);
        this.handleTokenGeneration = this.#handleTokenGeneration.bind(this);
    }

    /**
     * Initialize the manager and set up necessary elements and listeners
     */
    async initialize() {
        try {
            await ApiService.initialize();
            this.#initializeElements();
            this.#setupEventListeners();
            await this.#performCleanupAndUpdate();

            setInterval(() => this.#updateTokenStatus(), 60000);
        } catch (error) {
            console.error('Initialization failed:', error);
            this.#showError('Failed to initialize API key management');
        }
    }

    /**
     * Initialize DOM elements with error checking
     */
    #initializeElements() {
        const requiredElements = {
            apiKeyInput: '#apiKey',
            toggleButton: '#toggleApiKey',
            copyButton: '#copyApiKey',
            regenerateButton: '#regenerateApiKey',
            tokenStatus: '#tokenStatus',
            alertContainer: '#alertContainer',
            persistentAlertContainer: '#persistentAlertContainer'
        };

        for (const [key, selector] of Object.entries(requiredElements)) {
            const element = document.querySelector(selector);
            if (!element) {
                throw new Error(`Required element not found: ${selector}`);
            }
            this.#elements[key] = element;
        }

        this.#elements.toggleButton.disabled = true;
        this.#elements.copyButton.disabled = true;
    }

    /**
     * Set up event listeners
     */
    #setupEventListeners() {
        this.#elements.toggleButton.addEventListener('click', this.handleToggleDisplay);
        this.#elements.copyButton.addEventListener('click', this.handleCopy);
        this.#elements.regenerateButton.addEventListener('click', this.handleTokenGeneration);

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) this.#hideApiKey();
        });
    }



    /**
     * Handle token generation with security measures
     */
    async #handleTokenGeneration() {
        if (this.#state.isLoading) return;

        try {
            this.#state.isLoading = true;
            this.#elements.regenerateButton.disabled = true;
            this.#showInfo('Generating new API token...');

            const response = await ApiService.safeFetch(this.#config.endpoints.token, {
                method: 'POST'
            });

            if (!response?.access_token) {
                throw new Error(response.error || 'Invalid token response');
            }

            this.#updateUIWithToken({
                access_token: response.access_token,
                created_at: response.token_created_at || response.created_at,
                expires_at: response.expires_at
            });

            if (response.next_token_request) {
                localStorage.setItem('next_token_request', response.next_token_request);
                this.#startWaitTimeUpdater();
            }

            this.#showSuccess(this.#config.messages.tokenGenerated);
        } catch (error) {
            console.error('Token generation failed:', error);
            this.#showError(error.message.includes('Daily limit') ?
                this.#config.messages.dailyLimitReached : error.message);
            this.#setNoTokenState();
        } finally {
            this.#state.isLoading = false;
            await this.#updateTokenStatus();
        }
    }

    /**
     * Update token status and UI elements
     */
    async #updateTokenStatus() {
        try {
            const data = await ApiService.safeFetch(this.#config.endpoints.status, { method: 'GET' });

            if (data.token_status === 'expired') {
                this.#showPersistentAlert(
                    'Your token has expired. Please generate a new one.',
                    'warning',
                    'token-expired'
                );
                this.#setNoTokenState();
                return;
            }

            if (data.has_active_token && data.token_info) {
                this.#updateUIWithToken(data.token_info);
            } else {
                this.#setNoTokenState();
            }

            this.#elements.regenerateButton.disabled = !data.can_generate;

            if (!data.can_generate && data.next_eligible_time) {
                const waitTime = this.#formatTimeRemaining(
                    new Date(data.next_eligible_time).getTime() - Date.now()
                );
                this.#showPersistentAlert(
                    this.#config.messages.waitMessage.replace('{time}', waitTime),
                    'info',
                    'cooldown-timer'
                );
            }
        } catch (error) {
            console.error('Status update failed:', error);
            this.#showError('Failed to update token status');
        }
    }

    #sanitizeToken(token) {
        // Verifica che il token sia nel formato atteso (esempio: JWT)
        if (!this.#isValidTokenFormat(token)) {
            throw new Error('Invalid token format');
        }

        // Rimuove caratteri potenzialmente pericolosi
        return this.#escapeHtmlChars(token);
    }

    #isValidTokenFormat(token) {
        // Verifica che il token sia una stringa JWT valida
        const jwtPattern = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
        return jwtPattern.test(token);
    }

    #escapeHtmlChars(str) {
        const htmlEscapes = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        };
        return str.replace(/[&<>"'/]/g, char => htmlEscapes[char]);
    }

    /**
     * Update UI with token information
     */
    #updateUIWithToken(tokenInfo) {
        if (!tokenInfo?.access_token) {
            this.#setNoTokenState();
            return;
        }

        const { dateFormatted, timeFormatted } = this.#formatDate(
            tokenInfo.created_at || tokenInfo.token_created_at
        );

        try {
            // Sanitizza il token prima di inserirlo nel DOM
            const sanitizedToken = this.#sanitizeToken(tokenInfo.access_token);
            this.#elements.apiKeyInput.value = sanitizedToken;

            // Imposta attributi di sicurezza sull'elemento
            this.#elements.apiKeyInput.setAttribute('data-sanitized', 'true');
            this.#elements.apiKeyInput.setAttribute('autocomplete', 'off');
        } catch (error) {
            console.error('Token sanitization failed:', error);
            this.#showError('Invalid token format detected');
            this.#setNoTokenState();
        }


        this.#elements.apiKeyInput.classList.remove('text-muted');
        this.#elements.toggleButton.disabled = false;
        this.#elements.copyButton.disabled = false;

        const creationMessage = this.#config.messages.tokenCreation
            .replace('{date}', dateFormatted)
            .replace('{time}', timeFormatted);

        this.#showPersistentAlert(creationMessage, 'info', 'token-creation');
        this.#elements.tokenStatus.textContent = creationMessage;
        this.#state.tokenInfo = tokenInfo;

        if (tokenInfo.expires_at) {
            const daysLeft = Math.ceil(
                (new Date(tokenInfo.expires_at) - new Date()) / (1000 * 60 * 60 * 24)
            );
            if (daysLeft > 0) {
                const expiryMessage = this.#config.messages.tokenExpiring.replace('{days}', daysLeft);
                this.#showInfo(expiryMessage);
                this.#showPersistentAlert(expiryMessage, 'warning', 'token-expiry');
            }
        }
    }

    /**
     * Perform token cleanup and status update
     */
    async #performCleanupAndUpdate() {
        try {
            await ApiService.initialize();
            await this.#cleanupExpiredTokens();
            await this.#updateTokenStatus();
        } catch (error) {
            console.error('Cleanup and update failed:', error);
        }
    }

    /**
     * Clean up expired tokens
     */
    async #cleanupExpiredTokens() {
        try {
            const response = await ApiService.safeFetch(this.#config.endpoints.cleanup, {
                method: 'POST'
            });

            if (response.error) {
                console.warn('Token cleanup warning:', response.error);
                return;
            }

            if (response.cleaned_tokens > 0) {
                this.#showInfo(`${response.cleaned_tokens} expired tokens have been cleaned up`);
            }
        } catch (error) {
            console.error('Token cleanup failed:', error);
        }
    }

    /**
     * Manage wait time updates
     */
    #startWaitTimeUpdater() {
        this.#stopWaitTimeUpdater();

        const nextTokenTime = localStorage.getItem('next_token_request');
        if (!nextTokenTime) return;

        this.#updateWaitTimeMessage(nextTokenTime);
        this.#state.waitTimeInterval = setInterval(() => {
            this.#updateWaitTimeMessage(nextTokenTime);
        }, 60000);
    }

    #stopWaitTimeUpdater() {
        if (this.#state.waitTimeInterval) {
            clearInterval(this.#state.waitTimeInterval);
            this.#state.waitTimeInterval = null;
        }
    }

    #updateWaitTimeMessage(nextTokenTime) {
        const cooldown = this.#calculateRemainingCooldown(nextTokenTime);

        if (!cooldown) {
            this.#elements.regenerateButton.disabled = false;
            this.#removePersistentAlert('cooldown-timer');
            this.#elements.alertContainer.querySelectorAll('.alert-info').forEach(alert => alert.remove());
            this.#stopWaitTimeUpdater();
            return;
        }

        const formattedTime = this.#formatCooldownTime(cooldown);
        const message = this.#config.messages.waitMessage.replace('{time}', formattedTime);
        this.#showPersistentAlert(message, 'info', 'cooldown-timer');
        this.#showInfo(message);

        if (cooldown.totalMilliseconds < 60000) {
            this.#stopWaitTimeUpdater();
            this.#state.waitTimeInterval = setInterval(() => {
                this.#updateWaitTimeMessage(nextTokenTime);
            }, 1000);
        }
    }

    #calculateRemainingCooldown(nextTokenTime) {
        const timeDiff = new Date(nextTokenTime) - new Date();
        if (timeDiff <= 0) return null;

        return {
            hours: Math.floor(timeDiff / (1000 * 60 * 60)),
            minutes: Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60)),
            totalMilliseconds: timeDiff
        };
    }

    #formatCooldownTime(cooldown) {
        if (!cooldown) return '';

        const parts = [];
        if (cooldown.hours > 0) {
            parts.push(`${cooldown.hours} ${cooldown.hours === 1 ? 'hour' : 'hours'}`);
        }
        if (cooldown.minutes > 0 || parts.length === 0) {
            parts.push(`${cooldown.minutes} ${cooldown.minutes === 1 ? 'minute' : 'minutes'}`);
        }

        return parts.join(' and ');
    }

    #setNoTokenState() {
        this.#elements.apiKeyInput.value = this.#config.messages.noToken;
        this.#elements.apiKeyInput.classList.add('text-muted');
        this.#elements.toggleButton.disabled = true;
        this.#elements.copyButton.disabled = true;
        this.#state.tokenInfo = null;
        ['token-creation', 'token-expiry'].forEach(id => this.#removePersistentAlert(id));
    }

    // Utility methods for date and time formatting
    #formatDate(dateString) {
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) throw new Error('Invalid date');

            return {
                dateFormatted: date.toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                }),
                timeFormatted: date.toLocaleTimeString(undefined, {
                    hour: '2-digit',
                    minute: '2-digit'
                })
            };
        } catch (error) {
            console.error('Date formatting error:', error);
            return { dateFormatted: 'Unknown date', timeFormatted: 'Unknown time' };
        }
    }

    #formatTimeRemaining(milliseconds) {
        const hours = Math.floor(milliseconds / (1000 * 60 * 60));
        const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));

        const parts = [];
        if (hours > 0) parts.push(`${hours} ${hours === 1 ? 'hour' : 'hours'}`);
        if (minutes > 0) parts.push(`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`);

        return parts.join(' and ') || 'less than a minute';
    }

    // Alert management methods
    #showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.setAttribute('role', 'alert');

        const messageText = document.createTextNode(message);
        alertDiv.appendChild(messageText);

        const closeButton = document.createElement('button');
        closeButton.className = 'btn-close';
        closeButton.setAttribute('type', 'button');
        closeButton.setAttribute('data-bs-dismiss', 'alert');
        closeButton.setAttribute('aria-label', 'Close');
        alertDiv.appendChild(closeButton);

        this.#elements.alertContainer.querySelectorAll('.alert').forEach(alert => alert.remove());
        this.#elements.alertContainer.appendChild(alertDiv);
    }

    #showError(message) { this.#showAlert(message, 'danger'); }
    #showSuccess(message) { this.#showAlert(message, 'success'); }
    #showInfo(message) { this.#showAlert(message, 'info'); }
    #showWarning(message) { this.#showAlert(message, 'warning'); }

    // Persistent alert methods
    #showPersistentAlert(message, type, id) {
        this.#removePersistentAlert(id);

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} fade show`;
        alertDiv.setAttribute('role', 'alert');
        alertDiv.setAttribute('data-alert-id', id);
        alertDiv.appendChild(document.createTextNode(message));

        this.#elements.persistentAlertContainer.appendChild(alertDiv);
        this.#state.persistentAlerts.add(id);
    }

    #removePersistentAlert(id) {
        const existingAlert = this.#elements.persistentAlertContainer.querySelector(
            `[data-alert-id="${id}"]`
        );
        if (existingAlert) {
            existingAlert.remove();
            this.#state.persistentAlerts.delete(id);
        }
    }

    // Token visibility methods
    #handleToggleDisplay() {
        if (this.#elements.apiKeyInput.value === this.#config.messages.noToken) return;

        if (this.#elements.apiKeyInput.type === 'password') {
            this.#showApiKey();
            setTimeout(() => this.#hideApiKey(), this.#config.timeouts.display);
        } else {
            this.#hideApiKey();
        }
    }

    #showApiKey() {
        this.#elements.apiKeyInput.type = 'text';
        this.#elements.toggleButton.querySelector('i').className = 'fas fa-eye-slash';
        this.#state.isVisible = true;
    }

    #hideApiKey() {
        this.#elements.apiKeyInput.type = 'password';
        this.#elements.toggleButton.querySelector('i').className = 'fas fa-eye';
        this.#state.isVisible = false;
    }

    // Copy functionality
    async #handleCopy() {
        try {
            const key = this.#elements.apiKeyInput.value;
            if (key === this.#config.messages.noToken) {
                this.#showError('No API key available to copy');
                return;
            }

            await navigator.clipboard.writeText(key);
            this.#showSuccess('API key copied to clipboard');
            setTimeout(() => {
                this.#elements.alertContainer
                    .querySelector('.alert-success')?.remove();
            }, this.#config.timeouts.copy);
        } catch (error) {
            console.error('Copy failed:', error);
            this.#showError('Failed to copy API key');
        }
    }
}