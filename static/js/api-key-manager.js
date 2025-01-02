import { ApiService } from "./api-service.js";

/**
 * SecureApiKeyManager.js
 * Enhanced secure service for managing JWT API tokens with strict cooldown enforcement
 */
export default class ApiKeyManager {
    constructor() {
        // Core configuration
        this.config = {
            endpoints: {
                token: '/api/token',
                status: '/api/token/status',
                cleanup: '/api/token/cleanup'
            },
            displayTimeout: 30000, // 30 seconds
            copyTimeout: 3000,     // 3 seconds
            cooldownPeriod: 12 * 60 * 60 * 1000, // 12 hours in milliseconds
            messages: {
                tokenExpiring: 'Your token will expire in {days} days',
                tokenGenerated: 'New token generated successfully',
                waitMessage: 'You can generate a new token in {time}',
                tokenCreation: 'Token created on {date} at {time}',
                noToken: 'No token generated',
                dailyLimitReached: 'Daily token limit reached. Please try again tomorrow.'
            }
        };

        // Secure state management
        this.state = {
            isVisible: false,
            isLoading: false,
            tokenInfo: null,
            waitTimeInterval: null,
            persistentAlerts: new Set()
        };

        // DOM elements - initialized in initialize()
        this.elements = {
            apiKeyInput: null,
            toggleButton: null,
            copyButton: null,
            regenerateButton: null,
            tokenStatus: null,
            alertContainer: null,
            persistentAlertContainer: null
        };

        // Bind methods
        this.handleToggleDisplay = this.handleToggleDisplay.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.handleTokenGeneration = this.handleTokenGeneration.bind(this);
        this.updateTokenStatus = this.updateTokenStatus.bind(this);
        this.startWaitTimeUpdater = this.startWaitTimeUpdater.bind(this);
        this.stopWaitTimeUpdater = this.stopWaitTimeUpdater.bind(this);
        this.lastCleanupCheck = null;
    }

    /**
    * Calculate the exact remaining cooldown time
    */
    calculateRemainingCooldown(nextTokenTime) {
        const now = new Date();
        const nextTime = new Date(nextTokenTime);
        const timeDiff = nextTime - now;

        // If time difference is negative or zero, cooldown has expired
        if (timeDiff <= 0) {
            return null;
        }

        // Calculate hours and minutes
        const hours = Math.floor(timeDiff / (1000 * 60 * 60));
        const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));

        return {
            hours,
            minutes,
            totalMilliseconds: timeDiff
        };
    }

    /**
     * Format the cooldown time into a human-readable string
     */
    formatCooldownTime(cooldown) {
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
    /**
     * Initialize the manager and set up necessary elements and listeners
     */
    async initialize() {
        try {
            await ApiService.initialize();
            // Initialize DOM elements
            this.initializeElements();

            // Set up event listeners
            this.setupEventListeners();

            await this.performCleanupAndUpdate();

            // Start periodic status checks
            setInterval(() => this.updateTokenStatus(), 60000); // Check every minute

            console.log('ApiKeyManager initialized successfully');
        } catch (error) {
            console.error('Initialization failed:', error);
            this.showError('Failed to initialize API key management');
        }
    }

    /**
     * Perform token cleanup and status update in a single operation
     * This ensures we always have fresh data after cleanup
     */
    async performCleanupAndUpdate() {
        try {
            // Prima esegui la pulizia dei token
            await this.cleanupExpiredTokens();

            // Poi aggiorna lo stato del token
            await this.updateTokenStatus();
        } catch (error) {
            console.error('Cleanup and update failed:', error);
        }
    }

    /**
     * Clean up expired tokens by calling the backend endpoint
     */
    async cleanupExpiredTokens() {
        try {
            // Chiama l'endpoint di pulizia
            const response = await ApiService.safeFetch(this.config.endpoints.cleanup, {
                method: 'POST'
            });

            // Aggiorna il timestamp dell'ultimo controllo
            this.lastCleanupCheck = new Date();

            if (response.error) {
                console.warn('Token cleanup warning:', response.error);
                return;
            }

            // Se ci sono token scaduti che sono stati puliti, mostra una notifica
            if (response.cleaned_tokens > 0) {
                this.showInfo(`${response.cleaned_tokens} expired tokens have been cleaned up`);
            }

        } catch (error) {
            console.error('Token cleanup failed:', error);
            // Non mostriamo l'errore all'utente poiché questa è un'operazione in background
        }
    }

    /**
     * Initialize DOM elements with error checking
     */
    initializeElements() {
        const elements = {
            apiKeyInput: document.querySelector('#apiKey'),
            toggleButton: document.querySelector('#toggleApiKey'),
            copyButton: document.querySelector('#copyApiKey'),
            regenerateButton: document.querySelector('#regenerateApiKey'),
            tokenStatus: document.querySelector('#tokenStatus'),
            alertContainer: document.querySelector('#alertContainer'),
            persistentAlertContainer: document.querySelector('#persistentAlertContainer') // Nuovo elemento
        };

        // Validate all required elements exist
        for (const [key, element] of Object.entries(elements)) {
            if (!element) {
                throw new Error(`Required element not found: ${key}`);
            }
        }
        // Crea il contenitore per gli avvisi permanenti se non esiste
        if (!elements.persistentAlertContainer) {
            elements.persistentAlertContainer = document.createElement('div');
            elements.persistentAlertContainer.id = 'persistentAlertContainer';
            elements.alertContainer.parentNode.insertBefore(
                elements.persistentAlertContainer,
                elements.alertContainer
            );
        }

        // Validate all required elements exist
        for (const [key, element] of Object.entries(elements)) {
            if (!element) {
                throw new Error(`Required element not found: ${key}`);
            }
        }
        this.elements = elements;

        // Set initial button states
        this.elements.toggleButton.disabled = true;
        this.elements.copyButton.disabled = true;
    }
    /**
     * Mostra un avviso permanente con un ID univoco
     */
    showPersistentAlert(message, type, id) {
        // Rimuovi l'avviso esistente con lo stesso ID se presente
        this.removePersistentAlert(id);

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} fade show`;
        alertDiv.setAttribute('role', 'alert');
        alertDiv.setAttribute('data-alert-id', id);

        const messageText = document.createTextNode(message);
        alertDiv.appendChild(messageText);

        this.elements.persistentAlertContainer.appendChild(alertDiv);
        this.state.persistentAlerts.add(id);
    }
    /**
     * Rimuove un avviso permanente specifico
     */
    removePersistentAlert(id) {
        const existingAlert = this.elements.persistentAlertContainer.querySelector(`[data-alert-id="${id}"]`);
        if (existingAlert) {
            existingAlert.remove();
            this.state.persistentAlerts.delete(id);
        }
    }
    /**
     * Set up event listeners with proper cleanup
     */
    setupEventListeners() {
        this.elements.toggleButton.addEventListener('click', this.handleToggleDisplay);
        this.elements.copyButton.addEventListener('click', this.handleCopy);
        this.elements.regenerateButton.addEventListener('click', this.handleTokenGeneration);

        // Auto-hide on tab change or window blur
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.hideApiKey();
            }
        });
    }

    /**
     * Update token status and UI elements
     */
    async updateTokenStatus() {
        try {
            const data = await ApiService.safeFetch(this.config.endpoints.status, {
                method: 'GET'
            });

            // Se il token è scaduto, mostra un avviso permanente
            if (data.token_status === 'expired') {
                this.showPersistentAlert(
                    'Your token has expired. Please generate a new one.',
                    'warning',
                    'token-expired'
                );
                this.setNoTokenState();
                return;
            }

            // Update UI based on token status
            if (data.has_active_token && data.token_info) {
                this.updateUIWithToken(data.token_info);
            } else {
                this.setNoTokenState();
            }

            // Update regenerate button state
            this.elements.regenerateButton.disabled = !data.can_generate;

            if (!data.can_generate && data.next_eligible_time) {
                const nextEligible = new Date(data.next_eligible_time);
                const waitTime = this.formatTimeRemaining(nextEligible.getTime() - Date.now());
                this.showPersistentAlert(
                    this.config.messages.waitMessage.replace('{time}', waitTime),
                    'info',
                    'cooldown-timer'
                );
            }

        } catch (error) {
            console.error('Status update failed:', error);
            this.showError('Failed to update token status');
        }
    }

    /**
     * Handle token generation with cooldown enforcement
     */
    async handleTokenGeneration() {
        if (this.state.isLoading) return;

        try {
            this.state.isLoading = true;
            this.elements.regenerateButton.disabled = true;
            this.showInfo('Generating new API token...');

            const data = await ApiService.safeFetch(this.config.endpoints.token, {
                method: 'POST'
            });

            if (data.error) {
                throw new Error(data.error);
            }

            if (!data.access_token) {
                throw new Error('Invalid token response');
            }

            // Ensure we have proper date handling for the new token
            const tokenData = {
                access_token: data.access_token,
                created_at: data.token_created_at || data.created_at,
                expires_at: data.expires_at
            };

            this.updateUIWithToken(tokenData);
            this.showSuccess(this.config.messages.tokenGenerated);

            // If next token request time is provided, store it
            if (data.next_token_request) {
                localStorage.setItem('next_token_request', data.next_token_request);
                this.startWaitTimeUpdater(); // Start the wait time updater
            }

        } catch (error) {
            console.error('Token generation failed:', error);
            if (error.message.includes('Daily limit')) {
                this.showError(this.config.messages.dailyLimitReached);
            } else {
                this.showError(error.message);
            }
            this.setNoTokenState();
        } finally {
            this.state.isLoading = false;
            await this.updateTokenStatus(); // This will update the button state correctly
        }
    }


    /**
     * Initialize wait time updater to show countdown until next token generation
     */
    /**
    * Start wait time updater with proper cooldown handling
    */
    startWaitTimeUpdater() {
        // Clear any existing interval
        this.stopWaitTimeUpdater();

        const nextTokenTime = localStorage.getItem('next_token_request');
        if (!nextTokenTime) return;

        // Update immediately
        this.updateWaitTimeMessage(nextTokenTime);

        // Set up interval to update the wait time message
        this.state.waitTimeInterval = setInterval(() => {
            this.updateWaitTimeMessage(nextTokenTime);
        }, 60000); // Update every minute
    }

    /**
     * Stop the wait time updater interval
     */
    stopWaitTimeUpdater() {
        if (this.state.waitTimeInterval) {
            clearInterval(this.state.waitTimeInterval);
            this.state.waitTimeInterval = null;
        }
    }

    /**
     * Update the wait time message based on next eligible time
     */
    updateWaitTimeMessage(nextTokenTime) {
        const cooldown = this.calculateRemainingCooldown(nextTokenTime);

        if (!cooldown) {
            // Cooldown period has expired
            this.elements.regenerateButton.disabled = false;
            this.removePersistentAlert('cooldown-timer');
            this.elements.alertContainer.querySelectorAll('.alert-info').forEach(alert => alert.remove());
            this.stopWaitTimeUpdater();
            return;
        }

        // Show remaining cooldown time
        const formattedTime = this.formatCooldownTime(cooldown);
        this.showPersistentAlert(
            this.config.messages.waitMessage.replace('{time}', formattedTime),
            'info',
            'cooldown-timer'
        );
        this.showInfo(this.config.messages.waitMessage.replace('{time}', formattedTime));

        // If less than a minute remains, update more frequently
        if (cooldown.totalMilliseconds < 60000) {
            this.stopWaitTimeUpdater();
            this.state.waitTimeInterval = setInterval(() => {
                this.updateWaitTimeMessage(nextTokenTime);
            }, 1000); // Update every second for the final countdown
        }
    }

    /**
     * Format a date string into a localized format
     * Handles both ISO strings and timestamp numbers
     */
    formatDate(dateString) {
        try {
            const date = new Date(dateString);

            // Check if the date is valid
            if (isNaN(date.getTime())) {
                throw new Error('Invalid date');
            }

            // Format date and time according to user's locale
            const dateFormatted = date.toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });

            const timeFormatted = date.toLocaleTimeString(undefined, {
                hour: '2-digit',
                minute: '2-digit'
            });

            return { dateFormatted, timeFormatted };
        } catch (error) {
            console.error('Date formatting error:', error);
            return {
                dateFormatted: 'Unknown date',
                timeFormatted: 'Unknown time'
            };
        }
    }

    /**
     * Update UI with token information
     */
    updateUIWithToken(tokenInfo) {
        if (!tokenInfo || !tokenInfo.access_token) {
            this.setNoTokenState();
            return;
        }

        this.elements.apiKeyInput.value = tokenInfo.access_token;
        this.elements.apiKeyInput.classList.remove('text-muted');
        this.elements.toggleButton.disabled = false;
        this.elements.copyButton.disabled = false;

        // Handle the created_at timestamp
        const createdAt = tokenInfo.created_at || tokenInfo.token_created_at;
        const { dateFormatted, timeFormatted } = this.formatDate(createdAt);

        // Mostra la data di creazione come avviso permanente
        this.showPersistentAlert(
            this.config.messages.tokenCreation
                .replace('{date}', dateFormatted)
                .replace('{time}', timeFormatted),
            'info',
            'token-creation'
        );

        this.elements.tokenStatus.textContent = this.config.messages.tokenCreation
            .replace('{date}', dateFormatted)
            .replace('{time}', timeFormatted);

        this.state.tokenInfo = tokenInfo;

        // If we have an expiration date, show it
        if (tokenInfo.expires_at) {
            const expiryDate = new Date(tokenInfo.expires_at);
            const now = new Date();
            const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));

            if (daysLeft > 0) {
                this.showInfo(this.config.messages.tokenExpiring.replace('{days}', daysLeft));
                this.showPersistentAlert(
                    this.config.messages.tokenExpiring.replace('{days}', daysLeft),
                    'warning',
                    'token-expiry'
                );
            }
        }
    }

    /**
     * Set UI state for no token
     */
    setNoTokenState() {
        this.elements.apiKeyInput.value = this.config.messages.noToken;
        this.elements.apiKeyInput.classList.add('text-muted');
        this.elements.toggleButton.disabled = true;
        this.elements.copyButton.disabled = true;
        this.state.tokenInfo = null;

        // Rimuovi tutti gli avvisi permanenti relativi al token
        this.removePersistentAlert('token-creation');
        this.removePersistentAlert('token-expiry');
    }

    /**
     * Handle secure copying of API key
     */
    async handleCopy() {
        try {
            const key = this.elements.apiKeyInput.value;

            if (key === this.config.messages.noToken) {
                this.showError('No API key available to copy');
                return;
            }

            await navigator.clipboard.writeText(key);
            this.showSuccess('API key copied to clipboard');

            setTimeout(() => {
                const alert = this.elements.alertContainer.querySelector('.alert-success');
                alert?.remove();
            }, this.config.copyTimeout);

        } catch (error) {
            console.error('Copy failed:', error);
            this.showError('Failed to copy API key');
        }
    }

    /**
     * Handle secure token visibility toggle
     */
    handleToggleDisplay() {
        if (this.elements.apiKeyInput.value === this.config.messages.noToken) {
            return;
        }

        if (this.elements.apiKeyInput.type === 'password') {
            this.showApiKey();
            setTimeout(() => this.hideApiKey(), this.config.displayTimeout);
        } else {
            this.hideApiKey();
        }
    }

    /**
     * Show API key
     */
    showApiKey() {
        this.elements.apiKeyInput.type = 'text';
        this.elements.toggleButton.querySelector('i').className = 'fas fa-eye-slash';
        this.state.isVisible = true;
    }

    /**
     * Hide API key
     */
    hideApiKey() {
        this.elements.apiKeyInput.type = 'password';
        this.elements.toggleButton.querySelector('i').className = 'fas fa-eye';
        this.state.isVisible = false;
    }

    /**
     * Format time remaining in a human-readable format
     */
    formatTimeRemaining(milliseconds) {
        const hours = Math.floor(milliseconds / (1000 * 60 * 60));
        const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));

        const parts = [];
        if (hours > 0) {
            parts.push(`${hours} ${hours === 1 ? 'hour' : 'hours'}`);
        }
        if (minutes > 0) {
            parts.push(`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`);
        }

        return parts.join(' and ') || 'less than a minute';
    }

    /**
     * Alert display methods with XSS prevention
     */
    showAlert(message, type) {
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

        // Remove existing alerts
        this.elements.alertContainer.querySelectorAll('.alert').forEach(alert => alert.remove());
        this.elements.alertContainer.appendChild(alertDiv);
    }

    showError(message) { this.showAlert(message, 'danger'); }
    showSuccess(message) { this.showAlert(message, 'success'); }
    showInfo(message) { this.showAlert(message, 'info'); }
    showWarning(message) { this.showAlert(message, 'warning'); }
}