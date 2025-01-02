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
                status: '/api/token/status'
            },
            displayTimeout: 30000, // 30 seconds
            copyTimeout: 3000,     // 3 seconds
            messages: {
                tokenExpiring: 'Your token will expire in {days} days',
                tokenGenerated: 'New token generated successfully',
                waitMessage: 'You can generate a new token in {time}',
                tokenCreation: 'Token created on {date} at {time}',
                noToken: 'No token generated'
            }
        };

        // Secure state management
        this.state = {
            isVisible: false,
            isLoading: false,
            tokenInfo: null
        };

        // DOM elements - initialized in initialize()
        this.elements = {
            apiKeyInput: null,
            toggleButton: null,
            copyButton: null,
            regenerateButton: null,
            tokenStatus: null,
            alertContainer: null
        };

        // Bind methods
        this.handleToggleDisplay = this.handleToggleDisplay.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.handleTokenGeneration = this.handleTokenGeneration.bind(this);
        this.updateTokenStatus = this.updateTokenStatus.bind(this);
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

            // Get initial token status
            await this.updateTokenStatus();

            // Start periodic status checks
            setInterval(() => this.updateTokenStatus(), 60000); // Check every minute

            console.log('ApiKeyManager initialized successfully');
        } catch (error) {
            console.error('Initialization failed:', error);
            this.showError('Failed to initialize API key management');
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
            alertContainer: document.querySelector('#alertContainer')
        };

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
                this.showInfo(this.config.messages.waitMessage.replace('{time}', waitTime));
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
            this.showError(error.message);
            this.setNoTokenState();
        } finally {
            this.state.isLoading = false;
            await this.updateTokenStatus(); // This will update the button state correctly
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