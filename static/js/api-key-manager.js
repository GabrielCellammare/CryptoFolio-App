/**
 * ApiKeyManager.js
 * Service for managing the display, security, and interactions of API keys
 * Integrates with the existing API service infrastructure
 */
import { ApiService } from './api-service.js';

export default class ApiKeyManager {
    constructor() {

        this.apiService = ApiService;

        // UI element references
        this.elements = {
            apiKeyInput: null,
            toggleButton: null,
            copyButton: null,
            container: null,
            regenerateButton: null,
            tokenStatus: null,
            isVisible: false,
            displayAttempts: 0,
            lastToggleTime: 0,
            currentToken: null,
            nextTokenTime: null,
            isGenerating: false
        };

        // Configuration for security and display
        this.config = {
            displayTimeout: 30000,
            copyTimeout: 3000,
            maxDisplayAttempts: 3,
            tokenEndpoint: '/api/token',
            warningThreshold: 86400000 * 3, // 3 days in milliseconds
            TOKEN_CHECK_INTERVAL: 60000,
            TOKEN_REFRESH_THRESHOLD: 300000,
            messages: {
                TOKEN_EXPIRING: 'Il tuo token scadrà tra {days} giorni',
                TOKEN_GENERATED: 'Nuovo token generato con successo. Valido per 7 giorni.',
                WAIT_MESSAGE: 'Potrai generare un nuovo token tra {time}',
                DAILY_LIMIT: 'Hai raggiunto il limite di 2 token per oggi'
            }
        };

        // State management
        this.state = {
            isVisible: false,
            displayAttempts: 0,
            lastToggleTime: 0,
            currentToken: null
        };
        // Bind methods to preserve context
        this.handleToggleDisplay = this.handleToggleDisplay.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.handleTokenGeneration = this.handleTokenGeneration.bind(this);
        this.updateTokenStatus = this.updateTokenStatus.bind(this);
        this.showApiKey = this.showApiKey.bind(this);
        this.hideApiKey = this.hideApiKey.bind(this);
        this.showAlert = this.showAlert.bind(this);
        this.showError = this.showError.bind(this);
        this.showSuccess = this.showSuccess.bind(this);
        this.showInfo = this.showInfo.bind(this);
        this.showWarning = this.showWarning.bind(this);

    }

    async updateTokenStatus() {
        const expiryStr = localStorage.getItem(this.apiService.config.TOKEN_EXPIRY_KEY);
        const nextRequestStr = localStorage.getItem(this.apiService.config.NEXT_TOKEN_REQUEST_KEY);

        if (!expiryStr) {
            this.showWarning('Nessun token attivo. Generane uno nuovo.');
            return;
        }

        const expiry = new Date(expiryStr);
        const now = new Date();
        const timeLeft = expiry.getTime() - now.getTime();
        const daysLeft = Math.ceil(timeLeft / (1000 * 60 * 60 * 24));

        // Mostra avviso se il token sta per scadere
        if (timeLeft < this.config.warningThreshold) {
            this.showWarning(this.config.messages.TOKEN_EXPIRING.replace('{days}', daysLeft));
        }

        // Mostra tempo di attesa per il prossimo token se applicabile
        if (nextRequestStr) {
            const nextRequest = new Date(nextRequestStr);
            if (now < nextRequest) {
                const waitTime = this.formatWaitTime(nextRequest.getTime() - now.getTime());
                this.showInfo(this.config.messages.WAIT_MESSAGE.replace('{time}', waitTime));
            }
        }
    }

    startTokenCheck() {
        // Clear any existing interval
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
        }
        this.tokenCheckInterval = setInterval(() => this.checkTokenStatus(), this.config.TOKEN_CHECK_INTERVAL);
    }
    // Add destroy method for cleanup
    destroy() {
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
            this.tokenCheckInterval = null;
        }
    }

    async checkTokenStatus() {
        const tokenStatus = await this.apiService.checkTokenStatus();

        if (tokenStatus.needsRefresh) {
            try {
                await this.handleTokenGeneration();
            } catch (error) {
                this.showError(`Token refresh failed: ${error.message}`);
            }
        }
    }

    /**
     * Initialize the manager and set up necessary elements and listeners
     */
    async initialize() {
        try {
            await this.apiService.initialize();
            this.initializeElements();
            this.setupEventListeners();
            const token = localStorage.getItem(this.apiService.config.TOKEN_STORAGE_KEY);
            if (token) {
                this.elements.apiKeyInput.value = token;
                this.elements.apiKeyInput.classList.remove('text-muted');
            }
            await this.updateRegenerateButtonState();
            this.startTokenCheck();
            await this.validateCurrentKey();

            // Carica il token esistente dal localStorage

            console.log('API Key Manager initialized successfully');
        } catch (error) {
            console.error('Failed to initialize API Key Manager:', error);
            this.showError('Failed to initialize API key management');
        }
    }

    async updateRegenerateButtonState() {
        const nextRequestStr = localStorage.getItem(this.apiService.config.NEXT_TOKEN_REQUEST_KEY);
        if (nextRequestStr) {
            const nextRequest = new Date(nextRequestStr);
            const now = new Date();

            if (now < nextRequest) {
                this.elements.regenerateButton.disabled = true;
                this.state.nextTokenTime = nextRequest;
                this.updateNextTokenTimer();
            } else {
                this.elements.regenerateButton.disabled = false;
                this.state.nextTokenTime = null;
            }
        }
    }


    startNextTokenTimer() {
        // Aggiorna il timer ogni secondo
        setInterval(() => this.updateNextTokenTimer(), 1000);
    }

    updateNextTokenTimer() {
        if (this.state.nextTokenTime) {
            const now = new Date();
            const timeLeft = this.state.nextTokenTime.getTime() - now.getTime();

            if (timeLeft > 0) {
                const waitTime = this.formatWaitTime(timeLeft);
                this.showInfo(this.config.messages.WAIT_MESSAGE.replace('{time}', waitTime));
            } else {
                this.elements.regenerateButton.disabled = false;
                this.state.nextTokenTime = null;
                const alerts = this.elements.container.querySelectorAll('.alert-info');
                alerts.forEach(alert => alert.remove());
            }
        }
    }

    /**
     * Initialize references to DOM elements
     */
    initializeElements() {
        // Initialize all required DOM elements
        const elements = {
            apiKeyInput: document.getElementById('apiKey'),
            toggleButton: document.getElementById('toggleApiKey'),
            copyButton: document.getElementById('copyApiKey'),
            regenerateButton: document.getElementById('regenerateApiKey'),
            tokenStatus: document.getElementById('tokenStatus')
        };
        // Check if all elements exist
        const missingElements = Object.entries(elements)
            .filter(([, element]) => !element)
            .map(([key]) => key);

        if (missingElements.length > 0) {
            throw new Error(`Missing required elements: ${missingElements.join(', ')}`);
        }

        this.elements = elements;
        this.elements.container = this.elements.apiKeyInput.closest('.card-body');
    }

    /**
     * Set up event listeners for key management interactions
     */
    setupEventListeners() {

        // Set up click handlers with bound context
        this.elements.toggleButton.addEventListener('click', this.handleToggleDisplay);
        this.elements.copyButton.addEventListener('click', this.handleCopy);
        this.elements.regenerateButton.addEventListener('click', this.handleTokenGeneration);

        // Document-level click handler for auto-hide
        document.addEventListener('click', (event) => {
            if (this.state.isVisible &&
                !event.target.closest('.input-group') &&
                this.elements.apiKeyInput.type === 'text') {
                this.hideApiKey();
            }
        });

        // Visibility change handler
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && this.state.isVisible) {
                this.hideApiKey();
            }
        });
    }
    /**
     * Handle API token generation using SafeFetch
     */
    async handleTokenGeneration() {

        if (this.state.isGenerating) return;

        try {
            this.state.isGenerating = true;
            this.elements.regenerateButton.disabled = true;
            this.showInfo('Generating new API token...');

            const success = await this.apiService.handleTokenGeneration();

            if (success) {
                // Get the token from localStorage
                const token = localStorage.getItem(this.apiService.config.TOKEN_STORAGE_KEY);
                const nextRequestStr = localStorage.getItem(this.apiService.config.NEXT_TOKEN_REQUEST_KEY);

                // Update the input field with the new token
                if (token) {
                    this.elements.apiKeyInput.value = token;
                    this.elements.apiKeyInput.classList.remove('text-muted');
                    this.showSuccess(this.config.messages.TOKEN_GENERATED);
                    if (nextRequestStr) {
                        this.state.nextTokenTime = new Date(nextRequestStr);
                    }
                } else {
                    this.showError('Token generated but not found in storage');
                    this.elements.apiKeyInput.value = 'No API key generated';
                    this.elements.apiKeyInput.classList.add('text-muted');
                }

                await this.updateTokenStatus();

                // Enable controls
                this.elements.toggleButton.disabled = false;
                this.elements.copyButton.disabled = false;
            }

        } catch (error) {
            console.error('Token generation failed:', error);
            this.showError(`Failed to generate new API token: ${error.message}`);
            this.elements.apiKeyInput.value = 'No API key generated';
            this.elements.apiKeyInput.classList.add('text-muted');
        } finally {
            this.state.isGenerating = false;
            await this.updateRegenerateButtonState();
        }
    }

    formatWaitTime(milliseconds) {
        const hours = Math.floor(milliseconds / (1000 * 60 * 60));
        const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));

        if (hours > 0) {
            return `${hours} ore e ${minutes} minuti`;
        }
        return `${minutes} minuti`;
    }

    /**
     * Validate the current API key format and presence
     */
    async validateCurrentKey() {
        const tokenStatus = await this.apiService.checkTokenStatus();

        if (tokenStatus.needsRefresh) {
            this.elements.apiKeyInput.classList.add('text-muted');
            this.elements.toggleButton.disabled = true;
            this.elements.copyButton.disabled = true;

            // Show appropriate message
            if (tokenStatus.error) {
                this.showWarning(tokenStatus.error);
            } else {
                this.showWarning('Your API token needs to be regenerated');
            }
            return;
        }

        const expiryStr = localStorage.getItem(this.apiService.config.TOKEN_EXPIRY_KEY);
        if (expiryStr) {
            const expiry = new Date(expiryStr);
            const now = new Date();
            const timeLeft = expiry.getTime() - now.getTime();

            if (timeLeft < this.config.warningThreshold) {
                this.showWarning(`Token will expire in ${Math.ceil(timeLeft / (1000 * 60 * 60 * 24))} days`);
            }
        }

        this.elements.toggleButton.disabled = false;
        this.elements.copyButton.disabled = false;
    }

    /**
     * Handle toggling API key visibility
     */
    async handleToggleDisplay() {
        const now = Date.now();

        // Rate limiting for toggle actions
        if (now - this.state.lastToggleTime < 1000) {
            return; // Prevent rapid toggling
        }

        this.state.lastToggleTime = now;

        if (this.elements.apiKeyInput.type === 'password') {
            // Show the API key
            if (this.state.displayAttempts >= this.config.maxDisplayAttempts) {
                this.showError('Too many display attempts. Please wait a few minutes.');
                return;
            }

            this.showApiKey();
            this.state.displayAttempts++;

            // Auto-hide after timeout
            setTimeout(() => this.hideApiKey(), this.config.displayTimeout);
        } else {
            this.hideApiKey();
        }
    }

    /**
     * Show an alert message to the user
     */
    showAlert(message, type) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show mt-3" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;

        // Remove existing alerts
        const existingAlerts = this.elements.container.querySelectorAll('.alert');
        existingAlerts.forEach(alert => alert.remove());

        // Add new alert
        this.elements.container.insertAdjacentHTML('beforeend', alertHtml);

        // Auto-remove success and info alerts
        if (type === 'success' || type === 'info') {
            setTimeout(() => {
                const alert = this.elements.container.querySelector(`.alert-${type}`);
                if (alert) alert.remove();
            }, this.config.copyTimeout);
        }
    }

    // Helper methods for showing different types of alerts
    showError(message) { this.showAlert(message, 'danger'); }
    showSuccess(message) { this.showAlert(message, 'success'); }
    showInfo(message) { this.showAlert(message, 'info'); }
    showWarning(message) { this.showAlert(message, 'warning'); }

    /**
     * Show the API key
     */
    showApiKey() {
        this.elements.apiKeyInput.type = 'text';
        this.updateToggleButton(true);
        this.state.isVisible = true;
    }

    /**
     * Hide the API key
     */
    hideApiKey() {
        this.elements.apiKeyInput.type = 'password';
        this.updateToggleButton(false);
        this.state.isVisible = false;
    }

    /**
     * Update the toggle button icon and state
     */
    updateToggleButton(isVisible) {
        const icon = this.elements.toggleButton.querySelector('i');
        icon.className = isVisible ? 'fas fa-eye-slash' : 'fas fa-eye';
    }

    /**
     * Handle copying the API key
     */
    async handleCopy() {
        try {
            const key = this.elements.apiKeyInput.value;

            if (key === 'No API key generated') {
                this.showError('No API key available to copy');
                return;
            }

            await navigator.clipboard.writeText(key);
            this.showSuccess('API key copied to clipboard');

            // Automatically hide success message
            setTimeout(() => {
                const alert = this.elements.container.querySelector('.alert-success');
                if (alert) {
                    alert.remove();
                }
            }, this.config.copyTimeout);

        } catch (error) {
            console.error('Failed to copy API key:', error);
            this.showError('Failed to copy API key');
        }
    }

    /**
     * Show an error message to the user
     */
    showError(message) {
        this.showAlert(message, 'danger');
    }

    /**
     * Show a success message to the user
     */
    showSuccess(message) {
        this.showAlert(message, 'success');
    }

    /**
     * Generic alert display helper
     */
    showAlert(message, type) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show mt-3" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;

        // Remove any existing alerts
        const existingAlerts = this.elements.container.querySelectorAll('.alert');
        existingAlerts.forEach(alert => alert.remove());

        // Add new alert
        this.elements.container.insertAdjacentHTML('beforeend', alertHtml);
    }
}