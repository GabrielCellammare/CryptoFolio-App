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
            container: null
        };

        // Configuration for security and display
        this.config = {
            displayTimeout: 30000, // Auto-hide after 30 seconds
            copyTimeout: 3000,     // Copy message display duration
            maxDisplayAttempts: 3,// Maximum consecutive display attempts
            tokenEndpoint: '/api/token' // Endpoint for token generation
        };

        // State management
        this.state = {
            isVisible: false,
            displayAttempts: 0,
            lastToggleTime: 0,
            currentToken: null
        };

        // Bind methods to preserve context
        this.initializeElements = this.initializeElements.bind(this);
        this.setupEventListeners = this.setupEventListeners.bind(this);
        this.handleToggleDisplay = this.handleToggleDisplay.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.updateToggleButton = this.updateToggleButton.bind(this);
    }

    /**
     * Initialize the manager and set up necessary elements and listeners
     */
    async initialize() {
        try {
            await this.apiService.initialize();
            this.initializeElements();
            this.setupEventListeners();
            await this.validateCurrentKey();
            console.log('API Key Manager initialized successfully');
        } catch (error) {
            console.error('Failed to initialize API Key Manager:', error);
            this.showError('Failed to initialize API key management');
        }
    }

    /**
     * Initialize references to DOM elements
     */
    initializeElements() {
        this.elements.apiKeyInput = document.getElementById('apiKey');
        this.elements.toggleButton = document.getElementById('toggleApiKey');
        this.elements.copyButton = document.getElementById('copyApiKey');
        this.elements.container = this.elements.apiKeyInput?.closest('.card-body');

        if (!this.elements.apiKeyInput || !this.elements.toggleButton || !this.elements.copyButton) {
            throw new Error('Required API key elements not found in DOM');
        }
    }

    /**
     * Set up event listeners for key management interactions
     */
    setupEventListeners() {
        // Make sure we're using the correct button ID
        this.elements.regenerateButton = document.getElementById('regenerateApiKey');

        // Add event listener for regenerate button
        this.elements.regenerateButton?.addEventListener('click', () => this.handleTokenGeneration());

        // Other existing event listeners...
        this.elements.toggleButton.addEventListener('click', this.handleToggleDisplay);
        this.elements.copyButton.addEventListener('click', this.handleCopy);

        // Auto-hide on document click outside
        document.addEventListener('click', (event) => {
            if (this.state.isVisible &&
                !event.target.closest('.input-group') &&
                this.elements.apiKeyInput.type === 'text') {
                this.hideApiKey();
            }
        });

        // Reset visibility on tab change
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
        try {
            // Show loading state
            this.elements.regenerateButton.disabled = true;
            this.showInfo('Generating new API token...');

            // Use ApiService's safeFetch for secure communication
            const response = await this.apiService.safeFetch(this.config.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response) {
                throw new Error('No response received from server');
            }

            if (!response.access_token) {
                throw new Error('Token missing from server response');
            }


            // Update UI with new token
            this.state.currentToken = response.access_token;
            this.elements.apiKeyInput.value = response.access_token;
            this.elements.apiKeyInput.type = 'password';

            // Enable controls
            this.elements.toggleButton.disabled = false;
            this.elements.copyButton.disabled = false;

            this.showSuccess('New API token generated successfully');

            // Store token generation timestamp for expiration tracking
            localStorage.setItem('token_generated_at', Date.now().toString());

        } catch (error) {
            console.error('Token generation failed:', error);
            this.showError(`Failed to generate new API token: ${error.message}`);
        } finally {
            this.elements.regenerateButton.disabled = false;
        }
    }

    /**
     * Validate the current API key format and presence
     */
    async validateCurrentKey() {
        const currentKey = this.elements.apiKeyInput.value;

        if (currentKey === 'No API key generated') {
            this.elements.apiKeyInput.classList.add('text-muted');
            this.elements.toggleButton.disabled = true;
            this.elements.copyButton.disabled = true;
            return;
        }

        // Validate token expiration
        const generatedAt = localStorage.getItem('token_generated_at');
        if (generatedAt) {
            const expirationTime = parseInt(generatedAt) + (60 * 60 * 1000); // 1 hour
            if (Date.now() > expirationTime) {
                this.showWarning('Your API token has expired. Please generate a new one.');
                return;
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