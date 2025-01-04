/**
 * CurrencyManager handles currency-related operations and UI updates
 * Security considerations:
 * - Input validation and sanitization
 * - Error handling with safe error messages
 * - XSS prevention
 * - API error handling
 * - Rate limiting for currency updates
 */

import { ApiService } from './api-service.js';

export default class CurrencyManager {
    // Private fields using # prefix for better encapsulation
    #currencySelect;
    #lastUpdateTimestamp = 0;
    #updateInProgress = false;
    #MIN_UPDATE_INTERVAL = 2000; // Rate limiting: minimum 2 seconds between updates

    /**
     * Initialize the CurrencyManager with required DOM elements
     * @throws {Error} If required DOM elements are not found
     */
    constructor() {
        // Validate DOM elements exist before proceeding
        const currencySelect = document.getElementById('currencySelect');
        if (!currencySelect) {
            throw new Error('Required currency select element not found');
        }
        this.#currencySelect = currencySelect;

        this.#initialize().catch(error => {
            this.#handleError('Initialization failed', error);
        });
    }

    /**
     * Initialize currency manager and set up event listeners
     * @private
     */
    async #initialize() {
        try {
            const currentCurrency = await this.#getCurrentCurrency();

            // Sanitize currency value before setting
            if (!this.#isValidCurrency(currentCurrency)) {
                throw new Error('Invalid currency value received');
            }

            this.#currencySelect.value = currentCurrency;

            const { updatePriceLabels } = await import('./utils.js');
            updatePriceLabels(currentCurrency);

            this.#setupEventListeners();
        } catch (error) {
            this.#handleError('Initialization error', error);
        }
    }

    /**
     * Set up event listeners with proper error handling and rate limiting
     * @private
     */
    #setupEventListeners() {
        this.#currencySelect.addEventListener('change', async (e) => {
            if (!this.#canUpdate()) {
                this.#showUserMessage('Please wait before updating currency again', 'warning');
                return;
            }

            const loadingOverlay = document.querySelector('.loading-overlay');
            if (!loadingOverlay) return;

            try {
                this.#updateInProgress = true;
                loadingOverlay.style.display = 'flex';

                const newCurrency = e.target.value;
                if (!this.#isValidCurrency(newCurrency)) {
                    throw new Error('Invalid currency selection');
                }

                await this.#updateCurrency(newCurrency);

                // Use session storage to maintain state during reload
                sessionStorage.setItem('pendingCurrencyUpdate', 'true');
                window.location.reload();
            } catch (error) {
                this.#handleError('Currency update failed', error);
            } finally {
                this.#updateInProgress = false;
                loadingOverlay.style.display = 'none';
            }
        });
    }

    /**
     * Rate limiting check for currency updates
     * @private
     * @returns {boolean} Whether an update is allowed
     */
    #canUpdate() {
        const now = Date.now();
        if (this.#updateInProgress || (now - this.#lastUpdateTimestamp) < this.#MIN_UPDATE_INTERVAL) {
            return false;
        }
        this.#lastUpdateTimestamp = now;
        return true;
    }

    /**
     * Validate currency codes
     * @private
     * @param {string} currency Currency code to validate
     * @returns {boolean} Whether the currency code is valid
     */
    #isValidCurrency(currency) {
        const validCurrencies = ['USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD']; // Add all supported currencies
        return typeof currency === 'string' &&
            currency.length === 3 &&
            validCurrencies.includes(currency.toUpperCase());
    }

    /**
     * Get current currency with error handling
     * @private
     * @returns {Promise<string>} Current currency code
     */
    async #getCurrentCurrency() {
        try {
            const response = await ApiService.getCurrentCurrency();

            if (!response || !response.currency) {
                throw new Error('Invalid response format');
            }

            return this.#isValidCurrency(response.currency) ? response.currency : 'USD';
        } catch (error) {
            this.#handleError('Error fetching currency', error);
            return 'USD';
        }
    }

    /**
     * Update currency settings
     * @private
     * @param {string} currency New currency code
     */
    async #updateCurrency(currency) {
        try {
            await ApiService.safeFetch('/api/preferences/currency', {
                method: 'PUT',
                body: JSON.stringify({ currency })
            });

            await this.#updateCryptoSelectPrices(currency);
        } catch (error) {
            this.#handleError('Currency update error', error);
            throw error;
        }
    }

    /**
     * Update cryptocurrency prices in select element
     * @private
     * @param {string} currency Currency code
     */
    async #updateCryptoSelectPrices(currency) {
        try {
            const data = await ApiService.fetchCryptocurrencies();
            if (!data?.status === 'success' || !Array.isArray(data?.data)) {
                throw new Error('Invalid cryptocurrency data received');
            }

            const select2Element = $('#crypto-select');
            if (!select2Element.length) return;

            const { formatCurrency } = await import('./utils.js');

            const updatedOptions = data.data.map(crypto => ({
                id: this.#sanitizeInput(crypto.id),
                text: this.#sanitizeInput(
                    `${crypto.name} (${crypto.symbol}) - ${formatCurrency(crypto.current_price, currency)}`
                )
            }));

            select2Element.empty();
            select2Element.select2({
                data: updatedOptions,
                placeholder: 'Select a cryptocurrency'
            });
        } catch (error) {
            this.#handleError('Error updating crypto prices', error);
        }
    }

    /**
     * Sanitize user input to prevent XSS
     * @private
     * @param {string} input Input to sanitize
     * @returns {string} Sanitized input
     */
    #sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    /**
     * Handle errors safely without exposing sensitive information
     * @private
     * @param {string} userMessage Message to show to user
     * @param {Error} error Error object
     */
    #handleError(userMessage, error) {
        // Log full error for debugging but don't expose to user
        console.error(`${userMessage}:`, error);

        // Show sanitized message to user
        this.#showUserMessage(userMessage, 'error');
    }

    /**
     * Show message to user safely
     * @private
     * @param {string} message Message to display
     * @param {string} type Message type (error, warning, success)
     */
    #showUserMessage(message, type = 'error') {
        const flashMessages = document.getElementById('flashMessages');
        if (!flashMessages) return;

        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;

        // Sanitize message content
        const sanitizedMessage = this.#sanitizeInput(message);

        alert.innerHTML = `
            ${sanitizedMessage}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        flashMessages.appendChild(alert);

        setTimeout(() => {
            if (alert.parentNode === flashMessages) {
                flashMessages.removeChild(alert);
            }
        }, 5000);
    }
}