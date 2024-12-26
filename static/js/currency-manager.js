import { ApiService } from './api-service.js';

// currency-manager.js
export default class CurrencyManager {
    constructor() {
        this.currencySelect = document.getElementById('currencySelect');
        this.initialize();
    }

    async initialize() {
        try {
            // Get current currency using the class method
            const currentCurrency = await this.getCurrentCurrency();
            this.currencySelect.value = currentCurrency;

            // Import the updatePriceLabels function from utils.js
            const { updatePriceLabels } = await import('./utils.js');

            // Update initial price labels
            updatePriceLabels(currentCurrency);

            // Add event listener for currency changes
            this.currencySelect.addEventListener('change', async (e) => {
                const loadingOverlay = document.querySelector('.loading-overlay');
                loadingOverlay.style.display = 'flex';

                try {
                    const newCurrency = e.target.value;
                    await this.updateCurrency(newCurrency);

                    // Update price labels before reload
                    updatePriceLabels(newCurrency);

                    // Force reload to get fresh converted prices
                    window.location.reload();
                } catch (error) {
                    console.error('Currency update error:', error);
                    this.showError('Currency update failed. Please try again.');
                    loadingOverlay.style.display = 'none';
                }
            });
        } catch (error) {
            console.error('Initialization error:', error);
            this.showError('Failed to initialize currency manager');
        }
    }

    async getCurrentCurrency() {
        try {
            const response = await ApiService.getCurrentCurrency();
            return response.currency || 'USD';
        } catch (error) {
            console.error('Error fetching currency:', error);
            return 'USD'; // Default fallback
        }
    }

    async updateCurrency(currency) {
        try {
            // Use ApiService for the secure PUT request
            await ApiService.safeFetch('/api/preferences/currency', {
                method: 'PUT',
                body: JSON.stringify({ currency })
            });

            // Update crypto select prices if available
            const cryptoSelect = document.getElementById('crypto-select');
            if (cryptoSelect) {
                await this.updateCryptoSelectPrices(currency);
            }
        } catch (error) {
            console.error('Currency update error:', error);
            throw error; // Propagate the error for handling in the caller
        }
    }

    async updateCryptoSelectPrices(currency) {
        try {
            const data = await ApiService.fetchCryptocurrencies();

            if (data.status === 'success' && data.data) {
                const select2Element = $('#crypto-select');
                const { formatCurrency } = await import('./utils.js');

                // Update prices in select2 options
                const updatedOptions = data.data.map(crypto => ({
                    id: crypto.id,
                    text: `${crypto.name} (${crypto.symbol}) - ${formatCurrency(crypto.current_price, currency)}`
                }));

                select2Element.empty();
                select2Element.select2({
                    data: updatedOptions,
                    placeholder: 'Select a cryptocurrency'
                });
            }
        } catch (error) {
            console.error('Error updating crypto prices:', error);
            this.showError('Failed to update cryptocurrency prices');
        }
    }

    showError(message) {
        const flashMessages = document.getElementById('flashMessages');
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show';
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        flashMessages.appendChild(alert);

        // Remove the alert after 5 seconds
        setTimeout(() => {
            alert.remove();
        }, 5000);
    }

    async updateDisplayValues(newCurrency) {
        const { updatePriceLabels } = await import('./utils.js');
        updatePriceLabels(newCurrency);

        // Update portfolio value
        const portfolioValueElement = document.getElementById('formatted-portfolio-value');
        if (portfolioValueElement) {
            const value = parseFloat(portfolioValueElement.textContent.replace(/[^0-9.-]+/g, ''));
            if (!isNaN(value)) {
                portfolioValueElement.textContent = formatCurrency(value, newCurrency);
            }
        }
    }
}