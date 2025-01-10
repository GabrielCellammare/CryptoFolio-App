// static/js/utils.js

/**
 * Format currency value with proper symbol and decimal places
 * @param {number} amount - Amount to format
 * @param {string} currency - Currency code (USD or EUR)
 * @returns {string} Formatted currency string
 */


let activeLoadingOperations = 0;
let reloadPending = false;

export function formatCurrency(amount, currency = 'USD') {
    if (typeof amount !== 'number' || isNaN(amount)) {
        console.warn('Invalid amount provided to formatCurrency:', amount);
        amount = 0;
    }

    amount = parseFloat(amount.toFixed(2));

    const currencyConfig = {
        USD: {
            locale: 'en-US',
            currency: 'USD',
            symbol: '$'
        },
        EUR: {
            locale: 'it-IT', // Using German locale for Euro formatting
            currency: 'EUR',
            symbol: '€'
        }
    };

    const config = currencyConfig[currency] || currencyConfig.USD;

    try {
        return new Intl.NumberFormat(config.locale, {
            style: 'currency',
            currency: config.currency,
            minimumFractionDigits: 6,
            maximumFractionDigits: 6
        }).format(amount);
    } catch (error) {
        console.error('Error formatting currency:', error);
        return `${config.symbol}${amount.toFixed(6)}`;
    }
}

export function updatePriceLabels(currency) {
    // Aggiorna le etichette dei prezzi nelle intestazioni della tabella
    const headers = document.querySelectorAll('#portfolioTable th');
    headers.forEach(header => {
        const text = header.textContent;
        if (text.includes('Price') || text.includes('Value') || text.includes('Profit/Loss')) {
            header.textContent = text.replace(/\([^)]*\)/, `(${currency})`);
            if (!text.includes('(')) {
                header.textContent = `${text} (${currency})`;
            }
        }
    });

    // Aggiorna il valore totale del portfolio
    const portfolioValue = document.getElementById('formatted-portfolio-value');
    if (portfolioValue) {
        const value = parseFloat(portfolioValue.textContent.replace(/[^0-9.-]+/g, ''));
        if (!isNaN(value)) {
            portfolioValue.textContent = formatCurrency(value, currency);
        }
    }

    // Aggiorna solo i valori monetari nella tabella, lasciando inalterati amount e date
    document.querySelectorAll('#portfolioTable tbody tr').forEach(row => {
        // Aggiorna purchase price
        const purchasePriceCell = row.children[2];
        if (purchasePriceCell) {
            const displayValue = purchasePriceCell.querySelector('.display-value');
            if (displayValue) {
                const value = parseFloat(displayValue.textContent);
                if (!isNaN(value)) {
                    displayValue.textContent = formatCurrency(value, currency);
                }
            }
        }

        // Aggiorna current price
        const currentPriceCell = row.children[4];
        if (currentPriceCell) {
            const value = parseFloat(currentPriceCell.textContent);
            if (!isNaN(value)) {
                currentPriceCell.textContent = formatCurrency(value, currency);
            }
        }

        // Aggiorna current value
        const currentValueCell = row.children[5];
        if (currentValueCell) {
            const value = parseFloat(currentValueCell.textContent);
            if (!isNaN(value)) {
                currentValueCell.textContent = formatCurrency(value, currency);
            }
        }

        // Aggiorna profit/loss mantenendo la percentuale
        const profitLossCell = row.children[6];
        if (profitLossCell) {
            const text = profitLossCell.textContent;
            const value = parseFloat(text);
            const percentageMatch = text.match(/\((.*?)%\)/);
            const percentage = percentageMatch ? percentageMatch[1] : '';

            if (!isNaN(value)) {
                profitLossCell.textContent = `${formatCurrency(value, currency)} (${percentage}%)`;
            }
        }
    });

    // Aggiorna l'etichetta del campo purchase price nel form
    const purchasePriceLabel = document.querySelector('label[for="purchase-price"]');
    if (purchasePriceLabel) {
        purchasePriceLabel.textContent = `Purchase Price (${currency})`;
    }
}


/**
 * Show error message
 * @param {string} message - Error message to display
 */
export function showError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.getElementById('flashMessages').appendChild(alertDiv);
}

export function showSuccess(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success alert-dismissible fade show enhanced-alert';

    // Creiamo il contenuto del messaggio con icona
    alertDiv.innerHTML = `
        <div class="alert-content">
            <i class="fas fa-check-circle alert-icon"></i>
            <span class="alert-message">${message}</span>
        </div>
    `;

    document.getElementById('flashMessages').appendChild(alertDiv);

    // Rimuovi automaticamente dopo 5 secondi
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }
    }, 5000);
}

export function showLoading() {
    activeLoadingOperations++;
    document.querySelector('.loading-overlay').style.display = 'flex';
}

export function hideLoading() {
    activeLoadingOperations--;
    // Nascondi la loading overlay solo quando tutte le operazioni sono completate
    if (activeLoadingOperations <= 0) {
        activeLoadingOperations = 0;
        if (!reloadPending) {
            document.querySelector('.loading-overlay').style.display = 'none';
        }
    }
}


export function safePageReload() {
    reloadPending = true;
    showLoading();
    // Attendiamo che tutte le operazioni pendenti siano completate
    const checkOperations = () => {
        if (activeLoadingOperations <= 1) { // 1 perché questa è un'operazione attiva
            window.location.reload();
        } else {
            setTimeout(checkOperations, 100);
        }
    };
    checkOperations();
}

import ApiKeyManager from './api-key-manager.js';
document.addEventListener('DOMContentLoaded', () => {
    const apiKeyManager = new ApiKeyManager();
    apiKeyManager.initialize().catch(error => {
        console.error('Failed to initialize API Key Manager:', error);
    });
});
// Import the API service
import { ApiService } from './api-service.js';

document.addEventListener('DOMContentLoaded', () => {
    const logoutButton = document.getElementById('logoutButton');
    const loadingOverlay = document.querySelector('.loading-overlay');
    const flashMessages = document.getElementById('flashMessages');

    if (logoutButton) {
        logoutButton.addEventListener('click', handleLogout);
    } else {
        console.error('Logout button not found in the document');
    }

    async function handleLogout() {
        try {
            showLoading();

            // Initialize API service
            await ApiService.initialize();

            // Make the logout request
            const response = await ApiService.safeFetch('/auth/logout', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json'
                }
            });

            // Handle the response directly as JSON
            if (response && response.status === 'success') {
                // Successful logout - redirect to the provided URL
                if (response.redirect_url) {
                    window.location.replace(response.redirect_url);
                } else {
                    // Fallback to index if no redirect URL provided
                    window.location.replace('/index');
                }
            } else {
                throw new Error(response?.message || 'Logout failed');
            }
        } catch (error) {
            console.error('Logout failed:', error);

            // Show error message to user
            if (flashMessages) {
                flashMessages.innerHTML = `
                    <div class="alert alert-danger alert-dismissible fade show">
                        ${error.message || 'Logout failed. Please try again.'}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                `;
            }
            hideLoading();
        } finally {
            // Hide loading overlay
            loadingOverlay.style.display = 'none';
        }
    }
});


// Prevent navigation using browser back/forward buttons
window.addEventListener('load', function () {
    window.history.pushState({ page: 'dashboard' }, '', '');

    window.addEventListener('popstate', function (event) {
        window.history.pushState({ page: 'dashboard' }, '', '');
        showNavigationWarning();
    });
});

function showNavigationWarning() {
    const alertHtml = `
        <div class="alert alert-warning alert-dismissible fade show" role="alert">
            Please use the navigation buttons provided instead of browser controls.
        </div>
    `;

    const flashMessages = document.getElementById('flashMessages');
    flashMessages.innerHTML = alertHtml;
}

// Make navigateToHome available globally
window.navigateToHome = async function () {
    // Show loading overlay
    document.querySelector('.loading-overlay').style.display = 'flex';

    try {
        // First ensure API service is initialized
        await ApiService.initialize();

        // Make the secure navigation request
        const response = await ApiService.navigateToHome();

        // Check if we received a redirect URL
        if (response.redirect_url) {
            window.location.href = response.redirect_url;
        } else {
            // Default to home if no specific redirect provided
            window.location.href = '/';
        }

    } catch (error) {
        console.error('Navigation failed:', error);
        // Hide loading overlay
        document.querySelector('.loading-overlay').style.display = 'none';

        // Show error message
        const flashMessages = document.getElementById('flashMessages');
        flashMessages.innerHTML = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                Navigation failed. Please try again.
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
    }
};