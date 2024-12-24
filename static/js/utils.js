// static/js/utils.js

/**
 * Format currency value with proper symbol and decimal places
 * @param {number} amount - Amount to format
 * @param {string} currency - Currency code (USD or EUR)
 * @returns {string} Formatted currency string
 */


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
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }).format(amount);
    } catch (error) {
        console.error('Error formatting currency:', error);
        return `${config.symbol}${amount.toFixed(2)}`;
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
 * Get current user's preferred currency with error handling
 * Fetches the currency preference from the server using the /api/preferences/currency endpoint
 * Falls back to USD if there's any error in the process
 * @returns {Promise<string>} Preferred currency code (USD or EUR)
 */
export async function getCurrentCurrency() {
    try {
        // Using the correct API endpoint that matches our Flask route
        const response = await fetch('/api/preferences/currency');

        // Check if the response was successful
        if (!response.ok) {
            // If the server returns an error, throw an exception with details
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to fetch currency preference');
        }

        // Parse the response data
        const data = await response.json();

        // Get the currency from the response, using the correct property name
        // that matches what our Flask endpoint returns
        const currency = data.currency || 'USD';

        // Ensure the currency is always uppercase for consistency
        return currency.toUpperCase();

    } catch (error) {
        // Log the error for debugging purposes
        console.error('Error fetching currency preference:', error);

        // Return USD as a safe default if anything goes wrong
        return 'USD';
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
    alertDiv.className = 'alert alert-success alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.getElementById('flashMessages').appendChild(alertDiv);
}

export function showLoading() {
    document.querySelector('.loading-overlay').style.display = 'flex';
}

export function hideLoading() {
    document.querySelector('.loading-overlay').style.display = 'none';
}