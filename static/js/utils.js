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
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
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