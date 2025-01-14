import { ApiService } from './api-service.js';
import { showError } from './utils.js';

let availableCryptos = [];

/**
 * Initialize portfolio functionality
 */
export async function initializePortfolio() {
    try {
        await loadAvailableCryptos();
        setupAutoRefresh();
    } catch (error) {
        console.error('Portfolio initialization error:', error);
        showError('Failed to initialize portfolio');
    }
}

/**
 * Load available cryptocurrencies and populate select
 */
async function loadAvailableCryptos() {
    try {
        // Get the response from the API
        const response = await ApiService.fetchCryptocurrencies();

        // Check if the response has the expected structure
        if (response.status === 'success' && Array.isArray(response.data)) {
            availableCryptos = response.data;
            populateCryptoSelect(availableCryptos);
        } else {
            throw new Error('Invalid cryptocurrency data format');
        }
    } catch (error) {
        console.error('Error loading cryptocurrencies:', error);
        showError('Failed to load cryptocurrencies');
    }
}

/**
 * Populate cryptocurrency select element
 * @param {Array} cryptos - List of available cryptocurrencies
 */
function populateCryptoSelect(cryptos) {
    const select = document.getElementById('crypto-select');
    if (!select) {
        console.error('Crypto select element not found');
        return;
    }

    // Clear existing options
    select.innerHTML = '<option value="">Select a cryptocurrency</option>';

    // Ensure cryptos is an array before attempting to iterate
    if (!Array.isArray(cryptos)) {
        console.error('Invalid cryptocurrencies data format');
        return;
    }

    cryptos.forEach(crypto => {
        // Add null checks to prevent errors with malformed data
        if (crypto && crypto.id && crypto.name && crypto.symbol && crypto.current_price != null) {
            const option = new Option(
                `${crypto.name} (${crypto.symbol}) - $${crypto.current_price.toFixed(6)}`,
                crypto.id
            );
            $(option).data('symbol', crypto.symbol);
            $(option).data('name', crypto.name);
            select.appendChild(option);
        }
    });

    // Update purchase price when crypto is selected
    $('#crypto-select').on('select2:select', function (e) {
        const selectedCrypto = availableCryptos.find(c => c.id === e.params.data.id);
        if (selectedCrypto) {
            document.getElementById('purchase-price').value = selectedCrypto.current_price.toFixed(6);
        }
    });
}



/**
 * Set up automatic portfolio refresh
 */
function setupAutoRefresh() {
    setInterval(() => {
        window.location.reload();
    }, 300000); // Refresh 5 minute
}

export { availableCryptos };