
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
        availableCryptos = await ApiService.fetchCryptocurrencies();
        populateCryptoSelect(availableCryptos);
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
    select.innerHTML = '<option value="">Select a cryptocurrency</option>';

    cryptos.forEach(crypto => {
        const option = new Option(
            `${crypto.name} (${crypto.symbol}) - $${crypto.current_price.toFixed(2)}`,
            crypto.id
        );
        $(option).data('symbol', crypto.symbol);
        $(option).data('name', crypto.name);
        select.appendChild(option);
    });


    // Update purchase price when crypto is selected
    $('#crypto-select').on('select2:select', function (e) {
        const selectedCrypto = availableCryptos.find(c => c.id === e.params.data.id);
        if (selectedCrypto) {
            document.getElementById('purchase-price').value = selectedCrypto.current_price.toFixed(2);
        }
    });
}

/**
 * Set up automatic portfolio refresh
 */
function setupAutoRefresh() {
    setInterval(() => {
        window.location.reload();
    }, 60000); // Refresh every minute
}

export { availableCryptos };