import { initializePortfolio } from './portfolio-manager.js';
import { setupUIHandlers } from './portfolio-ui.js';
import { showError, showSuccess } from './utils.js';
import CurrencyManager from './currency-manager.js';


/**
 * Main application initialization
 * Sets up all event listeners and initializes components
 */
document.addEventListener('DOMContentLoaded', async () => {
    new CurrencyManager();
    try {
        // Initialize Select2 for cryptocurrency selection
        $('#crypto-select').select2({
            placeholder: 'Select a cryptocurrency',
            allowClear: true
        });

        // Initialize components
        await initializePortfolio();
        setupUIHandlers();

        // Set max date for purchase date input to today
        const purchaseDateInput = document.getElementById('purchase-date');
        purchaseDateInput.max = new Date().toISOString().split('T')[0];

        showSuccess('Application initialized successfully');
    } catch (error) {
        console.error('Initialization error:', error);
        showError('Failed to initialize application');
    }
});