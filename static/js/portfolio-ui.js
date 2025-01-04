// static/js/portfolio-ui.js

import { ApiService } from './api-service.js';
import { getCurrentCurrency, } from './utils.js';
import { showError, showSuccess, showLoading, hideLoading } from './utils.js';

export function setupUIHandlers() {
    setupAddCryptoForm();
    setupEditHandlers();
    setupDeleteHandlers();
}

/**
 * Format date string to yyyy-MM-dd format
 * @param {string} dateString - Date string in any format
 * @returns {string} Formatted date string
 */
function formatDateForInput(dateString) {
    // Handle empty or invalid dates
    if (!dateString) return '';

    // Create a date object from the string
    const date = new Date(dateString);

    // Check if date is valid
    if (isNaN(date.getTime())) return '';

    // Format to YYYY-MM-DD
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');

    return `${year}-${month}-${day}`;
}
/**
 * Set up add cryptocurrency form handler
 */
function setupAddCryptoForm() {

    // Validazione input
    function validateInput(value, type) {
        switch (type) {
            case 'amount':
            case 'price':
                return !isNaN(value) && value > 0 && value < 1000000000;
            case 'date':
                const date = new Date(value);
                return date instanceof Date && !isNaN(date) && date <= new Date();
            default:
                return true;
        }
    }

    // Sanitizzazione input
    function sanitizeInput(value, type) {
        switch (type) {
            case 'amount':
            case 'price':
                return parseFloat(value).toFixed(8);
            case 'string':
                return DOMPurify.sanitize(value);
            default:
                return value;
        }
    }

    document.getElementById('addCryptoForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();


        try {
            const selectedOption = $('#crypto-select').select2('data')[0];
            if (!selectedOption) {
                throw new Error('Please select a cryptocurrency');
            }

            // Validazione e sanitizzazione degli input
            const amount = document.getElementById('amount').value;
            const purchasePrice = document.getElementById('purchase-price').value;
            const purchaseDate = document.getElementById('purchase-date').value;

            if (!validateInput(amount, 'amount')) {
                throw new Error('Invalid amount');
            }
            if (!validateInput(purchasePrice, 'price')) {
                throw new Error('Invalid purchase price');
            }
            if (!validateInput(purchaseDate, 'date')) {
                throw new Error('Invalid date');
            }

            const cryptoData = {
                crypto_id: selectedOption.id,
                symbol: $(selectedOption.element).data('symbol'),
                amount: parseFloat(document.getElementById('amount').value),
                purchase_price: parseFloat(document.getElementById('purchase-price').value),
                purchase_date: purchaseDate
            };



            await ApiService.addCrypto(cryptoData);
            showSuccess('Cryptocurrency added successfully');
            // Instead of full page reload, fetch and update only the portfolio data
            window.location.reload();
            // Reset form
            document.getElementById('addCryptoForm').reset();
            $('#crypto-select').val(null).trigger('change');
        } catch (error) {
            console.error('Error:', error);
            showError(error.message);
        } finally {
            hideLoading();
        }
    });
}

/**
 * Set up portfolio edit handlers
 */
function setupEditHandlers() {

    const setMaxDate = () => {
        const today = new Date().toISOString().split('T')[0];
        document.querySelectorAll('input[type="date"]').forEach(input => {
            input.max = today;
        });
    };
    setMaxDate();
    const originalToggleEdit = window.toggleEdit;
    window.toggleEdit = function (button) {
        originalToggleEdit(button);
        setMaxDate();
    };

    // Edit button handler
    window.toggleEdit = function (button) {
        const row = button.closest('tr');
        toggleEditMode(row, true);
    };



    // Save changes handler
    window.saveChanges = async function (button) {
        const row = button.closest('tr');
        showLoading();

        try {
            const cryptoId = row.dataset.cryptoId;
            const updateData = getUpdateData(row);
            await ApiService.updateCrypto(cryptoId, updateData);
            showSuccess('Cryptocurrency updated successfully');
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showError(error.message);
            toggleEditMode(row, false);
        } finally {
            hideLoading();
        }
    };

    // Cancel edit handler
    window.cancelEdit = function (button) {
        const row = button.closest('tr');
        toggleEditMode(row, false);
    };


}

// Delete handler
let currentCryptoId = null;

// Replace the original removeCrypto function
window.removeCrypto = function (cryptoId) {
    currentCryptoId = cryptoId;
    const modal = document.getElementById('deleteConfirmationModal');
    modal.classList.add('active');
};

function setupDeleteHandlers() {
    const modal = document.getElementById('deleteConfirmationModal');
    const cancelBtn = document.getElementById('cancelDelete');
    const confirmBtn = document.getElementById('confirmDelete');

    // Close modal on cancel
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function () {
            modal.classList.remove('active');
            currentCryptoId = null;
        });
    }

    // Close modal on clicking outside
    modal.addEventListener('click', function (e) {
        if (e.target === modal) {
            modal.classList.remove('active');
            currentCryptoId = null;
        }
    });

    // Handle delete confirmation
    if (confirmBtn) {
        confirmBtn.addEventListener('click', async function () {
            if (!currentCryptoId) return;

            showLoading();
            try {
                await ApiService.deleteCrypto(currentCryptoId);
                showSuccess('Cryptocurrency removed successfully');
                window.location.reload();
            } catch (error) {
                console.error('Error:', error);
                showError(error.message);
            } finally {
                hideLoading();
                modal.classList.remove('active');
                currentCryptoId = null;
            }
        });
    }
}

/**
 * Toggle edit mode for a portfolio row
 * @param {HTMLElement} row - Table row element
 * @param {boolean} enable - Whether to enable or disable edit mode
 */
function toggleEditMode(row, enable) {
    const displayValues = row.querySelectorAll('.display-value');
    const editInputs = row.querySelectorAll('.edit-input');
    const editBtn = row.querySelector('.edit-btn');
    const saveBtn = row.querySelector('.save-btn');
    const cancelBtn = row.querySelector('.cancel-btn');

    if (enable) {
        row.dataset.originalValues = JSON.stringify(Array.from(editInputs).map(input => input.value));
        displayValues.forEach((span, index) => {
            const input = editInputs[index];
            if (input.type === 'date') {
                // Format the date properly for the input
                input.value = formatDateForInput(span.textContent);
            }
            span.classList.add('d-none');
        });
        editInputs.forEach(input => input.classList.remove('d-none'));
        editBtn.classList.add('d-none');
        saveBtn.classList.remove('d-none');
        cancelBtn.classList.remove('d-none');
    } else {
        const originalValues = JSON.parse(row.dataset.originalValues);
        editInputs.forEach((input, index) => {
            input.value = originalValues[index];
        });
        displayValues.forEach(span => span.classList.remove('d-none'));
        editInputs.forEach(input => input.classList.add('d-none'));
        editBtn.classList.remove('d-none');
        saveBtn.classList.add('d-none');
        cancelBtn.classList.add('d-none');
    }
}

/**
 * Get update data from edit form
 * @param {HTMLElement} row - Table row element
 * @returns {Object} Update data
 */
function getUpdateData(row) {
    const inputs = row.querySelectorAll('.edit-input');
    return {
        amount: parseFloat(inputs[0].value),
        purchase_price: parseFloat(inputs[1].value),
        purchase_date: inputs[2].value
    };
}

// Add this new function to update the portfolio table
async function updatePortfolioTable() {
    return fetch('/dashboard')
        .then(response => response.text())
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newTable = doc.querySelector('#portfolioTable tbody');
            const currentTable = document.querySelector('#portfolioTable tbody');

            if (newTable && currentTable) {
                currentTable.innerHTML = newTable.innerHTML;
            }

            return getCurrentCurrency();
        })
        .then(updateTableDisplay())
        .catch(error => {
            console.error('Error updating portfolio:', error);
            showError('Failed to update portfolio display');
        });
}

/**
 * Update the display of all monetary values in the table
 * This function is called after loading the page and after currency updates
 */

async function updateTableDisplay() {
    try {
        showLoading();

        // Aggiorniamo tutti i valori monetari nella tabella
        const monetaryElements = document.querySelectorAll('.current-price, .current-value, .purchase-price');
        monetaryElements.forEach(element => {
            // Estraiamo il valore numerico dal testo
            const rawValue = parseFloat(element.textContent.replace(/[^0-9.-]+/g, ''));
        });

        // Aggiorniamo i profitti/perdite
        const profitLossElements = document.querySelectorAll('.profit-loss');
        profitLossElements.forEach(element => {
            const rawValue = parseFloat(element.textContent.replace(/[^0-9.-]+/g, ''));
        });


    } catch (error) {
        console.error('Error updating display with new currency:', error);
        showError('Failed to update currency display');
    } finally {
        hideLoading();
    }
}
