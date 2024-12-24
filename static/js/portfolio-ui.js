// static/js/portfolio-ui.js

import { ApiService } from './api-service.js';
import { getCurrentCurrency, } from './utils.js';
import { showError, showSuccess, showLoading, hideLoading } from './utils.js';

export function setupUIHandlers() {
    setupAddCryptoForm();
    setupEditHandlers();
}

/**
 * Set up add cryptocurrency form handler
 */
function setupAddCryptoForm() {
    document.getElementById('addCryptoForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();


        try {
            const selectedOption = $('#crypto-select').select2('data')[0];
            if (!selectedOption) {
                throw new Error('Please select a cryptocurrency');
            }

            const cryptoData = {
                crypto_id: selectedOption.id,
                symbol: $(selectedOption.element).data('symbol'),
                amount: parseFloat(document.getElementById('amount').value),
                purchase_price: parseFloat(document.getElementById('purchase-price').value),
                purchase_date: document.getElementById('purchase-date').value
            };

            await ApiService.addCrypto(cryptoData);
            showSuccess('Cryptocurrency added successfully');
            // Instead of full page reload, fetch and update only the portfolio data
            await updatePortfolioTable();
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

    // Delete handler
    window.removeCrypto = async function (cryptoId) {
        if (!confirm('Are you sure you want to remove this cryptocurrency?')) {
            return;
        }

        showLoading();
        try {
            await ApiService.deleteCrypto(cryptoId);
            showSuccess('Cryptocurrency removed successfully');
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showError(error.message);
        } finally {
            hideLoading();
        }
    };
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
        displayValues.forEach(span => span.classList.add('d-none'));
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
