// static/js/portfolio-ui.js

import { ApiService } from './api-service.js';
import InputValidator from './input-validator.js';
import { showError, showSuccess, showLoading, hideLoading, safePageReload } from './utils.js';

export function setupUIHandlers() {
    setupAddCryptoForm();
    setupEditHandlers();
    setupDeleteHandlers();
}

async function handleOperation(operation, successMessage) {
    showLoading();
    try {
        await operation();
        showSuccess(successMessage);

        // Utilizziamo safePageReload invece del reload diretto
        safePageReload();
    } catch (error) {
        console.error('Operation failed:', error);
        showError(error.message);
        hideLoading();
    }
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

    // Add input event listeners for real-time validation
    const amountInput = document.getElementById('amount');
    const priceInput = document.getElementById('purchase-price');

    // Attach numeric validation to amount and price inputs
    InputValidator.attachNumericInputHandler(amountInput);
    InputValidator.attachNumericInputHandler(priceInput);

    document.querySelectorAll('input[type="date"]').forEach(input => {
        input.max = new Date().toISOString().split('T')[0];
        input.min = '2010-01-01';
    });

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
    // Improved validation function that checks for valid decimal numbers
    function validateNumericInput(value, type) {
        // Regular expression to match valid decimal numbers
        // Allows: 
        // - Optional negative sign
        // - Whole numbers
        // - Decimal numbers
        // - Prevents scientific notation (e.g., e22222)
        const decimalRegex = /^-?\d*\.?\d+$/;

        // First check if it's a valid decimal number format
        if (!decimalRegex.test(value)) {
            return false;
        }

        // Convert to number for range validation
        const numValue = parseFloat(value);

        switch (type) {
            case 'amount':
            case 'price':
                // Ensure the number is positive and within reasonable bounds
                return !isNaN(numValue) &&
                    numValue > 0 &&
                    numValue < 1000000000 &&
                    value.toLowerCase().indexOf('e') === -1; // Extra check for scientific notation
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
                return parseFloat(value).toFixed(6);
            case 'string':
                return DOMPurify.sanitize(value);
            default:
                return value;
        }
    }

    function validateAndStyleInput(input, type) {
        const isValid = validateNumericInput(input.value, type);
        input.classList.toggle('invalid', !isValid);
        return isValid;
    }

    // Real-time validation as user types
    amountInput.addEventListener('input', (e) => {
        validateAndStyleInput(e.target, 'amount');
    });

    priceInput.addEventListener('input', (e) => {
        validateAndStyleInput(e.target, 'price');
    });

    document.getElementById('addCryptoForm').addEventListener('submit', async (e) => {
        e.preventDefault();


        if (!validateForm()) {
            return;
        }
        showLoading();


        try {
            const selectedOption = $('#crypto-select').select2('data')[0];
            if (!selectedOption) {
                throw new Error('Please select a cryptocurrency');
            }

            // Validazione e sanitizzazione degli input
            const amount = amountInput.value
            const purchasePrice = priceInput.value
            const purchaseDate = document.getElementById('purchase-date').value;

            if (!validateInput(amount, 'amount') && !sanitizeInput(amount, 'amount')) {
                throw new Error('Invalid amount');
            }
            if (!validateInput(purchasePrice, 'price') && !sanitizeInput(purchasePrice, 'price')) {
                throw new Error('Invalid purchase price');
            }
            if (!validateInput(purchaseDate, 'date')) {
                throw new Error('Invalid date');
            }


            // Validate all inputs
            if (!validateNumericInput(amount, 'amount')) {
                throw new Error('Invalid amount. Please enter a valid number.');
            }
            if (!validateNumericInput(purchasePrice, 'price')) {
                throw new Error('Invalid purchase price. Please enter a valid number.');
            }


            const cryptoData = {
                crypto_id: selectedOption.id,
                symbol: $(selectedOption.element).data('symbol'),
                amount: parseFloat(amount),
                purchase_price: parseFloat(purchasePrice),
                purchase_date: purchaseDate
            };


            await handleOperation(async () => {
                await ApiService.addCrypto(cryptoData);
                // Instead of full page reload, fetch and update only the portfolio data
                window.location.reload();
                // Reset form
                document.getElementById('addCryptoForm').reset();
                $('#crypto-select').val(null).trigger('change');
            },
                'Cryptocurrency added successfully'
            );
        } catch (error) {
            console.error('Error:', error);
            showError(error.message);
        } finally {
            hideLoading();
        }
    });

    function validateForm() {
        const inputs = document.querySelectorAll('#addCryptoForm input');
        let isValid = true;

        inputs.forEach(input => {
            if (!input.checkValidity()) {
                input.reportValidity();
                isValid = false;
            }
        });

        return isValid;
    }

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
        const inputs = row.querySelectorAll('.edit-input');
        inputs.forEach(input => {
            if (input.type === 'number') {
                InputValidator.attachNumericInputHandler(input);
            }
        });

        toggleEditMode(row, true);
    };



    // Save changes handler
    window.saveChanges = async function (button) {
        const row = button.closest('tr');
        const inputs = row.querySelectorAll('.edit-input');
        let isValid = true;

        inputs.forEach(input => {
            if (!input.checkValidity()) {
                input.reportValidity();
                isValid = false;
            }
        });

        if (!isValid) return;

        await handleOperation(async () => {
            try {
                // Force security credentials refresh before save
                await ApiService.initialize();
                // Small delay to ensure token propagation
                await new Promise(resolve => setTimeout(resolve, 100));
                const cryptoId = row.dataset.cryptoId;
                const updateData = getUpdateData(row);
                await ApiService.updateCrypto(cryptoId, updateData);
                window.location.reload();
            } catch (error) {
                console.error('Save failed:', {
                    error: error.message,
                    status: error.status
                });


                if (error.status === 403) {
                    // Instead of immediate retry, force a new token fetch
                    await ApiService.initialize();
                    // Clear any cached credentials
                    showError('Please try saving again - security tokens refreshed');
                    return; // Don't toggle edit mode off, let user retry
                } else {
                    showError(error.message);
                    toggleEditMode(row, false);
                }
            } finally {
                hideLoading();
            }


            // Cancel edit handler
            window.cancelEdit = function (button) {
                const row = button.closest('tr');
                toggleEditMode(row, false);
            };
        },
            'Cryptocurrency updated successfully'
        );
    };


}

// Delete handler
let currentCryptoId = null;

// Replace the original removeCrypto function
window.removeCrypto = function (cryptoId) {
    currentCryptoId = cryptoId;
    const modal = document.getElementById('deleteConfirmationModal');

    // Gestiamo la conferma di eliminazione
    document.getElementById('confirmDelete').onclick = async () => {
        modal.classList.remove('active');
        await handleOperation(
            async () => {
                await ApiService.deleteCrypto(currentCryptoId);
            },
            'Cryptocurrency removed successfully'
        );
    };

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