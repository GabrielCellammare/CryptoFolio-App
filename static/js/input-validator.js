// static/js/input-validator.js

class InputValidator {
    static DECIMAL_PLACES = 6;
    static NUMBER_PATTERN = new RegExp(`^\\d*\\.?\\d{0,${InputValidator.DECIMAL_PLACES}}$`);

    static validateNumericInput(value) {
        // Check if the input matches our required pattern (numbers and one decimal point only)
        if (!InputValidator.NUMBER_PATTERN.test(value)) {
            return {
                isValid: false,
                message: `Please enter a valid number with up to ${InputValidator.DECIMAL_PLACES} decimal places`
            };
        }

        // Convert to number and check if it's within reasonable bounds
        const numValue = parseFloat(value);
        if (isNaN(numValue) || numValue <= 0 || numValue >= 1000000000) {
            return {
                isValid: false,
                message: 'Please enter a number greater than 0 and less than 1 billion'
            };
        }

        return {
            isValid: true,
            value: numValue.toFixed(InputValidator.DECIMAL_PLACES)
        };
    }

    static validateDateInput(value) {
        const date = new Date(value);
        const minDate = new Date('2010-01-01');
        const today = new Date();

        if (isNaN(date.getTime())) {
            return {
                isValid: false,
                message: 'Please enter a valid date'
            };
        }

        if (date < minDate || date > today) {
            return {
                isValid: false,
                message: 'Date must be between January 1, 2010 and today'
            };
        }

        return {
            isValid: true,
            value: value
        };
    }

    static formatNumber(value) {
        if (typeof value !== 'number' || isNaN(value)) {
            return '0.000000';
        }
        return value.toFixed(InputValidator.DECIMAL_PLACES);
    }

    static attachNumericInputHandler(input) {
        let previousValue = '';

        input.addEventListener('input', (e) => {
            const result = InputValidator.validateNumericInput(e.target.value);

            if (result.isValid) {
                previousValue = e.target.value;
                input.setCustomValidity('');
                input.classList.remove('is-invalid');
            } else {
                e.target.value = previousValue;
                input.setCustomValidity(result.message);
                input.classList.add('is-invalid');

                // Create or update validation message
                let feedbackDiv = input.nextElementSibling;
                if (!feedbackDiv || !feedbackDiv.classList.contains('invalid-feedback')) {
                    feedbackDiv = document.createElement('div');
                    feedbackDiv.className = 'invalid-feedback';
                    input.parentNode.insertBefore(feedbackDiv, input.nextSibling);
                }
                feedbackDiv.textContent = result.message;
            }
        });
    }
}

export default InputValidator;