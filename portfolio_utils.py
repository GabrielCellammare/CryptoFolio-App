"""
Enhanced Portfolio Metrics Calculator
Version: 2.0
Author: [Gabriel Cellammare]
Last Modified: [05/01/2025]

This module provides precise financial calculations for cryptocurrency portfolio analysis
with comprehensive error handling, input validation, and proper decimal arithmetic.

Financial Calculation Features:
1. Decimal-based precise numerical handling
2. Comprehensive error handling
3. Robust input validation
4. Proper logging
5. Currency validation
6. Threshold-based zero handling
7. Controlled numerical precision
8. Explicit error states

Dependencies:
- decimal: For precise numerical calculations
- logging: For proper error tracking
- typing: For type hints
"""

import decimal
import logging
from decimal import Decimal
from typing import Dict, Union
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants for financial calculations
PRECISION = Decimal('0.00000001')  # 8 decimal places for crypto
ZERO_THRESHOLD = Decimal('0.000000001')  # Threshold for "zero" comparisons
ROUNDING_PLACES = 8  # Number of decimal places to round to


class Currency(Enum):
    """Valid currency denominations"""
    USD = "USD"
    EUR = "EUR"


class PortfolioCalculationError(Exception):
    """Base exception for portfolio calculation errors"""
    pass


class InvalidInputError(PortfolioCalculationError):
    """Exception for invalid input data"""
    pass


class CurrencyError(PortfolioCalculationError):
    """Exception for currency-related errors"""
    pass


def validate_numeric_input(value: Union[str, float, Decimal],
                           field_name: str) -> Decimal:
    """
    Validate and convert numeric input to Decimal.

    Args:
        value: The value to validate
        field_name: Name of the field for error messages

    Returns:
        Decimal: The validated and converted value

    Raises:
        InvalidInputError: If value is invalid
    """
    try:
        decimal_value = Decimal(str(value))
        if decimal_value < 0:
            raise InvalidInputError(
                f"{field_name} cannot be negative: {decimal_value}"
            )
        return decimal_value.quantize(PRECISION)
    except (decimal.InvalidOperation, TypeError, ValueError) as e:
        raise InvalidInputError(
            f"Invalid {field_name}: {value}. Error: {str(e)}"
        )


def validate_currency(currency: str) -> str:
    """
    Validate currency denomination.

    Args:
        currency: Currency code to validate

    Returns:
        str: Validated currency code

    Raises:
        CurrencyError: If currency is invalid
    """
    try:
        return Currency[currency.upper()].value
    except (KeyError, AttributeError):
        raise CurrencyError(f"Invalid currency: {currency}")


def calculate_portfolio_metrics(
    portfolio_item: Dict[str, Union[str, float, Decimal]],
    current_price: Union[str, float, Decimal],
    currency: str = 'USD'
) -> Dict[str, Union[Decimal, str, None]]:
    """
    Calculate Financial Metrics for Portfolio Position with precise decimal arithmetic.

    Processes a portfolio position and calculates key financial metrics
    including current value, profit/loss, and percentage returns.

    Args:
        portfolio_item: Portfolio position containing:
            - amount: Asset quantity
            - purchase_price: Entry price
        current_price: Current market price
        currency: Currency denomination (default: 'USD')

    Returns:
        dict: Financial metrics including:
            - current_price: Market price
            - current_value: Position value
            - profit_loss: Absolute P/L
            - profit_loss_percentage: Relative P/L
            - currency: Denomination currency
            - error: Error message if calculation failed

    Financial Safety:
    - Decimal arithmetic for precision
    - Comprehensive input validation
    - Specific error handling
    - Proper logging
    - Currency validation
    - Threshold-based zero handling
    - Controlled rounding
    """
    result = {
        'current_price': None,
        'current_value': None,
        'profit_loss': None,
        'profit_loss_percentage': None,
        'currency': None,
        'error': None
    }

    try:
        # Validate currency first
        result['currency'] = validate_currency(currency)

        # Validate and convert inputs
        amount = validate_numeric_input(
            portfolio_item.get('amount'), 'amount'
        )
        purchase_price = validate_numeric_input(
            portfolio_item.get('purchase_price'), 'purchase_price'
        )
        validated_current_price = validate_numeric_input(
            current_price, 'current_price'
        )

        # Position value calculations with precise decimal arithmetic
        current_value = (amount * validated_current_price).quantize(PRECISION)
        purchase_value = (amount * purchase_price).quantize(PRECISION)

        # Profit/Loss calculations with threshold checking
        profit_loss = (current_value - purchase_value).quantize(PRECISION)

        # Calculate percentage with threshold protection
        if purchase_value > ZERO_THRESHOLD:
            profit_loss_percentage = (
                ((current_value / purchase_value) - Decimal('1')) *
                Decimal('100')
            ).quantize(PRECISION)
        else:
            profit_loss_percentage = Decimal('0')

        # Update result with calculated values
        result.update({
            'current_price': validated_current_price,
            'current_value': current_value,
            'profit_loss': profit_loss,
            'profit_loss_percentage': profit_loss_percentage,
            'error': None
        })

        logger.info(
            f"Successfully calculated metrics for portfolio position: "
            f"amount={amount}, current_price={validated_current_price}"
        )

    except InvalidInputError as e:
        logger.error(f"Invalid input error: {str(e)}")
        result['error'] = f"Invalid input: {str(e)}"

    except CurrencyError as e:
        logger.error(f"Currency error: {str(e)}")
        result['error'] = f"Currency error: {str(e)}"

    except Exception as e:
        logger.error(
            f"Unexpected error in calculate_portfolio_metrics: {str(e)}")
        result['error'] = f"Calculation error: {str(e)}"

    return result
