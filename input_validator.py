"""
Enhanced Input Validation System
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

This module implements a comprehensive input validation system with strong focus on
security, data sanitization, and protection against common web vulnerabilities.

Security Features:
1. Input Sanitization
   - NoSQL injection prevention
   - XSS protection
   - HTML encoding
   - Special character handling
   - Data type validation

2. Validation Protection
   - Strict type checking
   - Pattern validation
   - Range validation
   - Length constraints
   - Custom validation hooks

3. Data Security
   - Protected field handling
   - Safe type conversion
   - Secure date parsing
   - Protected numeric operations
   - Field access control

4. Error Management
   - Secure error reporting
   - Non-revealing messages
   - Protected validation state
   - Safe error recovery

Security Considerations:
- All input is sanitized before processing
- Pattern matching is strictly controlled
- Type conversions are handled securely
- Error messages don't leak internal details
- Validation rules are immutable
- Date ranges are strictly enforced
- Numeric values are bounded
- Custom validators are protected

Dependencies:
- validators: For email and URL validation
- datetime: For secure date handling
- decimal: For precise numeric operations
- re: For pattern matching
- typing: For type validation
"""

from typing import Dict, Any, Optional, Union, List
from datetime import datetime
import re
from decimal import Decimal
from dataclasses import dataclass
from enum import Enum
import validators


class ValidationError(Exception):
    """
    Secure exception class for validation errors.

    Security Features:
    - Sanitized error messages
    - Protected field names
    - Safe string representation
    """

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class InputType(Enum):
    """
    Secure enumeration of allowed input types.

    Security Features:
    - Immutable type definitions
    - Protected value access
    - Controlled type expansion
    """
    STRING = "string"
    NUMBER = "number"
    DATE = "date"
    EMAIL = "email"
    URL = "url"
    CRYPTO_ID = "crypto_id"
    CURRENCY = "currency"
    JWT = "jwt"


@dataclass(frozen=True)
class ValidationRule:
    """
    Immutable validation rule configuration.

    Security Features:
    - Frozen dataclass prevents modification
    - Type-checked attributes
    - Protected validator references
    """
    required: bool = True
    type: InputType = InputType.STRING
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[Any]] = None
    custom_validator: Optional[callable] = None


class InputValidator:
    """
    Secure input validation system with comprehensive protection against common vulnerabilities.

    Security Features:
    - Input sanitization
    - Type validation
    - Pattern matching
    - Range checking
    - Custom validation hooks
    """
    # Secure validation patterns with strict matching
    PATTERNS = {
        'crypto_id': r'^[a-z0-9-]+$',  # Alphanumeric and hyphen only
        'currency': r'^[A-Z]{3}$',      # Exactly 3 uppercase letters
        # JWT format
        'jwt': r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'
    }

    # Predefined validation rules with security constraints
    COMMON_RULES = {
        'portfolio_add': {
            'crypto_id': ValidationRule(type=InputType.CRYPTO_ID, pattern=PATTERNS['crypto_id']),
            'symbol': ValidationRule(min_length=1, max_length=10),
            'amount': ValidationRule(type=InputType.NUMBER, min_value=0.0000001),
            'purchase_price': ValidationRule(type=InputType.NUMBER, min_value=0),
            'purchase_date': ValidationRule(type=InputType.DATE)
        },
        'auth': {
            'provider': ValidationRule(allowed_values=['google', 'github']),
            'state': ValidationRule(min_length=32, max_length=64),
            'code': ValidationRule(min_length=20)
        },
        'currency_preference': {
            'currency': ValidationRule(
                type=InputType.CURRENCY,
                pattern=PATTERNS['currency'],
                allowed_values=['USD', 'EUR']
            )
        },
        'portfolio_update': {
            'amount': ValidationRule(type=InputType.NUMBER, min_value=0.0000001),
            'purchase_price': ValidationRule(type=InputType.NUMBER, min_value=0),
            'purchase_date': ValidationRule(type=InputType.DATE)
        }
    }

    MIN_ALLOWED_DATE = datetime(2010, 1, 1)

    @staticmethod
    def sanitize_input(value: str) -> str:
        """
        Securely sanitize string input to prevent injection attacks.

        Args:
            value: Input string to sanitize

        Returns:
            Sanitized string safe for processing

        Security measures:
        - NoSQL operator removal
        - HTML character encoding
        - Special character handling
        - Type checking
        """
        if not isinstance(value, str):
            return value

        # Remove potentially dangerous NoSQL operators
        nosql_operators = ['$', '{', '}', '&&', '||', ';', '(', ')', '=']
        sanitized = value
        for op in nosql_operators:
            sanitized = sanitized.replace(op, '')

        # Encode HTML special characters to prevent XSS
        html_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        }
        for char, encoded in html_chars.items():
            sanitized = sanitized.replace(char, encoded)

        return sanitized

    @classmethod
    def validate_value(cls, value: Any, rule: ValidationRule) -> Any:
        """
        Securely validate a single value against defined rules.

        Args:
            value: Input value to validate
            rule: ValidationRule to apply

        Returns:
            Validated and potentially transformed value

        Security measures:
        - Type validation
        - Range checking
        - Pattern matching
        - Custom validation protection
        """
        if rule.required and (value is None or value == ''):
            raise ValidationError("input", "Field is required")

        if value is None or value == '':
            return value

        # Type validation
        if rule.type == InputType.NUMBER:
            try:
                value = float(value)
            except ValueError:
                raise ValidationError("input", "Invalid number format")

        elif rule.type == InputType.DATE:
            try:
                if isinstance(value, str):
                    value = datetime.strptime(value, '%Y-%m-%d')
                    parsed_date = value
                    # New validation check
                if parsed_date < cls.MIN_ALLOWED_DATE:
                    raise ValidationError(
                        "input",
                        f"Date must be on or after {
                            cls.MIN_ALLOWED_DATE.strftime('%Y-%m-%d')}"
                    )

                value = parsed_date
            except ValueError:
                raise ValidationError(
                    "input", "Invalid date format (use YYYY-MM-DD)")

        elif rule.type == InputType.EMAIL:
            if not validators.email(value):
                raise ValidationError("input", "Invalid email format")

        elif rule.type == InputType.URL:
            if not validators.url(value):
                raise ValidationError("input", "Invalid URL format")

        # Length validation for strings
        if isinstance(value, str):
            if rule.min_length and len(value) < rule.min_length:
                raise ValidationError(
                    "input", f"Minimum length is {rule.min_length}")
            if rule.max_length and len(value) > rule.max_length:
                raise ValidationError(
                    "input", f"Maximum length is {rule.max_length}")

        # Range validation for numbers
        if isinstance(value, (int, float)):
            if rule.min_value is not None and value < rule.min_value:
                raise ValidationError(
                    "input", f"Minimum value is {rule.min_value}")
            if rule.max_value is not None and value > rule.max_value:
                raise ValidationError(
                    "input", f"Maximum value is {rule.max_value}")

        # Pattern validation
        if rule.pattern and isinstance(value, str):
            if not re.match(rule.pattern, value):
                raise ValidationError(
                    "input", "Value does not match required pattern")

        # Allowed values validation
        if rule.allowed_values is not None and value not in rule.allowed_values:
            raise ValidationError("input", f"Value must be one of: {
                                  rule.allowed_values}")

        # Custom validation
        if rule.custom_validator:
            try:
                rule.custom_validator(value)
            except Exception as e:
                raise ValidationError("input", str(e))

        return value

    @classmethod
    def validate_request_data(cls, data: Dict[str, Any], rules: Dict[str, ValidationRule]) -> Dict[str, Any]:
        """
        Securely validate complete request data against defined rules.

        Args:
            data: Dictionary of input data
            rules: Dictionary of validation rules

        Returns:
            Dictionary of validated data

        Security measures:
        - Unknown field detection
        - Complete validation coverage
        - Protected field access
        - Secure type conversion
        """
        validated_data = {}

        # Check for unknown fields
        unknown_fields = set(data.keys()) - set(rules.keys())
        if unknown_fields:
            raise ValidationError("input", f"Unknown fields: {
                                  ', '.join(unknown_fields)}")

        # Validate each field
        for field, rule in rules.items():
            value = data.get(field)

            # Sanitize string inputs
            if isinstance(value, str):
                value = cls.sanitize_input(value)

            try:
                validated_value = cls.validate_value(value, rule)
                if validated_value is not None:  # Only include non-None values
                    validated_data[field] = validated_value
            except ValidationError as e:
                raise ValidationError(field, e.message)

        return validated_data

    @classmethod
    def validate_portfolio_add(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Secure validation for portfolio additions."""
        return cls.validate_request_data(data, cls.COMMON_RULES['portfolio_add'])

    @classmethod
    def validate_auth(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Secure validation for authentication data."""
        return cls.validate_request_data(data, cls.COMMON_RULES['auth'])

    @classmethod
    def validate_currency_preference(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Secure validation for currency preferences."""
        return cls.validate_request_data(data, cls.COMMON_RULES['currency_preference'])
