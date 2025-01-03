from typing import Dict, Any, Optional, Union, List
from datetime import datetime
import re
from decimal import Decimal
from dataclasses import dataclass
from enum import Enum
import validators


class ValidationError(Exception):
    """Custom exception for validation errors"""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class InputType(Enum):
    STRING = "string"
    NUMBER = "number"
    DATE = "date"
    EMAIL = "email"
    URL = "url"
    CRYPTO_ID = "crypto_id"
    CURRENCY = "currency"
    JWT = "jwt"


@dataclass
class ValidationRule:
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
    """Centralized input validation for the application"""

    # Common validation patterns
    PATTERNS = {
        'crypto_id': r'^[a-z0-9-]+$',
        'currency': r'^[A-Z]{3}$',
        'jwt': r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'
    }

    # Common validation rules
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
            'currency': ValidationRule(type=InputType.CURRENCY, pattern=PATTERNS['currency'],
                                       allowed_values=['USD', 'EUR'])
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
        Sanitize string input to prevent NoSQL injection and XSS
        """
        if not isinstance(value, str):
            return value

        # Remove NoSQL operators
        nosql_operators = ['$', '{', '}', '&&', '||', ';', '(', ')', '=']
        sanitized = value
        for op in nosql_operators:
            sanitized = sanitized.replace(op, '')

        # Encode HTML special characters
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
        """Validate a single value against a rule"""
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
        Validate request data against a set of rules
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
        """Validate portfolio addition data"""
        return cls.validate_request_data(data, cls.COMMON_RULES['portfolio_add'])

    @classmethod
    def validate_auth(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate authentication data"""
        return cls.validate_request_data(data, cls.COMMON_RULES['auth'])

    @classmethod
    def validate_currency_preference(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate currency preference data"""
        return cls.validate_request_data(data, cls.COMMON_RULES['currency_preference'])
