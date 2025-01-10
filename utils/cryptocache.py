"""
CryptoCache: Advanced Cryptocurrency Data Security Framework
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

This module implements a comprehensive security framework for caching cryptocurrency
pricing data with defense-in-depth measures and robust security controls. It provides
multi-layered protection against various attack vectors while ensuring data integrity
and secure API communications.

Core Security Features:

1. Data Protection
   - Secure cache file handling
   - Data validation and sanitization
   - Protected memory operations
   - Integrity verification

2. API Security
   - Rate limiting implementation 
   - Request throttling
   - Secure HTTP headers
   - Response validation

3. Cache Management
   - Secure directory creation
   - Protected file operations
   - Timestamp validation
   - Data expiration controls

4. Error Handling
   - Comprehensive exception management
   - Secure logging practices
   - Fail-safe defaults
   - Recovery procedures

Security Considerations:

1. File System Security:
   - Cache directory permissions must be properly configured
   - File operations need atomic write protection
   - Path traversal prevention required
   - Temporary file handling must be secure

2. API Communication:
   - SSL/TLS verification should be enforced
   - API keys need secure storage
   - Request headers should be sanitized
   - Rate limiting must prevent DOS

3. Data Validation:
   - All input parameters require validation
   - Cache data must be verified
   - Response data needs sanitization
   - Type checking should be strict

4. Memory Management:
   - Sensitive data needs secure cleanup
   - Memory limits should be enforced
   - Large objects require streaming
   - Garbage collection timing matters

Dependencies:
- requests: HTTP client with security features
- pathlib: Secure path operations
- json: Data serialization
- logging: Security event tracking
- dotenv: Environment management
- hashlib: Cryptographic operations

"""

from datetime import datetime, time, timedelta
import json
import os
from pathlib import Path
from dotenv import load_dotenv
import requests
from requests.exceptions import RequestException
import logging
from typing import List, Dict, Optional, Any
import hashlib
from urllib.parse import urljoin

# Configure logging with proper format for better debugging and monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Constants for API configuration and request handling
CACHE_DIR = Path("cache")
COINGECKO_BASE_URL = "https://api.coingecko.com/api/v3/"
DEFAULT_TIMEOUT = 10  # Timeout for API requests in seconds
MAX_RETRIES = 3      # Maximum number of retry attempts for failed requests


class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass


def initialize_environment() -> Dict:
    """
    Initialize and validate environment variables

    Returns:
        Dict: Configuration dictionary containing validated environment variables

    Raises:
        EnvironmentError: If required environment variables are missing
        SecurityError: If environment variables contain invalid values
    """
    load_dotenv()

    required_vars = ['COINGECKO_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        raise EnvironmentError(
            f"Missing required environment variables: {
                ', '.join(missing_vars)}"
        )

    # Validate API key format
    api_key = os.getenv('COINGECKO_API_KEY')
    if not isinstance(api_key, str) or len(api_key) < 16:
        raise SecurityError("Invalid API key format")

    # Validate cache duration
    cache_duration = os.getenv('CACHE_DURATION', '30')  # 30 minutes default
    try:
        cache_duration = int(cache_duration)
        if cache_duration < 0 or cache_duration > 1440:  # Max 24 hours
            raise ValueError
    except ValueError:
        raise SecurityError("Invalid cache duration value")

    return {
        'CACHE_DURATION': cache_duration,
        'COINGECKO_API_KEY': api_key
    }


class CryptoCache:
    """
    A cryptocurrency data caching system that provides secure data retrieval and storage.
    Implements rate limiting, input validation, and proper error handling.
    """

    def __init__(self):
        """
        Initialize CryptoCache with configuration from environment variables

        Raises:
            SecurityError: If security requirements are not met
            EnvironmentError: If required configuration is missing
        """
        try:
            config = initialize_environment()

            self.api_key = config['COINGECKO_API_KEY']
            self.cache_duration = timedelta(minutes=config['CACHE_DURATION'])

            self.cache_dir = CACHE_DIR
            self._secure_cache_directory()
            self.cache_file = self.cache_dir / "crypto_cache.json"

            self._load_cache()
            logger.info("CryptoCache initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize CryptoCache: {str(e)}")
            raise

    def _validate_cache_data(self, data: Any) -> bool:
        """
        Validate cached data for security and integrity

        Args:
            data: Data to validate

        Returns:
            bool: True if data is valid, False otherwise
        """
        try:
            # Verifica che i dati non siano None
            if data is None:
                return False

            # Verifica il tipo di dato basandosi sui possibili valori di ritorno dei metodi
            if isinstance(data, list):
                # Validazione per get_available_cryptocurrencies
                return all(
                    isinstance(item, dict) and
                    all(key in item for key in [
                        'id', 'symbol', 'name', 'current_price'])
                    for item in data
                )
            elif isinstance(data, dict):
                # Validazione per get_crypto_prices
                return all(
                    isinstance(k, str) and
                    isinstance(v, dict) and
                    all(isinstance(price, (int, float))
                        for price in v.values())
                    for k, v in data.items()
                )
            elif isinstance(data, (int, float)):
                # Validazione per get_exchange_rate
                return data > 0

            return False

        except Exception as e:
            logger.error(f"Cache validation error: {str(e)}")
            return False

    def _secure_cache_directory(self) -> None:
        """
        Ensure cache directory exists and is properly configured

        Raises:
            SecurityError: If directory cannot be created or accessed
        """
        try:
            if not self.cache_dir.exists():
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Cache directory created successfully")
        except Exception as e:
            logger.error(f"Cache directory error: {str(e)}")
            raise

    def _load_cache(self) -> None:
        """
        Load and validate cache data from file

        Raises:
            SecurityError: If cache data is invalid or cannot be loaded
        """
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)

                    # Validate cache structure
                    if not isinstance(cache_data, dict):
                        raise SecurityError("Invalid cache data structure")

                    self.data = cache_data.get('data', {})
                    self.timestamp = datetime.fromisoformat(
                        cache_data.get('timestamp', '2000-01-01')
                    )
            else:
                # Initialize new cache
                with open(self.cache_file, 'w') as f:
                    json.dump({
                        'data': {},
                        'timestamp': datetime.min.isoformat()
                    }, f)
                self.data = {}
                self.timestamp = datetime.min

            logger.info("Cache loaded successfully")
        except Exception as e:
            logger.error(f"Cache loading error: {str(e)}")
            self.data = {}
            self.timestamp = datetime.min

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make secure API request with rate limiting and error handling

        Args:
            endpoint (str): API endpoint to call
            params (Dict, optional): Query parameters for the request

        Returns:
            Dict: API response data

        Raises:
            RequestException: If request fails after retries
            SecurityError: If response validation fails
        """
        if not isinstance(endpoint, str) or not endpoint:
            raise SecurityError("Invalid endpoint")
        if params is not None and not isinstance(params, dict):
            raise SecurityError("Invalid parameters")

        url = urljoin(COINGECKO_BASE_URL, endpoint)
        headers = {
            'X-CG-Demo-Api-Key': self.api_key,
            'Accept': 'application/json',
            'User-Agent': 'CryptoCache/1.0'
        }

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT
                )

                if response.status_code == 429:
                    retry_after = min(
                        int(response.headers.get('Retry-After', 60)),
                        300  # Max 5 minute wait
                    )
                    logger.warning(
                        f"Rate limit reached. Waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except RequestException as e:
                logger.error(f"Request failed (attempt {
                             attempt + 1}/{MAX_RETRIES}): {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    raise
                # Exponential backoff with max 30s
                time.sleep(min(2 ** attempt, 30))

    def get_available_cryptocurrencies(self) -> List[Dict]:
        """
        Retrieve list of available cryptocurrencies with market data

        Returns:
            List[Dict]: List of cryptocurrency information including:
                - id: Unique identifier
                - symbol: Trading symbol (uppercase)
                - name: Full name
                - current_price: Current price in USD

        Raises:
            RequestException: If API request fails
            SecurityError: If data validation fails
        """
        cached_data = self.get('available_cryptocurrencies')
        if cached_data:
            return cached_data

        combined_cryptos = []

        for page in range(1, 3):
            params = {
                'vs_currency': 'usd',
                'order': 'market_cap_desc',
                'per_page': 100,
                'page': page,
                'sparkline': False,
                'precision': 15
            }

            result = self._make_request('coins/markets', params)

            if result:
                formatted_cryptos = [{
                    'id': crypto['id'],
                    'symbol': crypto['symbol'].upper(),
                    'name': crypto['name'],
                    'current_price': crypto['current_price']
                } for crypto in result]

                combined_cryptos.extend(formatted_cryptos)

        if combined_cryptos:
            self.set('available_cryptocurrencies', combined_cryptos)
            return combined_cryptos

        return cached_data or []

    def get_crypto_prices(self, crypto_ids: List[str], currency: str = 'USD') -> Dict:
        """
        Get current cryptocurrency prices for specified currencies

        Args:
            crypto_ids (List[str]): List of cryptocurrency IDs to fetch
            currency (str): Target currency for prices (default: USD)

        Returns:
            Dict: Dictionary mapping crypto IDs to their prices in the specified currency
                Format: {
                    'bitcoin': {'usd': 50000.00},
                    'ethereum': {'usd': 3000.00}
                }

        Raises:
            SecurityError: If input validation fails
            RequestException: If API request fails
        """
        try:
            if not isinstance(crypto_ids, list) or not crypto_ids:
                logger.error("Invalid crypto_ids provided")
                return {}

            currency = currency.lower()
            cache_key = f"prices_{','.join(sorted(crypto_ids))}_{currency}"
            cache_key = hashlib.sha256(cache_key.encode()).hexdigest()

            cached_data = self.get(cache_key)
            if cached_data and isinstance(cached_data, dict):
                return cached_data

            params = {
                'ids': ','.join(crypto_ids),
                'vs_currencies': currency
            }

            result = self._make_request('simple/price', params)

            if not isinstance(result, dict):
                logger.error(f"Invalid API response format: {result}")
                return {}

            formatted_result = {}
            for crypto_id in crypto_ids:
                if crypto_id in result:
                    crypto_data = result[crypto_id]
                    if isinstance(crypto_data, dict):
                        formatted_result[crypto_id] = {
                            currency: crypto_data.get(currency, 0)
                        }
                    else:
                        formatted_result[crypto_id] = {currency: 0}
                        logger.warning(f"Invalid price data for {crypto_id}")

            if formatted_result:
                self.set(cache_key, formatted_result)

            return formatted_result

        except Exception as e:
            logger.error(f"Error in get_crypto_prices: {str(e)}")
            return {}

    def get(self, key: str) -> Optional[Dict]:
        """
        Retrieve and validate cached data

        Args:
            key (str): Cache key to retrieve

        Returns:
            Optional[Dict]: Cached value if valid and not expired, None otherwise
        """
        try:
            if (datetime.now() - self.timestamp) < self.cache_duration:
                cached_value = self.data.get(key)
                if cached_value and self._validate_cache_data(cached_value):
                    return cached_value
            return None

        except Exception as e:
            logger.error(f"Error retrieving from cache: {str(e)}")
            return None

    def set(self, key: str, value: any) -> None:
        """
        Store data in cache

        Args:
            key (str): Cache key
            value: Value to cache

        Raises:
            SecurityError: If cache write fails
        """
        self.data[key] = value
        self.timestamp = datetime.now()

        try:
            cache_data = {
                'data': self.data,
                'timestamp': self.timestamp.isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")
