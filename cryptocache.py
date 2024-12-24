from datetime import datetime, time, timedelta
import json
import os
from pathlib import Path
from dotenv import load_dotenv
import requests
from requests.exceptions import RequestException
import logging
from typing import List, Dict, Optional
import hashlib
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Constants
CACHE_DIR = Path("cache")
COINGECKO_BASE_URL = "https://api.coingecko.com/api/v3/"
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3


class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass


def initialize_environment():
    """
    Initialize and validate environment variables
    Returns dict with configuration or raises error if required variables are missing
    """
    # Load environment variables
    load_dotenv()

    # Required variables
    required_vars = ['COINGECKO_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        raise EnvironmentError(
            f"Missing required environment variables: {
                ', '.join(missing_vars)}\n"
            f"Please check your .env file and ensure all required variables are set."
        )

    # Optional variables with defaults
    config = {
        'CACHE_DURATION': int(os.getenv('CACHE_DURATION', 30)),
        'COINGECKO_API_KEY': os.getenv('COINGECKO_API_KEY')
    }

    return config


# Carica le variabili d'ambiente dal file .env


class CryptoCache:
    def __init__(self):
        """
        Initialize CryptoCache with environment variables
        """
        try:
            # Get configuration from environment
            config = initialize_environment()

            # Initialize with configuration
            self.api_key = config['COINGECKO_API_KEY']
            self.cache_duration = config['CACHE_DURATION']

            # Set up cache directory and load cache
            self.cache_dir = Path("cache")
            self._secure_cache_directory()
            self.cache_file = self.cache_dir / "crypto_cache.json"
            self.cache_duration = timedelta(minutes=self.cache_duration)
            self._load_cache()

            logger.info("CryptoCache initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize CryptoCache: {e}")
            raise

    def _secure_cache_directory(self) -> None:
        """
        Assicura che la directory della cache esista
        """
        try:
            # Crea la directory se non esiste
            if not self.cache_dir.exists():
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Directory della cache creata con successo")
        except Exception as e:
            logger.error(
                f"Impossibile creare la directory della cache: {str(e)}")
            raise

    def _load_cache(self) -> None:
        """
        Carica i dati dalla cache se il file esiste,
        altrimenti inizializza una nuova cache vuota
        """
        try:
            if self.cache_file.exists():
                # Se il file esiste, leggi i dati
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.data = cache_data.get('data', {})
                    self.timestamp = datetime.fromisoformat(
                        cache_data.get('timestamp', '2000-01-01')
                    )
            else:
                # Se il file non esiste, crea una nuova cache vuota
                with open(self.cache_file, 'w') as f:
                    json.dump({
                        'data': {},
                        'timestamp': datetime.min.isoformat()
                    }, f)
                self.data = {}
                self.timestamp = datetime.min

            logger.info("Cache caricata con successo")
        except Exception as e:
            logger.error(f"Errore nel caricamento della cache: {e}")
            # In caso di errore, inizializza una cache vuota in memoria
            self.data = {}
            self.timestamp = datetime.min

    def _make_request(self, endpoint: str, params: Dict = None) -> Dict:
        """
        Make a secure API request with proper error handling and rate limiting

        Args:
            endpoint: API endpoint to call
            params: Query parameters for the request

        Returns:
            API response as dictionary
        """
        url = urljoin(COINGECKO_BASE_URL, endpoint)
        headers = {
            'X-CG-Demo-Api-Key': self.api_key,  # Corrected header name
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

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limit reached. Waiting {
                                   retry_after} seconds")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except RequestException as e:
                logger.error(f"Request failed (attempt {
                             attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff

    def get_available_cryptocurrencies(self) -> List[Dict]:
        """
        Get list of available cryptocurrencies from pages 1 and 2 with improved security and error handling.

        Returns:
            List of cryptocurrency information
        """
        cached_data = self.get('available_cryptocurrencies')
        if cached_data:
            return cached_data

        combined_cryptos = []

        for page in range(1, 3):  # Iterate through pages 1 and 2
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

                # Combine results from each page
                combined_cryptos.extend(formatted_cryptos)

        if combined_cryptos:
            self.set('available_cryptocurrencies', combined_cryptos)
            return combined_cryptos

        return cached_data or []

    def get_crypto_prices(self, crypto_ids: List[str], currency: str = 'USD') -> Dict:
        """
        Get current cryptocurrency prices with improved currency conversion and error handling

        Args:
            crypto_ids: List of cryptocurrency IDs
            currency: Target currency for prices (default: USD)

        Returns:
            Dictionary of cryptocurrency prices in requested currency
        """
        try:
            # Validate inputs
            if not isinstance(crypto_ids, list) or not crypto_ids:
                logger.error("Invalid crypto_ids provided")
                return {}

            currency = currency.lower()
            cache_key = f"prices_{','.join(sorted(crypto_ids))}_{currency}"
            cache_key = hashlib.sha256(cache_key.encode()).hexdigest()

            # Check cache first
            cached_data = self.get(cache_key)
            if cached_data and isinstance(cached_data, dict):
                return cached_data

            # Make API request
            params = {
                'ids': ','.join(crypto_ids),
                'vs_currencies': currency
            }

            result = self._make_request('simple/price', params)

            # Validate result structure
            if not isinstance(result, dict):
                logger.error(f"Invalid API response format: {result}")
                return {}

            # Process and format the result
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

            # Cache the formatted result
            if formatted_result:
                self.set(cache_key, formatted_result)

            return formatted_result

        except Exception as e:
            logger.error(f"Error in get_crypto_prices: {str(e)}")
            return {}

    def get_exchange_rate(self, from_currency: str = 'USD', to_currency: str = 'EUR') -> float:
        """
        Get exchange rate between two currencies with caching and validation

        Args:
            from_currency: Source currency code
            to_currency: Target currency code

        Returns:
            Exchange rate as float
        """
        # Rimuoviamo la decorazione @staticmethod e correggiamo la definizione
        try:
            cache_key = f"exchange_rate_{from_currency}_{to_currency}"
            cached_rate = self.get(cache_key)

            if cached_rate is not None and isinstance(cached_rate, (int, float)):
                return float(cached_rate)

            response = requests.get(
                f'https://api.exchangerate-api.com/v4/latest/{
                    from_currency.upper()}',
                timeout=DEFAULT_TIMEOUT
            )
            response.raise_for_status()
            rates = response.json()['rates']
            rate = float(rates.get(to_currency.upper(), 1.0))

            # Cache the exchange rate
            self.set(cache_key, rate)
            return rate

        except (RequestException, ValueError, KeyError) as e:
            logger.error(f"Exchange rate error: {e}")
            return 1.0

    def _validate_cache_data(self, data: any) -> bool:
        """
        Validate cached data structure

        Args:
            data: Data to validate

        Returns:
            bool: True if data is valid, False otherwise
        """
        if not isinstance(data, dict):
            return False

        for crypto_id, prices in data.items():
            if not isinstance(prices, dict):
                return False

            for currency, price in prices.items():
                if not isinstance(price, (int, float)):
                    return False

        return True

    def get(self, key: str) -> Optional[Dict]:
        """
        Get a value from the cache with validation

        Args:
            key: The cache key to retrieve

        Returns:
            The cached value if valid, None otherwise
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
        Set a value in the cache

        Args:
            key: The cache key
            value: The value to cache
        """
        self.data[key] = value
        self.timestamp = datetime.now()

        # Save to file
        try:
            cache_data = {
                'data': self.data,
                'timestamp': self.timestamp.isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def clear(self):
        """
        Clear all cached data and reset timestamp
        """
        self.data = {}
        self.timestamp = datetime.min

        # Clear the cache file
        try:
            cache_data = {
                'data': {},
                'timestamp': datetime.min.isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
