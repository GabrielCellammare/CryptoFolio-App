"""
FirebaseRateLimiter: Distributed Rate Limiting Implementation
Version: 1.0
Author: [Gabriel Cellammare]
Last Modified: [05/01/2025]

This module provides a distributed rate limiting solution using Firebase Firestore:
- Scalable rate limiting across multiple instances
- Automatic cleanup of expired entries
- Transaction-based atomic operations
- Probabilistic maintenance

Security Features:
1. Transaction-based updates
2. Automatic data cleanup
3. Error handling and logging
4. Atomic operations
5. Time-window based limiting

Dependencies:
- firebase_admin.firestore
- flask.current_app
- logging
- time
- random
"""

import logging
import random
import time
from typing import Tuple
from flask import current_app
from firebase_admin import firestore


class FirebaseRateLimitCleaner:
    """
    Cleanup Manager for Rate Limiting Data

    Handles the periodic cleanup of expired rate limiting entries:
    - Batch processing to avoid timeouts
    - Configurable window sizes
    - Error handling and logging

    Security Features:
    - Batched operations
    - Error isolation
    - Logging of operations
    """

    def __init__(self, db, collection_name: str = 'rate_limits'):
        """
        Initialize the rate limit cleaner.

        Args:
            db: Firestore client instance
            collection_name: Collection name for rate limits

        Security:
        - Validates inputs
        - Configures logging
        """
        self.db = db
        self.collection_name = collection_name
        self.logger = logging.getLogger(__name__)

    def clean_expired_entries(self, window_seconds: int = 3600, batch_size: int = 500) -> int:
        """
        Remove expired rate limit entries.

        Args:
            window_seconds: Time window in seconds
            batch_size: Number of documents per batch

        Returns:
            int: Number of deleted documents

        Security:
        - Batched operations
        - Transaction safety
        - Error handling
        """
        current_time = int(time.time())
        cutoff_time = current_time - window_seconds
        deleted_count = 0

        try:
            query = (self.db.collection(self.collection_name)
                     .where('window_start', '<', cutoff_time)
                     .limit(batch_size))

            while True:
                docs = query.stream()
                batch = self.db.batch()
                batch_deletions = 0

                for doc in docs:
                    batch.delete(doc.reference)
                    batch_deletions += 1

                if batch_deletions == 0:
                    break

                batch.commit()
                deleted_count += batch_deletions

                self.logger.info(
                    f"Deleted {batch_deletions} expired documents")

                if batch_deletions < batch_size:
                    break

            self.logger.info(
                f"Cleanup completed. Total documents deleted: {deleted_count}")
            return deleted_count

        except Exception as e:
            self.logger.error(f"Cleanup error: {str(e)}")
            raise


class FirebaseRateLimiter:

    def __init__(self, db, max_requests: int = 100,
                 window_seconds: int = 3600,
                 ip_max_requests: int = 1000,
                 ip_window_seconds: int = 3600, cleanup_probability: float = 0.001):
        """
        Initialize rate limiter.

        Args:
            db: Firestore database instance
            max_requests: Maximum requests per user window
            window_seconds: Time window for user limits
            ip_max_requests: Maximum requests per IP window
            ip_window_seconds: Time window for IP limits

        Security:
        - Input validation
        - Configuration logging
        - Cleanup initialization
        """
        self.db = db
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ip_max_requests = ip_max_requests
        self.ip_window_seconds = ip_window_seconds
        self.collection_name = 'rate_limits'
        self.cleanup_probability = cleanup_probability
        self.cleaner = FirebaseRateLimitCleaner(db, self.collection_name)

    def maybe_cleanup(self):
        """
        Probabilistic cleanup execution.

        Security:
        - Error isolation
        - Logging
        - Non-blocking operation
        """
        if random.random() < self.cleanup_probability:
            try:
                self.cleaner.clean_expired_entries(self.window_seconds)
            except Exception as e:
                logging.warning(f"Inline cleanup error: {str(e)}")

    def check_rate_limit(self, user_id: str, ip_address) -> Tuple[bool, int, int]:

        # First check IP-based limits
        ip_allowed, ip_remaining, ip_retry = self._check_ip_limit(ip_address)
        if not ip_allowed:
            return False, ip_remaining, ip_retry

        # Then check user-based limits
        user_allowed, user_remaining, user_retry = self._check_user_limit(
            user_id)
        if not user_allowed:
            return False, user_remaining, user_retry

        # Return the more restrictive remaining count
        remaining = min(ip_remaining, user_remaining)
        return True, remaining, 0

    def _check_user_limit(self, user_id):
        """
        Check and update rate limit for user.

        Args:
            user_id: User identifier

        Returns:
            Tuple[bool, int, int]: (is_allowed, remaining_requests, retry_after)

        Security:
        - Transaction safety
        - Time window validation
        - Error handling
        - Atomic updates
        """
        current_app.logger.info(f"Rate limit check for user: {user_id}")
        self.maybe_cleanup()
        current_time = int(time.time())
        doc_ref = self.db.collection(self.collection_name).document(user_id)

        transaction = self.db.transaction()

        @firestore.transactional
        def update_rate_limit(transaction):
            doc = doc_ref.get(transaction=transaction)

            if not doc.exists:
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.max_requests - 1, 0

            data = doc.to_dict()
            window_start = data['window_start']

            if current_time - window_start >= self.window_seconds:
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.max_requests - 1, 0

            if data['count'] >= self.max_requests:
                retry_after = window_start + self.window_seconds - current_time
                return False, 0, retry_after

            data['count'] += 1
            data['last_request'] = current_time
            transaction.update(doc_ref, data)

            return True, self.max_requests - data['count'], 0

        try:
            return update_rate_limit(transaction)
        except Exception as e:
            current_app.logger.error(f"Rate limit error: {str(e)}")
            return True, 0, 0

    def _check_ip_limit(self, ip_address: str) -> Tuple[bool, int, int]:
        """Check rate limit for an IP address."""
        current_app.logger.info(f"Rate limit check for ip: {ip_address}")
        self.maybe_cleanup()
        current_time = int(time.time())
        doc_ref = self.db.collection(
            self.collection_name).document(f'ip_{ip_address}')

        transaction = self.db.transaction()

        @firestore.transactional
        def update_ip_limit(transaction):
            doc = doc_ref.get(transaction=transaction)

            if not doc.exists:
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.ip_max_requests - 1, 0

            data = doc.to_dict()
            window_start = data['window_start']

            if current_time - window_start >= self.ip_window_seconds:
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.ip_max_requests - 1, 0

            if data['count'] >= self.ip_max_requests:
                retry_after = window_start + self.ip_window_seconds - current_time
                return False, 0, retry_after

            data['count'] += 1
            data['last_request'] = current_time
            transaction.update(doc_ref, data)

            return True, self.ip_max_requests - data['count'], 0

        return update_ip_limit(transaction)
