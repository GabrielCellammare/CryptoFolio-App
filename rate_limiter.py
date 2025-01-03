import logging
import random
import time
from typing import Tuple
from flask import current_app
from firebase_admin import firestore


class FirebaseRateLimitCleaner:
    def __init__(self, db, collection_name: str = 'rate_limits'):
        """
        Inizializza il sistema di pulizia dei rate limits

        Args:
            db: Istanza del client Firestore
            collection_name: Nome della collezione dei rate limits
        """
        self.db = db
        self.collection_name = collection_name
        self.logger = logging.getLogger(__name__)

    def clean_expired_entries(self, window_seconds: int = 3600, batch_size: int = 500) -> int:
        """
        Rimuove le entries di rate limiting scadute in batch per evitare timeout

        Args:
            window_seconds: Durata della finestra temporale in secondi
            batch_size: Numero di documenti da processare per batch

        Returns:
            int: Numero di documenti eliminati
        """
        current_time = int(time.time())
        cutoff_time = current_time - window_seconds
        deleted_count = 0

        try:
            # Query per trovare i documenti scaduti
            query = (self.db.collection(self.collection_name)
                     .where('window_start', '<', cutoff_time)
                     .limit(batch_size))

            while True:
                # Ottieni il batch corrente di documenti
                docs = query.stream()
                batch = self.db.batch()

                # Contatore per questo batch
                batch_deletions = 0

                # Aggiungi le operazioni di delete al batch
                for doc in docs:
                    batch.delete(doc.reference)
                    batch_deletions += 1

                # Se non ci sono documenti da eliminare, esci
                if batch_deletions == 0:
                    break

                # Esegui il batch di eliminazioni
                batch.commit()
                deleted_count += batch_deletions

                self.logger.info(
                    f"Eliminati {batch_deletions} documenti scaduti")

                # Se abbiamo eliminato meno documenti del batch_size, abbiamo finito
                if batch_deletions < batch_size:
                    break

            self.logger.info(
                f"Pulizia completata. Totale documenti eliminati: {deleted_count}")
            return deleted_count

        except Exception as e:
            self.logger.error(f"Errore durante la pulizia: {str(e)}")
            raise


def setup_periodic_cleanup(project_id: str):
    """
    Setup di una Cloud Function per la pulizia periodica
    Questa funzione può essere deployata come Cloud Function schedulata
    """
    db = firestore.Client(project_id)
    cleaner = FirebaseRateLimitCleaner(db)

    def cleanup_function(event, context):
        """
        Cloud Function per eseguire la pulizia
        Può essere schedulata usando Cloud Scheduler
        """
        try:
            deleted_count = cleaner.clean_expired_entries()
            return f"Pulizia completata con successo. Eliminati {deleted_count} documenti."
        except Exception as e:
            logging.error(f"Errore nella pulizia schedulata: {str(e)}")
            raise

    return cleanup_function


class FirebaseRateLimiter:
    def __init__(self, db, max_requests: int = 100,
                 window_seconds: int = 3600, cleanup_probability: float = 0.001):
        """
        Inizializza il rate limiter basato su Firebase

        Args:
            db: Istanza del client Firestore
            max_requests: Numero massimo di richieste nella finestra temporale
            window_seconds: Durata della finestra temporale in secondi
        """
        self.db = db
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.collection_name = 'rate_limits'
        self.cleanup_probability = cleanup_probability
        self.cleaner = FirebaseRateLimitCleaner(db, self.collection_name)

    def maybe_cleanup(self):
        """Esegue la pulizia con una certa probabilità"""
        if random.random() < self.cleanup_probability:
            try:
                self.cleaner.clean_expired_entries(self.window_seconds)
            except Exception as e:
                logging.warning(f"Errore durante la pulizia inline: {str(e)}")
                # Non propaghiamo l'errore per non interrompere il rate limiting

    def check_rate_limit(self, user_id: str) -> Tuple[bool, int, int]:
        """
        Verifica e aggiorna il rate limit per un utente usando Firestore

        Returns:
            Tuple[bool, int, int]: (is_allowed, remaining_requests, retry_after)
        """
        current_app.logger.info(f"Attempting to rate limit user: {user_id}")
        self.maybe_cleanup()
        current_time = int(time.time())
        doc_ref = self.db.collection(self.collection_name).document(user_id)

        transaction = self.db.transaction()
        # Usiamo una transazione per garantire l'atomicità delle operazioni

        @firestore.transactional
        def update_rate_limit(transaction):
            doc = doc_ref.get(transaction=transaction)

            if not doc.exists:
                # Prima richiesta dell'utente
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.max_requests - 1, 0

            data = doc.to_dict()
            window_start = data['window_start']

            # Verifica se la finestra temporale è scaduta
            if current_time - window_start >= self.window_seconds:
                # Reset del contatore per una nuova finestra
                data = {
                    'count': 1,
                    'window_start': current_time,
                    'last_request': current_time
                }
                transaction.set(doc_ref, data)
                return True, self.max_requests - 1, 0

            # Verifica se il limite è stato superato
            if data['count'] >= self.max_requests:
                retry_after = window_start + self.window_seconds - current_time
                return False, 0, retry_after

            # Incrementa il contatore
            data['count'] += 1
            data['last_request'] = current_time
            transaction.update(doc_ref, data)

            return True, self.max_requests - data['count'], 0

        # Esegui la transazione
        try:
            return update_rate_limit(transaction)
        except Exception as e:
            current_app.logger.error(f"Rate limit error: {str(e)}")
            # In caso di errore, permettiamo la richiesta per evitare interruzioni del servizio
            return True, 0, 0
