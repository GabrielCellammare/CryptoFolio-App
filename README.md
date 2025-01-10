## Documentazione API CryptoFolio

### Introduzione

CryptoFolio fornisce un'API RESTful che permette di gestire il proprio portfolio di criptovalute in modo programmatico. Questa documentazione descrive come utilizzare le API disponibili per interagire con il tuo portfolio.

### Autenticazione

Tutte le richieste API devono essere autenticate utilizzando un token JWT (JSON Web Token). Per ottenere il token:

1. Accedi alla dashboard di CryptoFolio
2. Vai alla sezione "API Access"
3. Clicca su "Generate New Token"

Il token ha una validità di 7 giorni e deve essere incluso nell'header `Authorization` di ogni richiesta nel seguente formato:

```
Authorization: Bearer il_tuo_token_jwt
```

### Endpoints Disponibili

#### Recuperare il Portfolio

**Endpoint**: `GET /api/v1/portfolio`

Questo endpoint restituisce l'elenco completo delle criptovalute nel tuo portfolio.

**Esempio di richiesta**:
```bash
curl -X GET \
  'https://api.cryptofolio.com/api/v1/portfolio' \
  -H 'Authorization: Bearer il_tuo_token_jwt'
```

**Esempio di risposta**:
```json
{
  "status": "success",
  "data": [
    {
      "crypto_id": "bitcoin",
      "symbol": "BTC",
      "amount": 0.5,
      "purchase_price": 45000,
      "purchase_date": "2025-01-15",
      "current_price": 48000,
      "current_value": 24000,
      "profit_loss": 1500,
      "profit_loss_percentage": 6.25
    },
    // altri elementi del portfolio...
  ],
  "total_value": 24000,
  "currency": "USD"
}
```

#### Aggiungere una Nuova Criptovaluta

**Endpoint**: `POST /api/v1/portfolio`

Questo endpoint permette di aggiungere una nuova criptovaluta al tuo portfolio.

**Parametri richiesti**:
- `crypto_id` (string): Identificativo della criptovaluta (es. "bitcoin")
- `symbol` (string): Simbolo della criptovaluta (es. "BTC")
- `amount` (number): Quantità acquistata
- `purchase_price` (number): Prezzo di acquisto in USD
- `purchase_date` (string): Data di acquisto in formato "YYYY-MM-DD"

**Esempio di richiesta**:
```bash
curl -X POST \
  'https://api.cryptofolio.com/api/v1/portfolio' \
  -H 'Authorization: Bearer il_tuo_token_jwt' \
  -H 'Content-Type: application/json' \
  -d '{
    "crypto_id": "bitcoin",
    "symbol": "BTC",
    "amount": 0.5,
    "purchase_price": 45000,
    "purchase_date": "2025-01-15"
}'
```

**Esempio di risposta**:
```json
{
  "status": "success",
  "message": "Cryptocurrency added successfully",
  "document_id": "abc123xyz"
}
```

### Limiti e Quote

Per garantire un servizio ottimale, sono in vigore i seguenti limiti:

- Massimo 100 richieste al minuto per ogni endpoint
- Massimo 2 token generabili al giorno
- Periodo di attesa di 12 ore tra una generazione di token e l'altra

### Gestione degli Errori

L'API utilizza i codici di stato HTTP standard e restituisce gli errori nel seguente formato:

```json
{
  "status": "error",
  "message": "Descrizione dell'errore"
}
```

Codici di stato comuni:
- `400`: Richiesta non valida (dati mancanti o formato errato)
- `401`: Token di autenticazione mancante o non valido
- `429`: Superato il limite di richieste
- `500`: Errore interno del server

### Consigli per la Sicurezza

1. Non condividere mai il tuo token JWT
2. Memorizza il token in modo sicuro (es. variabili d'ambiente)
3. Rigenera periodicamente il token per maggiore sicurezza
4. Non includere mai il token nel codice sorgente
5. Utilizza sempre HTTPS per le richieste

### FAQ

**D: Come posso sapere se il mio token sta per scadere?**

R: Il token include una data di scadenza che puoi verificare nella dashboard. Ti consigliamo di rinnovare il token qualche giorno prima della scadenza per evitare interruzioni del servizio.

**D: Cosa succede se supero il limite di richieste?**

R: Riceverai un errore 429 con un header `Retry-After` che indica dopo quanti secondi potrai riprovare.

**D: È possibile utilizzare valute diverse da USD?**

R: Al momento i prezzi sono forniti solo in USD. La conversione in altre valute deve essere gestita lato client. È necessario cambiare la valuta dalla dashboard per poter ricevere il controvalore correttamente attraverso l'Api.
