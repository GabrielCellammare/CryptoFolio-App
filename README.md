## Documentazione API CryptoFolio

### Introduzione

**CryptoFolio** fornisce un'API RESTful che permette di gestire il proprio portfolio di criptovalute in modo programmatico e sicuro. Questa documentazione descrive come utilizzare le API disponibili per interagire con il tuo portfolio.

### Autenticazione

Tutte le richieste API devono essere autenticate utilizzando un token JWT (JSON Web Token). Per ottenere il token:

1. Accedi alla dashboard di CryptoFolio
2. Vai alla sezione "API Access"
3. Clicca su "Generate New Token"

Il token ha una validità di 7 giorni e deve essere incluso nell'header `Authorization` di ogni richiesta nel seguente formato:

***RICORDA***: Se pensi che qualcuno sia venuto a conoscenza del tuo token JWT, potrai rinnovarlo nelle 12 ore immediatamente successive alla generazione, accedendo alla tua dashboard. Il token precedentemente generato verrà correttamente invalidato dal sistema.

```
Authorization: Bearer il_tuo_token_jwt
```

#### Perchè Authorization: Bearer?

Secondo *RFC6750* The OAuth 2.0 Authorization Framework Il Bearer Token è un token di sicurezza che soltanto le parti autorizzati possono utilizzare, da qui il nome ***Bearer**, ovvero un possessore. Lato server, questo Token è prodotto attraverso lo standard JWT.

L'aggiunta del termine “Bearer” prima del token nell'intestazione “Authorization” ha due scopi importanti:

1. **Identificazione**: La parola chiave “Bearer” aiuta il server a identificare facilmente il tipo di token utilizzato e a gestirlo in modo appropriato durante i processi di autenticazione e autorizzazione. 
2. **Standardizzazione**: L'uso dello schema “Bearer” è una convenzione ampiamente adottata e una pratica raccomandata per chiarezza e standardizzazione. Promuove l'interoperabilità tra i diversi sistemi e componenti coinvolti nel flusso di autenticazione, riducendo le possibilità di interpretazioni o comunicazioni errate.

##### È necessario allegare il termine *Bearer*?

Sebbene tecnicamente sia possibile eseguire l'autenticazione senza includere esplicitamente la parola chiave “Bearer”, si raccomanda vivamente di includerla per un'autenticazione corretta utilizzando lo schema del token Bearer. L'aggiunta di “Bearer” prima del token garantisce chiarezza, coerenza e compatibilità tra le diverse implementazioni e i diversi sistemi.

Quando il server riceve una richiesta HTTP con l'intestazione “Authorization”, controlla la presenza della parola chiave “Bearer” per determinare lo schema di autenticazione utilizzato. Senza la parola chiave “Bearer”, il server potrebbe non riconoscere il token come token Bearer e potrebbe non riuscire ad autenticare o autorizzare correttamente la richiesta.

Pertanto, è importante includere sempre la parola chiave “Bearer” prima dell'operazione.

##### JWT
Lo standard JWT rappresenta semplicemente un formato di serializzazione di informazioni (claim), espressi in **JSON** (*JavaScript Object Notation*).

Ogni JWT è composto (a parte casi particolari) da tre parti, codificate in base64:

1. Header
2. Payload
3. Signature

Per il calcolo della firma, è stato utilizzato *HS256* algoritmo simmetrico, nel quale la stessa chiave è usata per generare e validare la firma.

##### Differenze tra Authorization Bearer Token e JSON Web Token
Quindi è bene specificare che i **Bearer Token** sono un tipo particolare di Access Token, usati per ottenere l'autorizzazione ad accedere ad una risorsa protetta da un Authorization Server, mentre il JWT è un formato di serializzazione.

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

#### Esempi di Test


##### Test 1: Aggiunta valida
```json

{
    "crypto_id": "bitcoin",
    "symbol": "BTC",
    "amount": 0.5,
    "purchase_price": 42000.00,
    "purchase_date": "2024-01-15"
}
```
##### Test 2: Campi mancanti
```json

{
    "crypto_id": "ethereum",
    "symbol": "ETH",
    "amount": 2.0
    // Error
}
```

##### Test 3: Valori numerici invalidi

```json
{
    "crypto_id": "ripple",
    "symbol": "XRP", 
    "amount": "invalid",
    "purchase_price": -100,
    "purchase_date": "2024-01-15"
    // Error
}
```

##### Test 4: Data invalida
```json
{
    "crypto_id": "cardano",
    "symbol": "ADA",
    "amount": 1000,
    "purchase_price": 0.50,
    "purchase_date": "invalid-date"
    // Error
}
```
##### Test 5: Caratteri speciali
```json
{
    "crypto_id": "dogecoin<script>",
    "symbol": "DOGE';--",
    "amount": 1000,
    "purchase_price": 0.10,
    "purchase_date": "2024-01-15"
    // Error
}
```

### Limiti e Quote

Per garantire un servizio ottimale, sono in vigore i seguenti limiti:

- Massimo 100 richieste all'ora condivise tra i due EndPoint
- Massimo 2 token generabili al giorno
- Periodo di attesa di 12 ore tra una generazione di token e l'altra
- Validità di 7 giorni per ogni Token

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

## Fonti

 - [Bearer Token](https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly)
 - [JWT e Bearer Token](https://www.linkedin.com/pulse/jwt-e-bearer-token-facciamo-chiarezza-guido-spadotto/)