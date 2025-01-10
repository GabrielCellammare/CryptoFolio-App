# **CryptoFolio**: Tieni traccia delle tue criptovalute in modo semplice e sicuro

### SAOS 2024-2025: Caso di studio della materia di **Sicurezza delle Architetture Orientate ai Servizi** - Prof. Giulio Mallardi
### Laurea Magistrale in Sicurezza informatica - Università degli studi di Bari "Aldo Moro" - Dipartimento d'Informatica

### Author

- [@GabrielCellammare](https://github.com/GabrielCellammare)

**CryptoFolio** è un'applicazione web incentrata sulla sicurezza, progettata per aiutare gli utenti a tenere traccia e a gestire i loro investimenti in criptovalute, con particolare attenzione alla protezione dei dati e all'autenticazione sicura. Basato su **Flask** , con le moderne politiche di sicurezza offre un robusto set di funzionalità mantenendo rigorosi controlli di sicurezza.

## Caratteristiche principali
L'**applicazione** consente agli utenti di:

1. Tracciare le proprie **criptovalute** e i loro valori di mercato attuali
2. Monitorare le prestazioni del **portfolio** e le metriche di profitto/perdita
3. *Aggiungere, aggiornare e rimuovere* posizioni in **criptovalute**
4. Visualizzare le **analisi** del portfolio
5. Accedere ai prezzi delle criptovalute in tempo reale grazie all'integrazione delle API di [CoinGecko](https://www.coingecko.com/ "CoinGecko")
6. Gestire il **portfolio** in modo sicuro attraverso l'autenticazione **OAuth 2.0**
7. Interagire con il proprio portfolio attraverso **un'API Restful** 
8. Ottenere il **controvalore** del proprio portfolio in diverse valute sfrutando i tassi di conversione aggiornati in tempo reale 

## Architettura tecnica

L'architettura del sistema si presenta in tale modo
Anteprima ![image](https://github.com/user-attachments/assets/b5db5d12-471b-4d9f-9635-99695da2baed)
![image](https://github.com/user-attachments/assets/3f4d84c8-67d6-4df0-8e72-9aa4853f23a3)

Link all'architettura completa: [CryptoFolio(Project).pdf](https://github.com/user-attachments/files/18382420/CryptoFolio.Project.pdf)


## Route

### Autenticazione e sicurezza

1. Integrazione OAuth 2.0 con Google e GitHub per l'autenticazione sicura degli utenti
2. Autenticazione API basata su JWT per l'accesso programmatico
3. Protezione CSRF con convalida di token e nonce
4. Limitazione della velocità e strozzatura delle richieste
5. Crittografia AES-256 per l'archiviazione di dati sensibili
6. Convalida e sanitizzazione complete dell'input
7. Gestione sicura delle sessioni con timeout automatico
8. Operazioni di memoria protette per i dati sensibili

## Integrazioni esterne

1. CoinGecko API per i dati di prezzo delle criptovalute in tempo reale
2. Firebase/Firestore per la persistenza sicura dei dati
3. Google OAuth per l'autenticazione
4. GitHub OAuth per l'autenticazione

## Protezione dei dati
Tutti i dati sensibili dell'utente vengono crittografati utilizzando la crittografia AES-256 prima della memorizzazione, con meccanismi di derivazione della chiave e di salatura adeguati. L'applicazione implementa un approccio di difesa in profondità con più livelli di sicurezza:

sicurezza del livello di trasporto (TLS) per tutte le comunicazioni
Gestione sicura dei token con rotazione automatica
endpoint API protetti con controlli di accesso adeguati
Registrazione di audit per gli eventi rilevanti per la sicurezza
Gestione sicura degli errori per prevenire la perdita di informazioni

## Caratteristiche del frontend

Valutazione del portafoglio in tempo reale
Grafici e analisi interattivi
Design reattivo con Bootstrap
Supporto per la conversione di valuta
Gestione sicura dei moduli


L'applicazione segue le moderne best practice di sicurezza e include un'ampia protezione contro le vulnerabilità web più comuni come XSS, CSRF, SQL injection e vari vettori di attacco specifici per le API. Fornisce una piattaforma sicura per la gestione del portafoglio di criptovalute, mantenendo elevati standard di protezione dei dati degli utenti.
Tutte queste funzionalità sono implementate con una forte attenzione alla sicurezza, seguendo il principio della difesa in profondità e incorporando più livelli di protezione per garantire che i dati degli utenti rimangano al sicuro durante tutte le operazioni.

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


## Installation

Install my-project with npm

```bash
  npm install my-project
  cd my-project
```


## Deployment

To deploy this project run

```bash
  npm run deploy
```

## Documentation

[Documentation](https://linktodocumentation)


## Fonti

 - [Bearer Token](https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly)
 - [JWT e Bearer Token](https://www.linkedin.com/pulse/jwt-e-bearer-token-facciamo-chiarezza-guido-spadotto/)

