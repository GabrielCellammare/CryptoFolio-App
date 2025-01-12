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

## CryptoFolio: Architettura del sistema
**CryptoFolio** implementa un modello di "**architettura orientata ai servizi (SOA)**", in particolare un approccio simile ai **microservizi**, in cui i diversi componenti hanno un basso accoppiamento ed un'alta coesione, comunicando attraverso interfacce ben definite (***API REST***). 

Questa scelta architettonica offre diversi vantaggi:

- **Indipendenza dai servizi**: Ogni componente (autenticazione, gestione del portafoglio...) opera in modo indipendente
- **Scalabilità**: I servizi possono essere scalati in modo indipendente in base al carico
- **Isolamento della sicurezza:** La compromissione di un servizio non compromette automaticamente gli altri
- **Flessibilità tecnologica**: Servizi diversi possono utilizzare tecnologie diverse a seconda delle necessità

### Componenti principali
#### Architettura del Backend - Flask
![image](https://github.com/user-attachments/assets/08e8ffc2-91c8-4eb7-9be2-9e5e014ae562)

Flask è un framework di sviluppo web open-source scritto in Python. È stato progettato per essere un framework minimalista, flessibile e facile da utilizzare per la creazione di applicazioni web. L'utilizzo di Flask non è casuale, poichè consente lo sviluppo di **API** (_Interfacce di Programmazione delle Applicazioni_) attraverso la creazione di **endpoint** e percorsi per elaborare richieste e risposte **HTTP**.

Le caratteristiche **principali** includono:

- Nucleo minimalista e flessibile
- Ampio supporto per i plugin
- Server di sviluppo integrato
- Integrazione del toolkit Werkzeug per le funzionalità WSGI

  Il Web Server Gateway Interface (WSGI) è un protocollo di trasmissione che stabilisce e descrive comunicazioni ed interazioni tra server ed applicazioni web scritte nel linguaggio Python. È quindi 			l'interfaccia standard del web service per la programmazione in Python.

In CryptoFolio, **Flask** gestisce:

1. Instradamento ed elaborazione delle richieste
2. Gestione delle sessioni
3. Rendering dei modelli
4. Integrazione del middleware di sicurezza
5. Implementazione di endpoint API
6. Configurazione iniziale del Server
7. Meccanismi di sicurezza

#### Architettura del frontend

![image](https://github.com/user-attachments/assets/cce6530a-d59a-4203-a046-e5a27f7c5799)

Il **frontend** utilizza uno stack moderno incentrato su _sicurezza e prestazioni_:

1. **HTML5/CSS3**: markup semantico e stile reattivo
2. **JavaScript (ES6+)**: Funzionalità lato client con modelli sicuri
3. **Bootstrap 5**: framework di design reattivo
4. **Select2**: Caselle di selezione migliorate
5. **Chart.js**: Visualizzazione grafica del portafoglio
6. **jQuery**: Manipolazione del DOM e richieste AJAX

La tecnologia utilizzata ha permesso l'Implementazione di **CSP** (_Content Security Policy_) e quindi di conseguenza misure di prevenzione **XSS**, gestione dei token **CSRF** attraverso cookie sicuri, sanificazione degli **input** e una corretta gestione degli **errori** per evitare **IOE** (_Information over exposure_).

#### Architteura di archiviazione - Firebase Cloud Firestore

![image](https://github.com/user-attachments/assets/06459b7f-a2e6-4407-9a6c-1c9d711dddc6)


**Firebase Cloud Firestore** è un cloud NoSQL flessibile e scalabile, costruito sull'infrastruttura di Google Cloud, per archiviare e sincronizzare i dati per lo sviluppo lato client e lato server.
Firebase fornisce una soluzione di database sicura e scalabile con:

1. Sincronizzazione dei dati in tempo reale
2. Integrazione dell'autenticazione integrata
3. Scalabilità automatica
4. Regole di accesso sicuro ai dati
5. Backup e disaster recovery
6. Archiviazione crittografata dei dati

#### Architettura di sicurezza - Servizi di sicurezza

![image](https://github.com/user-attachments/assets/09c547e3-9a28-40be-8979-a0933ea177f7)

Sono state implementate  - _attraverso API debitamente protette_ - diversi servizi di sicurezza che lavorano sinergicamente per proteggere l'applicazione:

	Servizio di autenticazione
		Integrazione OAuth 2.0 (Google/GitHub)
		Gestione dei token JWT
		Gestione delle sessioni
		Gestione dell'identità dell'utente
    	Gestione delle origini 
    	Controllo Cookie e Headers

	Servizio di crittografia
		Crittografia AES-256
    	Hashing con HMAC
		Gestione delle chiavi
		Archiviazione sicura dei dati
		Crittografia dei token
		
	Servizio di limitazione
		Limitazione delle richieste
		Protezione DDoS
		Monitoraggio dell'utilizzo
		
	Servizio di protezione CSRF
		Generazione di token
		Convalida delle richieste
		Gestione nonce

#### Integrazioni esterne

Il sistema per offrire le funzionalità core dello stesso, integra diversi servizi esterni attraverso API RestFul messe a disposizione. Nel caso specifico dei prezzi crypto - per garantire disponibilità del dato agli utenti - è stato implementato un meccanismo di caching interno che possa aggirare la problematica della "_sincronia_" delle API RestFul, ovvero una delle caratteristiche principali dei Servizi Rest. Se Coincegko non dovesse essere disponibile, l'utente potrà in egual modo accedere ai prezzi delle crypto grazie a tale sistema.

**API CoinGecko**

![image](https://github.com/user-attachments/assets/ba036108-ff54-4761-b664-936d650d850d)


- Prezzi delle criptovalute in tempo reale
- Dati di mercato
- Informazioni sulle attività


**Fornitori OAuth**

![image](https://github.com/user-attachments/assets/2bc53069-9ec8-446a-8ce9-9b3d2559b77f)


- Servizio OAuth di Google
- Servizio GitHub OAuth


**Ngrok**

![image](https://github.com/user-attachments/assets/71bce232-ab88-4b58-ab9a-0ce72f623839)


- Tunnel sicuro per lo sviluppo locale
- Crittografia TLS e utilizzo del protocollo HTTPS
- Gestione degli URL

### Flusso di comunicazione
Il flusso di comunicazione del sistema segue diversi schemi chiave:

**Comunicazione utente-frontend**

- Connessioni protette da HTTPS
- Invio di moduli
- Richieste AJAX


**Comunicazione Frontend-Backend**

- Chiamate API REST
- Autenticazione JWT
- Convalida dei token CSRF
- Richieste imitate


**Comunicazione Backend-Servizi esterni**

- Chiamate API a CoinGecko
- Operazioni sul database Firebase
- Interazioni con il provider OAuth
- Gestione del tunnel Ngrok (sviluppo)
- Comunicazione con i servizi interni
- Autenticazione da servizio a servizio
- Trasferimento di dati criptati


### Sicurezza del flusso di dati
In tutto il sistema, i dati sono protetti da:

**Sicurezza del trasporto**

- Crittografia TLS 1.3
- Convalida del certificato
- Applicazione del protocollo sicuro


**Sicurezza dell'archiviazione dei dati**

- Crittografia AES-256 
- Gestione sicura delle chiavi
- Generazione e rotazione del sale


**Sicurezza delle richieste**
- Convalida dell'ingresso
- Sanificazione dell'input e output
- Limitazione delle richieste
- Protezione CSRF



![Flow](https://github.com/user-attachments/assets/7dcbabfd-b252-4dca-a053-bf24b090d96e)


### Architettura completa

Le comunicazioni avvengono tutte attraverso le cosìddette **Routes**, messe a disposizione di Flask. Ogni route rappresenta quindi un endpoint accessibile attraverso un' API Restful con un livello di protezione adeguato alla route specifica.

![image](https://github.com/user-attachments/assets/61bc6261-656f-4db3-a45d-3da4e308fee7)
![image](https://github.com/user-attachments/assets/96d68f16-01d9-4012-ae57-8af8d503b62b)




Link all'architettura completa: 
[CryptoFolio(Project).pdf](https://github.com/user-attachments/files/18385195/CryptoFolio.Project.pdf)


## Routes

Questa parte del documento illustra tutti i percorsi implementati nell'applicazione CryptoFolio, comprese le misure di sicurezza, i controlli di accesso e le funzionalità.

### Routes di autenticazione

#### /auth/login/provider



```
   /auth/login/<provider>
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `provider` | `string` | **Required**. ['Google', 'Github] |

**Accesso**: Pubblico

**Descrizione**: Avvia il flusso di autenticazione OAuth per il provider specificato (Google o GitHub).

**Questo percorso implementa diverse misure di sicurezza necessarie per la route successiva:**

- Generazione di token **CSRF** senza richiedere **l'ID utente**
- Convalida del provider per consentire solo “*google*” e “*github*”.
- Gestione sicura dei **reindirizzamenti**
- Gestione dello **stato** della sessione

Caratteristiche di **sicurezza**:

- Convalida dell'input per i parametri del *provider*
- Protezione **CSRF** attraverso la generazione di token
- Gestione sicura della sessione
- Convalida dei parametri di stato OAuth

**Esempio di risposta:** Reindirizza alla pagina di login del provider OAuth (Google - Github)

####  auth/callback/provider

```
   GET /auth/callback/<provider>
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `provider` | `string` | **Required**. ['Google', 'Github] |

**Metodo**: GET

**Accesso**: Riservato

**Descrizione**: Gestisce il callback OAuth dopo l'autenticazione del provider. 

**Prerequisiti**: Token CSRF

**Questo percorso implementa diverse misure di sicurezza necessarie per la route successiva:**


- Convalida dello stato **CSRF**
- Crittografia dei dati con **AES-256**
- Generazione sicura di **sale**
- **Registrazione** di tutti i tentativi di autenticazione
- Gestione degli **errori** con registrazione sicura

**Flusso del processo:**

1. Convalida lo stato **CSRF** dal provider
2. Recupera e convalida i token **OAuth**
3. Recupera le informazioni sull'utente dal **provider**
4. Recupera ID Utente dal **provider** ed effettua **hashing** per assicurare coerenza del formato indipendentemente dal provider
   
   ```python
	def hash_user_id(self, provider: str, original_id: str) -> str:
        """
        Generates a secure and consistent hash of the user ID using HMAC-SHA256,
        encoded in URL-safe base64 format.

        Args:
            provider: OAuth provider identifier (e.g., 'google', 'github')
            original_id: Original user ID from the provider

        Returns:
            str: Base64 encoded hash, URL-safe without padding

        Raises:
            ValueError: If provider or original_id is empty
            CryptographicError: If hashing fails
        """
        if not provider or not original_id:
            raise ValueError("Provider and user ID are required")

        try:
            # Combine provider and ID in a consistent format
            combined = f"{provider}:{original_id}"

            # Use HMAC-SHA256 to generate a secure hash
            hmac_obj = hmac.new(
                key=self.app_secret.to_bytes(),
                msg=combined.encode(),
                digestmod=hashlib.sha256
            )

            # Convert to URL-safe base64 without padding
            hash_bytes = hmac_obj.digest()  # Get raw bytes instead of hexadecimal
            return base64.urlsafe_b64encode(hash_bytes).rstrip(b'=').decode('ascii')

        except Exception as e:
            self.logger.error(f"Error hashing user ID: {e}")
            raise CryptographicError("Unable to hash user ID") from e

6. Cifra i dati **sensibili** dell'utente
7. Crea/aggiorna i record dell'utente
8. Stabilisce una sessione **sicura**

####  Logout Route: auth/logout

```
   POST auth/logout
```

**Metodo**: POST

**Accesso**: Riservato ad utenti loggati

**Descrizione**: Gestisce il processo di logout sicuro dell'utente

**Prerequisiti**: Token CSRF e Login

**Questo percorso implementa diverse misure di sicurezza necessarie**

- Richiede l'autenticazione (**login_required**)
- Protezione CSRF (**csrf.csrf_protect**)
- Pulizia completa della **sessione**
- Registrazione di **audit**


**Risultato**: Risposta **JSON** con redirect alla pagina **principale**

### Routes di gestione del Portfolio 

È bene specificare che tutte queste **routes** (al di fuori di dashboard), sono accessibili soltanto dalla pagina principale: non è possibile effettuare richieste API esternamente poichè verranno gestite interamente dalla web app, attraverso una firma gemerata da un'origine javascript verificata con una validità limitata. 

####  Dashboard route: /dashboard

```
   GET /dashboard
```

**Metodo**: GET

**Accesso**: Riservato ad utenti loggati

**Descrizione**: Dashboard principale che visualizza i dati crittografati del portfolio con valutazioni in tempo reale

**Prerequisiti**: Token CSRF e Login


**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Cifratura/decifratura dei **dati**
- Sanificazione dell'**input**
- Gestione degli **errori**
- Registrazione di **audit**


**Dettagli di implementazione:**

- Implementa la **paginazione** (50 elementi per pagina)
- Logica di ripetizione della **connessione** (max 3 tentativi)
- Recupero dei prezzi in batch
- Chunking dei dati per le prestazioni


####  Aggiungi crypto al portfolio: /api/portfolio/add

```
   POST /api/portfolio/add
```

**Metodo**: POST

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Aggiunge una nuova crypto al portfolio con archiviazione crittografata

**Prerequisiti**: Token CSRF, Nonce, Ratelimiting, Validazione Origin e Headers, e Login

**Questo percorso implementa diverse misure di sicurezza necessarie**

- Autenticazione **richiesta** (login_required)
- Protezione **CSRF** (csrf.csrf_protect)
- Limitazione della **richieste** (rate_limit_decorator)
- **Sanificazione** dell'input
- **Crittografia** dei dati
- Gestione delle **transazioni**
- Registrazione delle verifiche


**Esempio di utilizzo**
```json
{
    “crypto_id": “bitcoin”,
    “symbol": “BTC”,
    “amount": 1.5,
    “purchase_price": 45000,
    “purchase_date": “2024-01-15”
}
```


####  Modifica valori di una crypto nel portfolio: /api/portfolio/update/{doc_id}

```
   PUT /api/portfolio/update/<doc_id>
```

**Metodo**: PUT

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Modifica **quantità**, prezzo di **acquisto** e data di **acquisto** di una specifico **crypto** associata al portfolio con archiviazione **crittografata**.

**Prerequisiti**: Token CSRF, Nonce,  Login, Validazione Origin e Headers

**Campi necessari**:

`purchase_price`       `float`  **Required** nuovo prezzo di acquisto

 `purchase_date`       `float`  **Required** nuova data di acquisto 
 
 `purchase_amount`  `float`  **Required**. nuova quantità di acquisto 

Nel caso in cui l'utente decidesse di cambiare solo un valore, i rimanenti valori verranno aggiornati con quelli precedentemente presenti di default.

**Questo percorso implementa diverse misure di sicurezza necessarie**

- Verifica della **proprietà** del documento
- Cifratura dei **dati**
- **Sanificazione** dell'input
- **Registrazione** delle verifiche
- Gestione degli **errori**

####  Elimina una crypto dal portfolio: /api/portfolio/delete/{doc_id}

```
   DELETE /api/portfolio/delete/<doc_id>
```

**Metodo**: DELETE

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Elimina una crypto dal portfolio dell'utente

**Prerequisiti**: Token CSRF, Nonce,  Login,   Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- Verifica della **proprietà** dei documenti
- Creazione di un **backup** crittografato
- Pulizia dei dati **associati**
- Registrazione di **audit**
- Gestione degli **errori**

####  Visualizzazione valuta selezionata: /api/preferences/currency

```
   GET /api/preferences/currency
```

**Metodo**: GET

**Accesso**: Riservato ad utenti **loggati** e accessibile soltanto attraverso la **dashboard**

**Descrizione**: Restituisce la valuta attualmente selezionata dalla **dashboard**

**Prerequisiti**:  Token CSRF, Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Protezione **CSRF** (csrf.csrf_protect)

####  Modifica della valuta da visualizzare: /api/preferences/currency

```
   PUT /api/preferences/currency
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `currency` | `string` | **Required**. ['USD', 'EUR' |

**Metodo**: PUT

**Accesso**: Riservato ad utenti **loggati** e accessibile soltanto attraverso la **dashboard**

**Descrizione**: Permette di modificare la valuta attualmente selezionata dalla **dashboard**

**Prerequisiti**:  Token CSRF, Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Protezione **CSRF** (csrf.csrf_protect)
- Sanificazione degli **Input**

### Routes di gestiione dei Token per API (JWT)

Anche in questo caso, tutte le routes sono accessibili soltanto dalla pagina **principale**: non è possibile effettuare richieste API esternamente poichè verranno gestite interamente dalla web app, attraverso una firma gemerata da un'origine javascript verificata con una validità limitata. 

####  Ottieni un Token API (JWT): /api/token

```
   POST /api/token
```

**Metodo**: POST

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Ottieni un token **JWT** da utilizzare con **EndPoint** designati all'ottenimento del valore del **Portfolio** o all'aggiunta di nuove **Crypto**

**Prerequisiti**: Token CSRF, Nonce,  Login,  Validazione Origin e Headers, Prerequisiti per la generazione

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- **Protezione** CSRF
- Limitazione delle **richieste** (1 token ogni 12 ore, Max 2 token al giorno)
- La generazione di un nuovo **token** invalida quello precedentemente **generato**
- Rotazione dei **token**
- Registrazione di audit
- Tracciamento del dispositivo

####  Ottieni informazioni sulla validità del Token API (JWT): /api/token/status

```
   GET /api/token/status
```

**Metodo**: GET

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Ottieni informazioni sulla validità di un token **JWT** da utilizzare con **EndPoint** designati all'ottenimento del valore del **Portfolio** o all'aggiunta di nuove **Crypto**

**Prerequisiti**: Token CSRF, Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- **Protezione** CSRF
- Abilità o meno la **possibilità** di generare un nuovo token

####  Pulizia dei Token API (JWT): /api/token/cleanup

```
   POST  /api/token/cleanup
```

**Metodo**: POST

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Gestisce i token scaduti modificando la **proprietà** su Firestore da **Valid** a **Expired**

**Prerequisiti**: Token CSRF, Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- **Protezione** CSRF
- Abilità o meno la **possibilità** di generare un nuovo token JWT

### Routes utilizzati per la gestione dei Token CSRF

####  Generazione Token CSRF: api/csrf/token

```
   GET api/csrf/token
```

**Metodo**: GET

**Accesso**: Riservato ad utenti **loggati** e accessibile soltanto attraverso la **dashboard**

**Descrizione**: Ottieni un token **CSRF** da utilizzare per il corretto funzionamento del sistema

**Prerequisiti**:  Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Generazione **crittograficamente** sicura del Token CSRF
- Rotazione dei **token**
- Eliminazione **token** **CSRF** (Protezione DDOS)

####  Generazione Nonce CSRF: api/csrf/nonce

```
   GET api/csrf/nonce
```

**Metodo**: GET

**Accesso**: Riservato ad utenti **loggati** e accessibile soltanto attraverso la **dashboard**

**Descrizione**: Ottieni un nonce **CSRF** da utilizzare per il corretto funzionamento del sistema insieme al Token **CSRF**

**Prerequisiti**:  Token CSRF,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Generazione **crittograficamente** sicura del Nonce CSRF
- Rotazione dei nonce
- Eliminazione nonce scaduti


### Routes di utility
####  Navigazione verso la pagina principale: /navigate-home

```
   POST /navigate-home
```


**Metodo**: POST

**Accesso**: Riservato ad utenti loggati e accessibile soltanto dalla dashboard

**Descrizione**: Riporta l'utente alla pagina di benvenuto

**Prerequisiti**: Token CSRF, Nonce, , Validazione Origin e Headers, e Login

**Questo percorso implementa diverse misure di sicurezza necessarie**

- Autenticazione **richiesta** (login_required)
- Protezione **CSRF** (csrf.csrf_protect)



### Routes di gestione delle Cryptovalute disponibili

####  Generazione Token CSRF: api/cryptocurrencies

```
   GET api/cryptocurrencies
```

**Metodo**: GET

**Accesso**: Riservato ad utenti **loggati** e accessibile soltanto attraverso la **dashboard**

**Descrizione**: Restituisce tutte le **crypto** disponibili provenienti come risposta dall'API di CoinGecko e le salva nella cache: successivamente i valori verranno prelevati da essa e riaggiornati dopo 30 min.

**Prerequisiti**:  Token CSRF, Nonce,  Login,  Validazione Origin e Headers

**Questo percorso implementa diverse misure di sicurezza necessarie**

- **Autenticazione** necessaria
- Protezione **CSRF** (csrf.csrf_protect)

### Conclusione routes

Ogni percorso dell'applicazione è protetto da più livelli di sicurezza, secondo il principio della **difesa in profondità**. Le caratteristiche di sicurezza comuni a tutti i percorsi includono:

1. Convalida e sanificazione dell'input
2. Gestione degli errori con registrazione sicura
3. Limitazione della velocità, ove appropriato
4. Protezione CSRF
5. Controlli di autenticazione
6. Registrazione di eventi significativi
7. Gestione sicura delle sessioni
8. Crittografia dei dati per le informazioni sensibili

Tutti i dati di risposta sono accuratamente sanificati per evitare la fuga di informazioni e i messaggi di errore sono generalizzati per evitare di esporre dettagli interni al sistema.


## Configurazione di Sicurezza per Applicazioni Flask

Questa parte specifica della documentazione descrive in dettaglio la configurazione di sicurezza definita e adottata per la Web App, poichè tali parametri offrono protezione contro attacchi comuni, come lo scripting cross-site (XSS) e il clickjacking, e garantiscono che la comunicazione tra il server e il browser avvenga in modo sicuro.

---

### **Security Headers**

#### **1. HSTS**
```python
HSTS: str = field(default="max-age=31536000; includeSubDomains")
```
- **Significato**:
  - **`max-age=31536000`**: Impone ai browser di accedere al dominio solo tramite HTTPS per un periodo di 1 anno (31536000 secondi).
  - **`includeSubDomains`**: Estende questa regola a tutti i sottodomini del dominio principale.
- **Utilizzo**: Garantisce che il traffico del dominio (e dei suoi sottodomini) sia sempre cifrato.

---

#### **2. CONTENT_TYPE_OPTIONS**
```python
CONTENT_TYPE_OPTIONS: str = field(default="nosniff")
```
- **Significato**:
  - Previene che il browser interpreti il tipo di contenuto in modo diverso da quanto dichiarato dal server.
  - Protegge da attacchi di tipo **MIME-sniffing**.
- **Utilizzo**: Blocca il caricamento di contenuti con tipi MIME non validi o non attesi.

---

#### **3. FRAME_OPTIONS**
```python
FRAME_OPTIONS: str = field(default="DENY")
```
- **Significato**:
  - Impedisce che il sito venga incorniciato (`<iframe>`) in altri siti web.
  - Protegge da attacchi di **clickjacking**.
- **Utilizzo**: Blocca qualsiasi tentativo di visualizzare il sito in un iframe.

---

#### **4. XSS_PROTECTION**
```python
XSS_PROTECTION: str = field(default="1; mode=block")
```
- **Significato**:
  - Attiva il filtro XSS del browser.
  - **`1`**: Abilita il filtro.
  - **`mode=block`**: Blocca completamente la pagina in caso di rilevamento di uno script dannoso.
- **Utilizzo**: Protezione contro gli attacchi **Cross-Site Scripting (XSS)**.

---

#### **5. REFERRER_POLICY**
```python
REFERRER_POLICY: str = field(default="strict-origin-when-cross-origin")
```
- **Significato**:
  - Controlla quali informazioni del referrer (URL precedente) vengono inviate nelle richieste.
  - **`strict-origin-when-cross-origin`**:
    - Invia solo il dominio (`origin`) del referrer per richieste cross-origin.
    - Invia l'intero referrer solo per richieste verso la stessa origine.
- **Utilizzo**: Migliora la privacy degli utenti riducendo la quantità di informazioni condivise tra domini.

---

#### **6. PERMITTED_CROSS_DOMAIN_POLICIES**
```python
PERMITTED_CROSS_DOMAIN_POLICIES: str = field(default="none")
```
- **Significato**:
  - Blocca le richieste di politiche cross-domain come i file `*.swf` o `*.xml`.
- **Utilizzo**: Previene potenziali abusi relativi a plugin Adobe Flash o Silverlight.

---

### **Content Security Policy (CSP)**

#### **Definizione di CSP**
```python
CSP: str = field(default=(
    "default-src 'self'; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com; "
    "font-src 'self' https://cdnjs.cloudflare.com; "
    "connect-src 'self' https://*.ngrok-free.app https://*.ngrok.io; "
    "frame-ancestors 'none';"
))
```

##### **Descrizione delle direttive**:
1. **`default-src 'self';`**
   - Origine predefinita per tutte le risorse non coperte da altre direttive.
   - **`'self'`**: Consente solo risorse provenienti dallo stesso dominio da cui la pagina è stata servita.

2. **`img-src 'self' data: https:;`**
   - Controlla le origini consentite per il caricamento delle immagini.
   - **`'self'`**: Immagini caricate dallo stesso dominio della pagina.
   - **`data:`**: Consente immagini caricate come data URI (es. `data:image/png;base64,...`).
   - **`https:`**: Permette immagini da qualsiasi origine che usa HTTPS.

3. **`style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;`**
   - Controlla le origini per i fogli di stile (CSS).
   - **`'self'`**: Fogli di stile dal dominio della pagina.
   - **`'unsafe-inline'`**: Permette stili inline (rischioso, ma utile in alcuni casi specifici).
   - **URL specifici**: Permette stili da CDN noti come `jsdelivr` e `cdnjs`.

4. **`script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com;`**
   - Controlla le origini per il caricamento degli script JavaScript.
   - **`'self'`**: Solo script dal dominio della pagina.
   - **`'unsafe-inline'`**: Consente script inline (potenzialmente rischioso per XSS).
   - **`'unsafe-eval'`**: Permette l'uso di `eval()` e simili (rischioso).
   - **URL specifici**: Consente script da CDN comuni come `jsdelivr`, `cdnjs` e `code.jquery.com`.

5. **`font-src 'self' https://cdnjs.cloudflare.com;`**
   - Origini per i font web.
   - **`'self'`**: Font dal dominio della pagina.
   - **`cdnjs.cloudflare.com`**: Permette font da questo CDN.

6. **`connect-src 'self' https://*.ngrok-free.app https://*.ngrok.io;`**
   - Origini per connessioni HTTP o WebSocket.
   - **`'self'`**: Consente connessioni al proprio dominio.
   - **`https://*.ngrok-free.app`** e **`https://*.ngrok.io`**: Permette connessioni a sottodomini dinamici (es. per debug con ngrok).

7. **`frame-ancestors 'none';`**
   - Specifica chi può incorniciare il sito (usando `<iframe>`).
   - **`'none'`**: Blocca qualsiasi tentativo di incorniciare il sito.

---

### **Altre Variabili di Configurazione**

#### **7. DEFAULT_CORS_MAX_AGE**
```python
DEFAULT_CORS_MAX_AGE: int = 3600  # 1 hour
```
- **Significato**:
  - Specifica per quanto tempo una risposta **CORS preflight** può essere memorizzata nella cache dal browser.
- **Utilizzo**: Riduce il numero di richieste **OPTIONS** effettuate dal browser.

---

#### **8. DEFAULT_HSTS_MAX_AGE**
```python
DEFAULT_HSTS_MAX_AGE: int = 31536000  # 1 year
```
- **Significato**:
  - Durata predefinita per l'header HSTS.
- **Utilizzo**: Fornisce una configurazione standard per la durata delle politiche HSTS.

---

#### **9. SUPPORTED_ENVIRONMENTS**
```python
SUPPORTED_ENVIRONMENTS: Set[str] = frozenset({'development', 'production'})
```
- **Significato**:
  - Elenco degli ambienti supportati dall'applicazione.
  - **`development`**: Ambiente di test/sviluppo.
  - **`production`**: Ambiente di produzione con configurazioni più restrittive.
- **Utilizzo**: Aiuta a gestire configurazioni diverse per ambienti differenti.

---

### **Configurazioni CORS**

#### **Definizione di cors_headers**
```python
cors_headers = {
    'Access-Control-Allow-Headers': os.getenv('CORS_ALLOWED_HEADERS', ''),
    'Access-Control-Allow-Methods': os.getenv('CORS_ALLOWED_METHODS', ''),
    'Access-Control-Allow-Credentials': os.getenv('CORS_ALLOW_CREDENTIALS', ''),
    'Access-Control-Expose-Headers': os.getenv('CORS_EXPOSE_HEADERS', ''),
    'Access-Control-Max-Age': str(self.DEFAULT_CORS_MAX_AGE)
}
```
##### **Descrizione**:
1. **`Access-Control-Allow-Headers`**: Specifica gli header HTTP che il client può includere nelle richieste cross-origin.
2. **`Access-Control-Allow-Methods`**: Elenca i metodi HTTP consentiti (es. GET, POST, PUT).
3. **`Access-Control-Allow-Credentials`**: Consente al browser di inviare credenziali (es. cookie) nelle richieste cross-origin.
4. **`Access-Control-Expose-Headers`**: Definisce quali header il browser può esporre.
5. **`Access-Control-Max-Age`**: Specifica la durata di caching per le richieste preflight.

---

### **Configurazioni Security Headers**

#### **Definizione di security_headers**
```python
security_headers = {
    'X-Content-Type-Options': self._security_headers.CONTENT_TYPE_OPTIONS,
    'X-Frame-Options': self._security_headers.FRAME_OPTIONS,
    'X-XSS-Protection': self._security_headers.XSS_PROTECTION,
    'Referrer-Policy': self._security_headers.REFERRER_POLICY,
    'X-Permitted-Cross-Domain-Policies': self._security_headers.PERMITTED_CROSS_DOMAIN_POLICIES,
    'Content-Security-Policy': self._security_headers.CSP
}
```
##### **Descrizione**:
1. **`X-Content-Type-Options`**: Previene il MIME-sniffing.
2. **`X-Frame-Options`**: Impedisce il framing della pagina.
3. **`X-XSS-Protection`**: Protegge da attacchi XSS.
4. **`Referrer-Policy`**: Limita i dati referrer inviati nelle richieste.
5. **`X-Permitted-Cross-Domain-Policies`**: Blocca richieste cross-domain non autorizzate.
6. **`Content-Security-Policy`**: Gestisce le origini delle risorse caricate dal browser.


## Come vengono protette le routes?
### I decorator

I decorator in Python sono uno strumento potente che permette di modificare o estendere il comportamento di funzioni e metodi in modo pulito e riutilizzabile. Nel contesto della sicurezza delle applicazioni web, i decorator giocano un ruolo fondamentale permettendo di implementare controlli di sicurezza in modo modulare e consistente.

Un decorator è essenzialmente una funzione che prende come input un'altra funzione e ne estende il comportamento senza modificarne il codice sorgente. Questo pattern è particolarmente utile per implementare funzionalità trasversali come:

- Autenticazione e autorizzazione
- Rate limiting
- Protezione CSRF
- Logging e audit
- Gestione delle sessioni
- Validazione degli input

### Principali Classi di Sicurezza

Le classi principali che implementano la logica di sicurezza attraverso i decorator sono:

#### SecureConfig
Gestisce le configurazioni di sicurezza dell'applicazione, incluse:
- Gestione delle origini CORS consentite
- Configurazione degli header di sicurezza
- Validazione dell'ambiente
- Protezione contro attacchi di tipo injection

```python
class SecureConfig:
    def __init__(self):
        self._setup_secure_logging()
        self._init_crypto()
        self._request_history = {}
        self._initialized = False
```

#### CSRFProtection
Implementa la protezione contro attacchi Cross-Site Request Forgery attraverso:
- Generazione e validazione di token
- Gestione dei nonce
- Verifica dell'origine delle richieste
- Tracciamento delle catene di richieste

```python
class CSRFProtection:
    def __init__(self, app=None):
        self._signing_key = secrets.token_bytes(32)
        self.encryption_key = Fernet.generate_key()
        self._token_cache = {}
```

#### TokenJWTHandling
Gestisce l'intero ciclo di vita dei token JWT:
- Generazione sicura dei token
- Validazione e rinnovo
- Gestione della scadenza

#### FirebaseRateLimiter
Implementa il rate limiting distribuito usando Firebase:
- Tracciamento delle richieste
- Applicazione dei limiti
- Gestione delle finestre temporali
- Cleanup automatico

### Decorator di Sicurezza

#### @login_required

Questo decorator garantisce che solo gli utenti autenticati possano accedere alle route protette. È implementato come segue:

```python
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
```

Funzionalità di sicurezza:
- Verifica della presenza di una sessione valida
- Redirect sicuro per utenti non autenticati
- Mantenimento della catena di redirect
- Protezione contro accessi non autorizzati

### @rate_limit_decorator

Implementa il controllo del rate limiting per prevenire abusi delle API e rallentamenti del sistema. I

```python
def rate_limit_decorator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        ip_address = request.remote_addr
        rate_limiter = FirebaseRateLimiter(db)
        is_allowed, remaining, retry_after = rate_limiter.check_rate_limit(
            user_id, ip_address)
```
l sistema di rate limiting utilizza un approccio a doppio livello che combina limitazioni basate sull'IP e sull'identità dell'utente. Questo permette di proteggere l'applicazione sia da attacchi distribuiti che da abusi da parte di singoli utenti autenticati.

Il sistema mantiene le seguenti informazioni per ogni IP:
- Un contatore di richieste
- Il timestamp di inizio della finestra temporale
- Il timestamp dell'ultima richiesta

Per ogni nuova richiesta, il sistema:
1. Verifica se esiste già un record per l'IP
2. Controlla se la finestra temporale corrente è scaduta
3. Verifica se il numero di richieste ha superato il limite
4. Aggiorna i contatori in modo atomico usando una transazione Firebase


I limiti utente vengono gestiti separatamente ma in modo analogo ai limiti IP. Questo permette di:
- Avere limiti diversi per utenti autenticati
- Tracciare l'utilizzo per utente indipendentemente dall'IP
- Applicare politiche diverse per utenti specifici


Tutti questi dati vengono gestiti attraverso una finestra temporale:

1. Ogni finestra ha una durata configurabile (default: 3600 secondi per IP, configurabile per utente)
2. Quando una finestra scade, viene creata una nuova finestra con contatore azzerato
3. Le richieste vengono conteggiate all'interno della finestra corrente
4. Il sistema mantiene il timestamp di inizio finestra per calcolare quando resettare i contatori


L'utilizzo di Firebase Firestore permette una gestione distribuita del rate limiting:

1. Le transazioni atomiche garantiscono la consistenza dei contatori
2. I dati sono sincronizzati tra tutte le istanze dell'applicazione
3. Il cleanup automatico rimuove i record scaduti
4. Il sistema scala automaticamente con il carico



Il sistema aggiunge header di risposta per informare i client:

```python
response.headers['X-RateLimit-Remaining'] = str(remaining)
response.headers['X-RateLimit-Reset'] = str(retry_after)
```

Questi header permettono ai client di:
- Conoscere il numero di richieste rimanenti
- Sapere quando i limiti verranno resettati
- Implementare logiche di backoff quando necessario

Il sistema implementa un cleanup probabilistico dei dati:

```python
def maybe_cleanup(self):
    if random.random() < self.cleanup_probability:
        try:
            self.cleaner.clean_expired_entries(self.window_seconds)
        except Exception as e:
            logging.warning(f"Inline cleanup error: {str(e)}")
```

Questo assicura che:
1. I record scaduti vengano rimossi periodicamente
2. Il carico del cleanup sia distribuito nel tempo
3. Il database non cresca indefinitamente
4. Le performance rimangano costanti nel tempo


### @csrf.csrf_protect

Fornisce protezione CSRF completa attraverso:

```python
def csrf_protect(self, f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        nonce = request.headers.get('X-CSRF-Nonce')
        if not nonce or not self.validate_nonce(nonce):
            abort(403, "Invalid CSRF nonce")
```



La protezione CSRF (Cross-Site Request Forgery) implementata nell'applicazione utilizza un approccio a più livelli che combina token, nonce e validazione dell'origine. Questo crea una difesa in profondità contro attacchi CSRF sofisticati.

La strategia protettiva dei sistemi informatici denominata Defense in Depth o DiD (difesa in profondità) consiste in una stratificazione delle risorse informatiche di protezione. Il concetto di Difesa in Profondità si origina come strategia militare, per il rallentamento dell’avanzare nemico tramite barriere fisiche.

Agendo in tal modo, era possibile preparare l’effettivo contrattacco, delineando una strategia d’azione coerente e i mezzi attraverso cui attuarla.


Il decorator csrf_protect è il punto di ingresso principale per la protezione CSRF. Ecco come funziona nel dettaglio:

```python
def csrf_protect(self, f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Validazione del nonce
        nonce = request.headers.get('X-CSRF-Nonce')
        if not nonce or not self.validate_nonce(nonce):
            abort(403, "Invalid CSRF nonce")

        # 2. Validazione del token
        token = request.headers.get('X-CSRF-Token')
        if not token or not self.validate_token_request(token):
            abort(403, "Invalid CSRF token")

        # 3. Validazione dell'origine
        origin = request.headers.get('Origin')
        if origin and not self._validate_origin_secure(origin):
            abort(403, "Invalid request origin")

        return f(*args, **kwargs)
    return decorated_function
```

#### Validazione del Nonce

Il sistema utilizza nonce monouso per prevenire gli attacchi replay:

```python
def validate_nonce(self, nonce: str) -> bool:
    try:
        if not nonce or nonce not in self.used_nonces:
            return False

        nonce_data = self.used_nonces[nonce]
        current_time = time.time()

        # Verifica scadenza
        if current_time > nonce_data['expires']:
            del self.used_nonces[nonce]
            return False

        # Decrittazione e validazione payload
        payload = json.loads(
            self.fernet.decrypt(nonce.encode()).decode()
        )

        # Verifica binding con l'utente
        if payload['user_id'] != session.get('user_id'):
            return False

        # Rimozione dopo l'uso (one-time use)
        del self.used_nonces[nonce]
        return True

    except Exception as e:
        self.logger.error(f"Errore validazione nonce: {str(e)}")
        return False
```

Il nonce fornisce:
- Protezione contro attacchi replay
- Binding con la sessione utente
- Scadenza temporale automatica
- Utilizzo singolo garantito



Il sistema implementa una validazione completa del token CSRF:

```python
def validate_token_request(self, token: str) -> bool:
    if not token:
        return False

    # Validazione origine
    origin = request.headers.get('Origin')
    if origin:
        if not self._validate_origin_format(origin):
            self.logger.warning(f"Formato origine non valido: {origin}")
            return False

        if not self._check_origin_allowed(origin):
            self.logger.warning(f"Origine non consentita: {origin}")
            return False

    # Validazione referrer per richieste same-origin
    referrer = request.headers.get('Referer')
    if referrer:
        ref_url = urlparse(referrer)
        req_url = urlparse(request.url)
        if ref_url.netloc != req_url.netloc:
            self.logger.warning(f"Referrer non valido: {referrer}")
            return False

    return self._validate_token(token)
```

La validazione del token include:
- Controllo del formato e della firma
- Validazione dell'origine della richiesta
- Verifica del referrer
- Binding con la sessione utente

#### Generazione Sicura dei Token

I token vengono generati in modo sicuro con multiple protezioni:

```python
def _generate_secure_token(self, require_user_id=True) -> str:
    if require_user_id and 'user_id' not in session:
        abort(401)

    # Cleanup dei token scaduti
    self._cleanup_expired_tokens()

    if (require_user_id):
        # Validazione origine JavaScript
        js_origin = request.headers.get('X-JavaScript-Origin')
        if not js_origin or not self._validate_js_origin(js_origin):
            abort(403, "Invalid request origin")

        user_id = session['user_id']

        # Generazione componenti token
        timestamp = int(time.time())
        random_bytes = secrets.token_bytes(32)
        request_id = secrets.token_hex(16)

        # Creazione payload
        payload = {
            'user_id': user_id,
            'timestamp': timestamp,
            'request_id': request_id,
            'random': base64.b64encode(random_bytes).decode()
        }

        # Cifratura payload
        encrypted_payload = self.fernet.encrypt(
            json.dumps(payload).encode()
        )

        # Generazione firma HMAC
        signature = hmac.new(
            self._signing_key,
            encrypted_payload,
            hashlib.sha256
        ).digest()

        # Composizione token finale
        token = base64.urlsafe_b64encode(
            encrypted_payload + signature
        ).decode()

        # Salvataggio in cache con metadata
        self._token_cache[user_id][token] = {
            'timestamp': timestamp,
            'uses': 0,
            'request_id': request_id
        }

        return token
```

La generazione include:
- Entropia crittografica tramite secrets
- Crittografia del payload con Fernet
- Firma HMAC per integrità
- Caching sicuro con metadata

#### Validazione dell'Origine

Il sistema implementa una validazione completa dell'origine delle richieste:

```python
def _validate_origin_secure(self, origin: str) -> bool:
    if not origin or '\x00' in origin:
        return False

    try:
        parsed = urlparse(origin)
        
        # Validazione protocollo
        if parsed.scheme not in {'http', 'https'}:
            return False

        # Gestione origini locali
        is_local = (
            parsed.netloc.startswith('localhost') or
            parsed.netloc.startswith('127.0.0.1') or
            parsed.netloc == '[::1]'
        )

        if is_local:
            if os.getenv('FLASK_ENV') != 'development':
                return False

            # Validazione porta per sviluppo locale
            if ':' in parsed.netloc:
                port = int(parsed.netloc.split(':')[1])
                if not (1024 <= port <= 65535):
                    return False

            return True

        # Validazione dominio
        if not parsed.netloc or '.' not in parsed.netloc:
            return False

        return True

    except Exception as e:
        self.logger.error(f"Errore validazione origine: {str(e)}")
        return False
```

La validazione dell'origine assicura:
- Formato URL valido 
- Protocollo consentito
- Domini autorizzati
- Porte consentite in sviluppo

#### Gestione del Ciclo di Vita dei Token

Il sistema gestisce in modo sicuro l'intero ciclo di vita dei token:

```python
def _cleanup_expired_tokens(self) -> None:
    current_time = time.time()

    for user_id, tokens in list(self._token_cache.items()):
        # Rimuovi token scaduti o sovra-utilizzati
        valid_tokens = {}
        for token, data in tokens.items():
            is_valid = (
                (current_time - data['timestamp']) <= self._token_lifetime and
                data['uses'] < self._max_uses_per_token
            )

            # Gestione speciale token di autenticazione
            if data.get('is_auth_flow', False):
                is_valid = is_valid and data['uses'] == 0

            if is_valid:
                valid_tokens[token] = data

        if valid_tokens:
            self._token_cache[user_id] = valid_tokens
        else:
            del self._token_cache[user_id]

    # Protezione DoS - Se troppi token, rimuovi i più vecchi
    total_tokens = sum(len(tokens) 
                    for tokens in self._token_cache.values())
    if total_tokens > self._max_tokens_per_session * len(self._token_cache):
        for user_id in self._token_cache:
            tokens = self._token_cache[user_id]
            if len(tokens) > self._max_tokens_per_session:
                sorted_tokens = sorted(
                    tokens.items(),
                    key=lambda x: x[1]['timestamp'],
                    reverse=True
                )
                self._token_cache[user_id] = dict(
                    sorted_tokens[:self._max_tokens_per_session]
                )
```

Il ciclo di vita include:
- Pulizia automatica token scaduti
- Limiti di utilizzo per token
- Protezione contro accumulo token
- Gestione speciale token di autenticazione

Il sistema di protezione CSRF implementa una difesa in profondità attraverso:

1. Validazione multipla delle richieste
   - Token CSRF
   - Nonce monouso
   - Controllo origine
   - Validazione referrer

2. Gestione sicura dei token
   - Generazione crittografica
   - Cifratura payload
   - Firme HMAC
   - Cleanup automatico

3. Protezione sessione
   - Cookie sicuri
   - Binding utente
   - Timeout automatico
   - Limiti di utilizzo

4. Prevenzione attacchi
   - Anti-replay
   - Anti-DoS
   - Anti-timing
   - Sanitizzazione input

La combinazione di questi meccanismi crea più livelli di protezione, rendendo estremamente difficile bypassare la sicurezza anche se un singolo controllo viene compromesso.




### Middleware di Sicurezza

#### check_session_timeout
- Valida l'età della sessione
- Forza la ri-autenticazione per sessioni scadute
- Traccia l'ultima attività
- Implementa timeout di inattività di 60 minuti

```python
@app.before_request
def check_session_timeout():
    if 'last_active' in session:
        last_active = datetime.fromtimestamp(session['last_active'])
        if datetime.now() - last_active > timedelta(minutes=60):
            session.clear()
```

#### add_security_headers
Aggiunge header di sicurezza a tutte le risposte (precedentemente analizzato):
- Configurazione CORS
- Content Security Policy
- HSTS enforcement
- Protezione XSS
- Prevenzione Clickjacking

# Utilizzo del Sale nell'Applicazione

## Panoramica dell'Utilizzo del Sale

Nell'applicazione, il sale crittografico viene utilizzato principalmente per tre scopi fondamentali:

1. Protezione delle informazioni sensibili degli utenti
2. Generazione di identificatori utente univoci e sicuri
3. Derivazione delle chiavi di crittografia

## Generazione e Memorizzazione del Sale

Quando un nuovo utente si registra attraverso OAuth, viene generato un sale univoco:

```python
# Nel callback OAuth
secure_salt = cipher.generate_salt()
security_ref = db.collection('user_security').document(user_id)

# Conversione del SecureByteArray in stringa base64 per storage
salt_bytes = secure_salt.to_bytes()
encoded_salt = base64.b64encode(salt_bytes).decode()

# Memorizzazione nel database
security_ref.set({
    'salt': encoded_salt,
    'created_at': firestore.SERVER_TIMESTAMP,
    'last_login': firestore.SERVER_TIMESTAMP,
    'oauth_token_metadata': token_metadata
})
```

Il metodo generate_salt() nella classe AESCipher produce un sale crittograficamente sicuro:

```python
def generate_salt(self) -> SecureByteArray:
    try:
        return SecureByteArray(os.urandom(self.SALT_LENGTH))
    except Exception as e:
        self.logger.error(f"Error generating salt: {e}")
        raise CryptographicError("Unable to generate salt")
```

## Utilizzo del Sale per la Crittografia

Il sale viene utilizzato per la derivazione delle chiavi di crittografia quando si devono cifrare dati sensibili dell'utente:

```python
def derive_key(self, user_id: str, salt: Union[bytes, SecureByteArray]) -> SecureByteArray:
    key_material = None
    secure_salt = None
    derived_key = None

    try:
        # Conversione sicura del sale
        secure_salt = self._ensure_secure_bytes(salt)

        # Configurazione KDF (Key Derivation Function)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=self.KEY_LENGTH,
            salt=secure_salt.to_bytes(),
            iterations=self.KDF_ITERATIONS,
            backend=default_backend()
        )

        # Combinazione sicura di user_id e master_key
        key_material = SecureByteArray(
            user_id.encode() + self.master_key.to_bytes()
        )

        # Derivazione della chiave
        derived_key = SecureByteArray(kdf.derive(key_material.to_bytes()))

        return derived_key

    finally:
        # Pulizia sicura della memoria
        for secure_data in [key_material, secure_salt]:
            if secure_data is not None and secure_data is not salt:
                secure_data.secure_zero()
```

## Utilizzo Pratico nella Gestione del Portfolio

Quando si gestiscono le informazioni del portfolio dell'utente, il sale viene utilizzato per cifrare i dati sensibili:

```python
# Recupero del sale dell'utente per operazioni di portfolio
security_ref = db.collection('user_security').document(user_id)
security_data = security_ref.get()

encoded_salt = security_data.to_dict()['salt']
salt_bytes = base64.b64decode(encoded_salt)

# Cifratura di un elemento del portfolio
encrypted_data = portfolio_encryption.encrypt_portfolio_item(
    validated_data,
    user_id,
    salt_bytes
)

# Decifratura di un elemento del portfolio
decrypted_item = portfolio_encryption.decrypt_portfolio_item(
    encrypted_item,
    user_id,
    salt_bytes
)
```

## Protezione degli Indirizzi Email

Gli indirizzi email degli utenti vengono cifrati usando il sale dell'utente prima di essere memorizzati:

```python
# Durante la registrazione dell'utente
encrypted_email = cipher.encrypt(
    user_email,
    user_id,
    secure_salt
).decode()

user_ref.set({
    'username': username,
    'email': encrypted_email,
    'preferred_currency': 'USD',
    'created_at': firestore.SERVER_TIMESTAMP,
    'last_login': firestore.SERVER_TIMESTAMP,
    'provider': provider
})
```

## Gestione Sicura della Memoria

L'applicazione utilizza la classe SecureByteArray per gestire in modo sicuro il sale in memoria:

```python
class SecureByteArray:
    def secure_zero(self) -> None:
        """Cancella in modo sicuro i dati dalla memoria"""
        if self._length == 0:
            return

        try:
            for _ in range(self.SECURE_WIPE_PASSES):
                # Sovrascrittura con dati casuali
                random_data = secrets.token_bytes(
                    max(self._length, self.MIN_RANDOM_BYTES)
                )
                ctypes.memmove(self._address, random_data, self._length)

            # Passaggio finale di azzeramento
            ctypes.memset(self._address, 0, self._length)

        except Exception as e:
            self.logger.error(f"Errore durante la pulizia sicura della memoria: {e}")
            raise MemorySecurityError(
                "Impossibile cancellare la memoria in modo sicuro"
            )
```

## Vantaggi dell'Utilizzo del Sale

L'utilizzo del sale nell'applicazione fornisce diversi benefici di sicurezza:

1. **Unicità per Utente**: Ogni utente ha un sale univoco, quindi anche se due utenti hanno gli stessi dati, i valori cifrati saranno diversi.

2. **Protezione contro Attacchi Rainbow Table**: Il sale rende inefficaci gli attacchi basati su tabelle precalcolate.

3. **Isolamento dei Dati**: Il sale per utente garantisce che una compromissione dei dati di un utente non comprometta gli altri.

4. **Derivazione Sicura delle Chiavi**: Il sale permette di derivare chiavi di cifratura uniche per ogni utente partendo dalla master key.

## Considerazioni sulla Sicurezza

1. Il sale viene sempre generato utilizzando funzioni crittograficamente sicure (os.urandom)
2. La lunghezza del sale è sufficiente (32 byte) per garantire l'unicità
3. Il sale viene memorizzato in modo sicuro nel database
4. La memoria contenente il sale viene pulita in modo sicuro dopo l'uso
5. Il sale non viene mai esposto nelle risposte API o nei log

## Gestione del Ciclo di Vita

Il sale viene:
1. Generato alla registrazione dell'utente
2. Memorizzato nel documento di sicurezza dell'utente
3. Recuperato quando necessario per operazioni crittografiche
4. Mai modificato o rigenerato (per mantenere l'accesso ai dati cifrati)
5. Eliminato solo se l'account dell'utente viene completamente rimosso

Questa gestione assicura che i dati degli utenti rimangano accessibili e sicuri per l'intera durata dell'account.

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

[Documentation](https://gabrielcellammare.github.io/CryptoFolio-App/)


## Fonti

 - [Bearer Token](https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly)
 - [JWT e Bearer Token](https://www.linkedin.com/pulse/jwt-e-bearer-token-facciamo-chiarezza-guido-spadotto/)
 - [Flask Framework](https://flask.palletsprojects.com/en/stable/)
 - [Firebase Cloud Firestore](https://firebase.google.com/docs/firestore?hl=it)
 - [OAuth 2.0 (Google)](https://developers.google.com/identity/protocols/oauth2?hl=it)
 - [OAuth 2.0 (Github)](https://medium.com/@tony.infisical/guide-to-using-oauth-2-0-to-access-github-api-818383862591)
 - [CSP](https://managedserver.it/cose-il-criterio-csp-e-come-aggiungerne-uno-content-security-policy/)

