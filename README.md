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

6. Crittografa i dati **sensibili** dell'utente
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

[Documentation](https://gabrielcellammare.github.io/CryptoFolio-App/)


## Fonti

 - [Bearer Token](https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly)
 - [JWT e Bearer Token](https://www.linkedin.com/pulse/jwt-e-bearer-token-facciamo-chiarezza-guido-spadotto/)
 - [Flask Framework](https://flask.palletsprojects.com/en/stable/)
 - [Firebase Cloud Firestore](https://firebase.google.com/docs/firestore?hl=it)
 - [OAuth 2.0 (Google)](https://developers.google.com/identity/protocols/oauth2?hl=it)
 - [OAuth 2.0 (Github)](https://medium.com/@tony.infisical/guide-to-using-oauth-2-0-to-access-github-api-818383862591)
 - [CSP](https://managedserver.it/cose-il-criterio-csp-e-come-aggiungerne-uno-content-security-policy/)

