# Implementazione delle misure di rilevamento delle vulnerabilità API

> **Nota per il lettore/AI destinataria.** Questo documento descrive l'implementazione realmente presente nel repository `DetectionCloudSecurityRisk`. È stato redatto a partire dal codice sorgente (`src/`), dagli Architecture Decision Record (`docs/adr/`) e dalle convenzioni di progetto (`CLAUDE.md`). È pensato come base per la stesura del capitolo di tesi: prima fornisce una **visione d'insieme** dell'architettura e del funzionamento della piattaforma, poi entra nel dettaglio di **ogni singola misura di rilevamento**. La terminologia dei moduli segue i nomi reali delle directory (`src/core/apiN_*`), che corrispondono alle categorie OWASP API Security Top 10 (2023).

---

## Parte I — Visione generale

### 1.1 Obiettivo della piattaforma

La piattaforma unifica **analisi statica** e **analisi dinamica** della sicurezza di API cloud e infrastruttura-as-code (IaC) in un unico flusso. L'idea portante è che nessuna delle due tecniche, da sola, sia sufficiente:

- l'analisi statica (IaC, codice sorgente, contratti OpenAPI) individua *rischi potenziali* ma soffre di falsi positivi, perché non sa se il rischio sia realmente sfruttabile a runtime;
- l'analisi dinamica (attacchi reali contro l'applicazione in esecuzione) produce *prove empiriche* ma senza contesto statico fatica a coprire in modo sistematico la superficie d'attacco e a spiegare la causa radice.

La piattaforma combina i due mondi: gli scanner statici alimentano un inventario di rischi, gli attacchi dinamici (D-AST) cercano conferma empirica, e un **motore di correlazione** unisce le due viste su chiavi di risorsa comuni, elevando la severità dei rischi che trovano riscontro runtime e calcolando un **risk score pesato (0–10)**. Il risultato è presentato tramite una dashboard FastAPI.

Le vulnerabilità coperte appartengono alla **OWASP API Security Top 10 (2023)**: BOLA, Broken Authentication, BOPLA, Unrestricted Resource Consumption, BFLA, SSRF, Security Misconfiguration, Unsafe Consumption of APIs, oltre alla rilevazione di **Shadow API** (endpoint non documentati).

### 1.2 Principio architetturale: Clean Architecture + Event Bus

La piattaforma adotta una **Clean Architecture event-driven** (decisione formalizzata in `docs/adr/adr-002-architecture-separation.md`). I componenti non si conoscono direttamente: comunicano tramite un **event bus in-memory thread-safe** (`src/application/event_bus.py`) e contratti a interfacce astratte (`src/domain/interfaces.py`: `IScanner`, `IDetector`, `IRemediation`, `IEventBus`, `ILlmProvider`).

I layer del sorgente (`src/`) sono:

| Layer | Directory | Responsabilità |
|---|---|---|
| **Domain** | `src/domain/` | Entità (`Finding`), eventi, eccezioni, interfacce astratte. Nessuna dipendenza verso l'esterno. |
| **Application** | `src/application/` | Orchestratore delle fasi, event bus, plugin loader, motore di correlazione e scoring. |
| **Infrastructure** | `src/infrastructure/adapters/` | Un adapter per ogni tool esterno (Checkov, Semgrep, Spectral, ZAP, Mitmproxy); traduce l'output grezzo nel modello di dominio. |
| **Core** | `src/core/apiN_*/` | Un modulo autosufficiente per ogni rilevatore OWASP, con proprie `rules/`, `fixtures/`, `tests/`. |
| **Plugins** | `src/core/shadow_api/`, `plugins/detectors/` | Detector dinamici caricati a runtime, comunicano solo via event bus. |
| **Presentation** | `src/presentation/` | Dashboard FastAPI, CLI, template HTML. |

Il beneficio pratico del disaccoppiamento: **aggiungere un nuovo scanner o detector non richiede modifiche all'orchestratore**. Un adapter implementa `IScanner.scan()`; un detector si sottoscrive a eventi (`EVENT_STATIC_SCAN_COMPLETED`, `EVENT_TRAFFIC_CAPTURED`) ed emette `EVENT_FINDING_DETECTED`. L'orchestratore (`src/application/orchestrator.py`) coordina il flusso senza conoscere la logica interna dei singoli tool.

Gli eventi standardizzati (`src/domain/events.py`) sono quattro:

- `event.static_scan.completed`
- `event.traffic.captured`
- `event.finding.detected`
- `event.pipeline.completed`

### 1.3 Il modello unificato: `Finding`

L'entità centrale del dominio è `Finding` (`src/domain/entities.py`). Ogni scanner, statico o dinamico, traduce il proprio output eterogeneo (JSON, XML, alert) in questa struttura comune. È ciò che rende possibile correlare tool diversi. I campi chiave:

- **Identità e classificazione**: `finding_id` (ID deterministico via hash di sorgente + regola + risorsa, per evitare duplicati in correlazione), `source` (`FindingSource`: `CHECKOV`, `SPECTRAL`, `SEMGREP`, `ZAP_DAST`, `RUNTIME_VALIDATOR`, `SHADOW_API`), `category` (`FindingCategory`), `severity` (`Severity`: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`), `confidence` (0.0–1.0).
- **Localizzazione**: `location` (`CodeLocation`: file, riga, snippet) per i finding statici; `api` (`APIContext`: endpoint, metodo, base URL, versione, `requires_authentication`) per quelli API.
- **Prova empirica**: `runtime_evidence` (`RuntimeEvidence`: URL testato, status HTTP, tempo di risposta, header, snippet, `accessible_without_auth`, `rate_limit_detected`).
- **Contesto di rischio**: `risk_context` (`RiskContext`: `internet_exposed`, `sensitive_data_detected`, `public_resource`, `exploitable`).
- **Correlazione**: `correlation_key`, `related_findings`.
- **Natura del rischio**: `nature` (`FindingNature`: `EXPOSURE` vs `HARDENING`, oppure `None` = non classificato) — descritta al §1.5.
- **Metadati OWASP**: `owasp_api_category`, `cwe_id`, `cve_id`, `remediation`, `tags`, `references`, `raw_data`.

`Finding.to_dict()` serializza tutto in JSON, formato consumato da report persistenti e dashboard.

### 1.4 Le quattro fasi della pipeline

Il flusso logico (allineato con `CLAUDE.md` e l'orchestratore D-AST in `src/core/api1_bola/dynamic_orchestrator.py`) si articola in quattro fasi:

1. **Discovery & Static Analysis (IaC & AST).** Gli adapter statici scansionano il target: Checkov sui manifest Terraform, Semgrep sul codice sorgente per mappare rotte e stato di autenticazione, Spectral sui contratti OpenAPI. Ogni tool produce `Finding` di dominio. In questa fase gli endpoint dinamici vengono normalizzati (path parametrici ricondotti a `{id}`) per evitare falsi negativi in correlazione.
2. **Dynamic Seeding.** Prima degli attacchi, lo stato dell'applicazione target viene popolato in modo deterministico (es. utenti `user_a` = vittima e `user_b` = attaccante su Keycloak). Questo elimina le race condition e garantisce la replicabilità scientifica dei test dinamici.
3. **Attack & Runtime Stimulation (D-AST).** Gli attacchi reali vengono eseguiti: ZAP effettua scansioni differenziali con i token delle diverse identità (vittima vs attaccante vs anonimo); Mitmproxy cattura il traffico reale per scovare Shadow API. Uno status `200 OK` dove ci si aspetterebbe un `403` è indice di BOLA o Broken Authorization.
4. **Risk Correlation & Scoring.** Il motore di correlazione unisce i finding statici e dinamici su chiavi di risorsa normalizzate; in presenza di conferma runtime eleva la severità e ricalcola il risk score.

> **Nota sui tempi (rilevante per la validazione sperimentale).** Le scansioni statiche + D-AST leggero durano circa 15–20 secondi. Qualunque scansione che includa il modulo BOLA dura *decine di minuti*, perché esegue attacchi di rete reali con snapshot/rollback dello stato per ogni endpoint mutante (POST/PUT/PATCH/DELETE). Il default testa solo i metodi dichiarati dall'inventario; l'opzione `--all-methods` ripristina il comportamento esaustivo (5 metodi HTTP per endpoint), riportando i tempi ai 30+ minuti storici.

### 1.5 Correlazione, natura del rischio e risk scoring

Tre decisioni architetturali (ADR) governano come i finding vengono fusi e valutati. Sono il cuore del valore aggiunto della piattaforma rispetto a un semplice aggregatore di scanner.

**(a) Correlazione per risorsa** — `src/application/correlation/engine.py`, classe `RiskCorrelationEngine`. I finding vengono raggruppati per **chiave logica di risorsa**:
- per le API: `api:{METODO}:{path normalizzato}` (normalizzazione via `APIEndpointNormalizer`, `src/normalization/normalizer.py`, che riconduce gli ID concreti al placeholder `{id}`);
- per risorse cloud/IaC: `resource:{resource_id}`;
- fallback su file+riga o ID del finding.

Quando un finding statico trova un riscontro a runtime, il motore: allega la `runtime_evidence`, porta la `confidence` a 1.0, **eleva la severità** (HIGH→CRITICAL, altrimenti →HIGH) e imposta la natura a `EXPOSURE`. Questo è il meccanismo che trasforma un "rischio potenziale" in un "rischio dimostrato".

**(b) Natura del rischio: `FindingNature`** — `docs/adr/adr-004-finding-nature.md`. Distingue i controlli di **esposizione** (`EXPOSURE`: un varco realmente sfruttabile — ACL pubblica, policy IAM con privilegi jolly, endpoint senza autorizzazione, segreto cablato) dai controlli di **irrobustimento** (`HARDENING`: difesa in profondità o conformità — logging, versioning, lifecycle, notifiche). Il problema che risolve: senza questa distinzione un bucket privato e ben protetto riceveva lo stesso punteggio di uno pubblico solo perché gli mancavano i log. Quando più finding condividono una risorsa, la **voce rappresentativa** è scelta per natura (`EXPOSURE` > non classificato > `HARDENING`) e poi per severità, mai "il primo incontrato"; i controlli assorbiti restano in `raw_data["aggregated_checks"]`. Per Checkov, natura e severità di ogni controllo provengono da un **catalogo semantico esterno** (`config/scanner_configs/checkov-policy-catalog.yaml`, gestito da `checkov_policy_catalog.py`): le parole chiave operano sul *nome ufficiale* del controllo, non sull'ID opaco (`CKV_AWS_53`).

**(c) Risk scoring pesato** — `docs/adr/adr-001-risk-scoring.md` e `docs/adr/adr-005-risk-scoring.md`. La formula:

```
R = min(10, wS·S + wC·(10·C) + wX·X)
```

con pesi di default `wS = 0.6`, `wC = 0.2`, `wX = 0.2` (tutti in `config/risk_scoring.yaml`, sovrascrivibili). Dove:
- **S** = punteggio di severità (`CRITICAL = 10`, `HIGH = 7`, `MEDIUM = 4.5`, `LOW = 2`, `INFO = 0`);
- **C** = confidenza (0–1), *derivata dalla precisione della sorgente*, non un letterale: per Checkov dipende da come il catalogo ha classificato il controllo (match esatto per ID 1.0 > prefisso 0.9 > parola chiave 0.8 > default 0.6); per ZAP dal livello dell'alert; per Semgrep 0.95 se trova autenticazione, 0.7 se ne deduce l'assenza; una conferma empirica a runtime forza `C = 1.0`;
- **X** = contesto di esposizione, *dichiarato dalla sorgente non inferito dalla categoria*: +4 se esposto a Internet, +4 dati sensibili, +2 risorsa pubblica; `default_other = 3` senza contesto; **`X = 0` per i finding `HARDENING`** (una difesa mancante non è un vettore d'accesso).

Esempi risultanti (confidenza 1): ACL pubblica in lettura → `CRITICAL`, esposta+pubblica → **9.2**; policy IAM `*`/`*` → **8.6**; controllo non classificato `MEDIUM` → **5.3**; hardening `LOW` (notifiche assenti) → **3.2**.

### 1.6 Le due famiglie di misure di rilevamento

Le misure implementate si dividono in due famiglie complementari, entrambe convergenti sul modello `Finding`:

- **Adapter di scanner esterni** (`src/infrastructure/adapters/`): incapsulano tool di mercato — Checkov (IaC), Semgrep (SAST), Spectral (OpenAPI), ZAP (DAST), Mitmproxy (cattura traffico). Il loro compito è *traduttivo*: eseguire il tool e mappare l'output nel dominio.
- **Moduli Core proprietari** (`src/core/apiN_*/`): implementano la logica di rilevamento specifica per ciascuna categoria OWASP, spesso combinando più segnali (AST del codice, config, spec OpenAPI, traffico runtime). Sono il contributo originale della piattaforma.

La Parte II descrive ciascuna misura singolarmente.

### 1.7 Mappatura sintetica OWASP → moduli

| OWASP API (2023) | Modulo Core | Tecnica dominante |
|---|---|---|
| API1 — BOLA | `src/core/api1_bola/` | D-AST differenziale con seeding, snapshot/rollback, ZAP |
| API2 — Broken Authentication | `src/core/api2_broken_auth/` | Discovery LLM + AST + knowledge graph + test dinamici |
| API3 — BOPLA | `src/core/api3_bopla/` | Discovery proprietà + inferenza autorizzazione + test T01–T07 |
| API4 — Unrestricted Resource Consumption | `src/core/api4_resource_consumption/` | Analisi a 3 layer (AST / config / OpenAPI) |
| API5 — BFLA | `src/core/api5_bfla/` | Analisi a 3 layer con priorità di regola |
| API7 — SSRF | `src/core/api7_ssrf/` | Regole Semgrep dedicate + arricchimento OpenAPI |
| API8 — Security Misconfiguration | `src/core/api8_security_misconfig/` | Regole AST/testo + filtro di confidenza |
| API10 — Unsafe Consumption | `src/core/api10_unsafe_consumption/` | Regole AST + filtro di confidenza |
| (trasversale) Shadow API | `src/core/shadow_api/` | Plugin event-driven: traffico osservato vs rotte statiche |

> Le categorie API6 (Sensitive Business Flows) e API9 (Improper Inventory Management) non hanno un modulo Core dedicato; aspetti di inventario sono coperti dal detector Shadow API.

---

## Parte II — Implementazione delle singole misure di rilevamento

Ogni sottosezione segue lo schema: **ruolo → input → tecnica → output nel modello di dominio → note implementative**.

### 2.1 Adapter statici (Infrastructure Layer)

#### 2.1.1 Checkov — misconfiguration IaC (`checkov_adapter.py`)

- **Ruolo.** Analisi statica dei manifest di infrastruttura (Terraform/HCL) per rilevare misconfiguration cloud (S3, IAM, API Gateway, Lambda, rete, ecc.).
- **Input.** La directory target passata a `scan()` (perimetro sempre definito via `-d`; il file `.checkov.yaml` governa solo le opzioni accessorie).
- **Tecnica.** Esegue Checkov come subprocess, ne parsa l'output JSON. Per ogni controllo fallito costruisce un `Finding` la cui **natura e severità provengono dal catalogo semantico** (`CheckovPolicyCatalog`), non da regole cablate sull'ID. L'ordine di risoluzione del catalogo: mappatura esplicita per ID → famiglie per prefisso (`CKV_SECRET_*`) → parole chiave sul nome ufficiale (con precedenza ai termini difensivi come `encrypt`, `kms`, `waf`) → default (non classificato / `MEDIUM`).
- **Output.** `Finding` con `source=CHECKOV`, categoria mappata (IAM, STORAGE, NETWORK…), `nature`, e `RiskContext(internet_exposed, public_resource, sensitive_data_detected)` allegato **solo** ai controlli con flag `public: true` nel catalogo.
- **Note.** Se il catalogo manca o non è leggibile, tutto ricade su "non classificato / MEDIUM": degradazione sicura, nessuna pipeline si rompe. La confidenza del finding dipende dalla precisione del match nel catalogo (ADR-005).

#### 2.1.2 Semgrep — inventario endpoint e stato auth (`semgrep_adapter.py`)

- **Ruolo.** Mappatura delle rotte API dal codice sorgente e rilevamento dello **stato di autenticazione** di ciascun endpoint.
- **Input.** Directory del codice sorgente + ruleset Semgrep (`DEFAULT_SEMGREP_RULESET_PATH`).
- **Tecnica.** Esegue Semgrep come subprocess; con parsing euristico associa a ogni match la rotta, il metodo e la presenza/assenza di decoratori o handler di autenticazione. Gli endpoint vengono normalizzati (`APIEndpointNormalizer`) per la successiva correlazione.
- **Output.** `Finding` con `source=SEMGREP`, `APIContext` popolato (endpoint, metodo, `requires_authentication`). Agli endpoint dedotti come *senza autenticazione* viene allegato `RiskContext(internet_exposed=True)`.
- **Note.** La confidenza distingue riscontro positivo (auth trovata, 0.95) da assenza dedotta (0.7): l'assenza è un'inferenza statica, non una certezza.

#### 2.1.3 Spectral — contratti OpenAPI vs OWASP (`spectral_adapter.py`)

- **Ruolo.** Linting dei contratti OpenAPI/Swagger contro un ruleset di sicurezza OWASP.
- **Input.** File di specifica OpenAPI; ruleset `config/scanner_configs/spectral-owasp.yaml`.
- **Tecnica.** Esegue Spectral CLI come subprocess e mappa ogni violazione (alert del linter) in un `Finding`.
- **Output.** `Finding` con `source=SPECTRAL`, confidenza 1.0 (la violazione di contratto è deterministica), `RiskContext(internet_exposed=True)` sugli endpoint dichiarati senza autenticazione.
- **Note.** Rileva rischi a livello di *contratto* (es. metodi senza `security`, schema di risposta troppo permissivo) prima ancora che l'API sia in esecuzione.

### 2.2 Adapter dinamici (D-AST)

#### 2.2.1 OWASP ZAP — scansione differenziale (`zap_adapter.py`)

- **Ruolo.** Stimolare l'applicazione target generando traffico reale e raccogliere gli alert DAST.
- **Tecnica.** Dialoga con il daemon ZAP (`ZAPv2`); esegue spider e active scan, raccoglie gli alert e li trasforma in `Finding` (`source=ZAP_DAST`). Nel contesto BOLA/Broken Auth la scansione è **differenziale**: lo stesso endpoint viene sollecitato con i token di identità diverse (vittima, attaccante, anonimo) e le risposte vengono confrontate.
- **Output.** `Finding` con `RuntimeEvidence` (status, tempi, header) e confidenza derivata dal livello dell'alert ZAP (`User Confirmed` 1.0 … `Low` 0.5; gli alert `False Positive` vengono scartati).
- **Note.** Il polling dell'active scan è limitato da `ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS` (default 300); allo scadere chiama `ascan.stop_all_scans()`.

#### 2.2.2 Mitmproxy — cattura del traffico (`mitmproxy_adapter.py` + `mitmproxy/addon.py`)

- **Ruolo.** Intercettare il traffico HTTP reale verso l'applicazione e persisterlo per l'analisi dinamica (alimenta la rilevazione di Shadow API).
- **Tecnica.** Un addon mitmproxy (`src/infrastructure/adapters/mitmproxy/addon.py`) cattura le richieste e le salva su file JSON; l'adapter (`MitmproxyClientAdapter.load_captured_traffic()`) le ricarica come lista di dizionari.
- **Output.** Traffico strutturato pubblicato sul bus come `EVENT_TRAFFIC_CAPTURED`, consumato dai detector dinamici.

### 2.3 Modulo API1 — BOLA (`src/core/api1_bola/`)

È il modulo più articolato e il cuore della componente dinamica. Implementa un flusso D-AST deterministico **"Discovery → Seeding → Attack"** orchestrato da `DynamicOrchestrator` (`dynamic_orchestrator.py`), pensato per azzerare falsi positivi e falsi negativi tipici del DAST senza stato.

- **Discovery.** `discovery/object_discovery.py` (`ObjectReferenceDiscoveryEngine`) e `discovery/ownership_inference.py` (`OwnershipInferenceEngine`) individuano gli endpoint che espongono riferimenti a oggetti e ne inferiscono la proprietà; i path vengono unificati sotto `{id}`.
- **Seeding.** Popolamento deterministico dello stato con risorse assegnate a vittima (User A) e attaccante (User B), per rendere il test ripetibile.
- **Attack.** `attack_vector.py` (`ContextAwareAttackGenerator`) decodifica i token JWT reali (claim `sub`, UUID Keycloak) ed esegue la stimolazione incrociata multimetodo: l'attaccante prova ad accedere alle risorse della vittima.
- **Validazione semantica.** `assertion_engine.py` (`APIAssertionEngine`) applica **Differential Testing**: non si limita allo status code, ma confronta *semanticamente* i body JSON (rimuovendo campi volatili dichiarati in `config/bola.yaml`) e segnala un caso anche quando una risposta 2xx dell'attaccante contiene l'identificativo della vittima. Riconosce anche blocchi applicativi mascherati da `200 OK` tramite parole chiave d'errore.
- **Matrice dei privilegi.** `role_matrix.py` (`AccessControlMatrix`) classifica la violazione come **orizzontale** o **verticale** confrontando i *ranghi* dei ruoli (gerarchia letta da `config/bola.yaml`, non cablata: funziona anche con `owner > editor > viewer`).
- **Integrità dello stato.** `state_manager.py` (`APIStateEngine`) esegue snapshot/rollback dello stato in memoria del target prima/dopo le richieste distruttive (PUT/DELETE), evitando la *test cross-contamination*. I path di snapshot/rollback provengono dal contratto del bersaglio (`config/bola_target.yaml`, sezione `harness`).
- **Robustezza della cancellazione.** La cancellazione è un `threading.Event` per-istanza (`DynamicOrchestrator.cancel()`), mai stato di classe: il server tiene un registro `scan_id → orchestrator` e `POST /cancel-bola-scan?scan_id=…` ferma solo quella scansione.

Il modulo è riutilizzabile su repo target arbitrarie cooperanti (runner `run_bola_repo_target.py`, `make bola-repo-target`).

### 2.4 Modulo API2 — Broken Authentication (`src/core/api2_broken_auth/`)

Pipeline a più fasi che costruisce un modello dell'autenticazione dell'applicazione e lo verifica dinamicamente.

- **Fase 1 — Discovery (`discovery.py`).** Identifica lo stack tecnologico e le librerie di autenticazione dai manifest/config di progetto, usando un **LLM locale (Ollama)** con parsing robusto e recovery degli errori. Definisce le categorie di vulnerabilità (`VulnerabilityCategory`).
- **Fase 2 — AST (`ast_parser.py`).** Analizza il codice sorgente (multi-linguaggio) per estrarre funzioni/middleware di auth e, quando presente, il segreto JWT cablato.
- **Fase 3 — Intelligence (`authentication_intelligence.py`).** Correla Discovery, AST, spec OpenAPI e traffico runtime in un `AuthenticationKnowledgeGraph`: tipo di autenticazione, IdP, endpoint di login/refresh/logout, claim JWT, ruoli, middleware, endpoint protetti, validazione JWKS, rotazione refresh token, MFA, ecc.
- **Fase 4 — Dynamic Tester (`dynamic_tester.py`).** Esegue test dinamici asincroni (`httpx`) contro l'applicazione in esecuzione: ad esempio uso di token scaduti firmati validamente (quando il segreto è noto dall'AST), verifica degli endpoint di autenticazione. Con health check preventivi sul target.
- **Reporting (`reporter.py`).** Aggrega gli esiti.
- **Note.** Richiede Keycloak attivo per il runner dedicato (`run_broken_auth_scan.py`).

### 2.5 Modulo API3 — BOPLA (`src/core/api3_bopla/`)

Rileva il **Broken Object Property Level Authorization**: accesso o modifica non autorizzati a *singole proprietà* di un oggetto (mass assignment, esposizione eccessiva di dati). Coordinato da `BOPLAOrchestrator` (`orchestrator.py`), resiliente a input parziali (graceful degradation).

- **Discovery proprietà (`discovery.py`, `PropertyDiscoveryEngine`).** Costruisce l'inventario delle proprietà degli oggetti (`PropertyInventory`).
- **Inferenza autorizzazione (`property_inference.py`).** `PropertyAuthorizationInferenceEngine` deduce quali proprietà sono soggette a controlli di autorizzazione, analizzando codice sorgente (AST + regex, riusando il parser di API2), spec OpenAPI e traffico runtime; produce `PropertyEvidence` e un `PropertyAuthorizationGraph`. Usa un dizionario di parole chiave d'autorizzazione (`current_user`, `role`, `admin`, `token`, `identity`…).
- **Test dinamici (`dynamic_tester.py`, `BOPLADynamicTester`).** Esegue una batteria di test mirati **T01–T07** contro il base URL usando l'inventario, le evidenze e la matrice di header per identità, con soglia di confidenza configurabile.
- **Modelli (`models.py`).** `DynamicPropertyFinding`, `PropertyEvidence`, ecc.
- **Note.** Usa Keycloak se attivo, altrimenti ricade su mock (`run_bopla_scan.py`); esiste una demo offline con `requests` mockato (`run_bopla_dynamic_demo.py`).

### 2.6 Modulo API4 — Unrestricted Resource Consumption (`src/core/api4_resource_consumption/`)

Rileva l'assenza di limiti su risorse (rate limiting, paginazione, dimensioni di payload/upload) che espone a DoS applicativi.

- **Tecnica.** Analisi statica **a tre layer**, orchestrata da `detector.analyze()`:
  - `layer1_ast` — pattern nel codice sorgente;
  - `layer2_config` — file di configurazione;
  - `layer3_openapi` — dichiarazioni nel contratto OpenAPI (con opzione `enrich_spec` per arricchire la spec in-place).
- **Output.** `ResourceConsumptionReport` con `ResourceConsumptionFinding`, segnali di copertura per categoria (`coverage_signals`) e riepilogo per severità/categoria/layer.

### 2.7 Modulo API5 — BFLA (`src/core/api5_bfla/`)

Rileva il **Broken Function Level Authorization**: accesso a funzioni/endpoint amministrativi da parte di utenti non privilegiati.

- **Tecnica.** Analisi a tre layer analoga ad API4 (`layer1_ast` con estrazione endpoint, `layer2_config`, `layer3_openapi`), con un layer combinato `ast+openapi`.
- **Priorità delle regole.** Un dizionario `RULE_PRIORITY` ordina le regole (es. `BF-006` > `BF-004`…) per selezionare il finding rappresentativo quando più regole colpiscono lo stesso punto.
- **Output.** `FunctionAuthzReport` con `FunctionAuthzFinding`, coverage e summary (severità fino a `CRITICAL`).

### 2.8 Modulo API7 — SSRF (`src/core/api7_ssrf/`)

Rileva la **Server-Side Request Forgery**: input utente che confluisce in richieste server-side verso URL controllabili dall'attaccante.

- **Tecnica.** Layer principale basato su **regole Semgrep dedicate** (`rules/semgrep_rules.yml`) eseguite via `semgrep_runner`; l'output viene normalizzato (`normalizer.normalize_semgrep_output`) in `SsrfFinding`. Un layer OpenAPI (`layer3_openapi`) può arricchire l'analisi.
- **Robustezza.** In caso di timeout Semgrep (`SemgrepTimeoutError`) non va in crash: restituisce finding parziali con warning.
- **Output.** `SsrfReport` con findings normalizzati e metadati d'analisi.

### 2.9 Modulo API8 — Security Misconfiguration (`src/core/api8_security_misconfig/`)

Rileva misconfiguration a livello applicativo tramite un set di **regole AST/testo** applicate a ogni file sorgente (`detector.analyze()`):

- `cors_wildcard` — CORS con `*`;
- `debug_mode` — debug abilitato;
- `verbose_error_handler` — gestione errori troppo verbosa (information disclosure);
- `hardcoded_secret` — segreti cablati;
- `missing_security_headers` — regola *globale* (SC-004) che valuta il target nel suo insieme.

**Filtro di confidenza.** Vengono scartati i finding con `confidence < 0.70`, per contenere i falsi positivi. Output: `MisconfigReport` con `MisconfigFinding`.

### 2.10 Modulo API10 — Unsafe Consumption of APIs (`src/core/api10_unsafe_consumption/`)

Rileva il consumo non sicuro di API di terze parti tramite regole AST:

- `unvalidated_external_data` — dati esterni usati senza validazione;
- `http_instead_of_https` — chiamate in chiaro;
- `blind_redirect_following` — redirect seguiti ciecamente.

Stesso **filtro di confidenza ≥ 0.70**. Output: `UnsafeConsumptionReport` con `UnsafeConsumptionFinding`, coverage e summary.

### 2.11 Detector Shadow API (`src/core/shadow_api/shadow_api_detector.py`)

- **Ruolo.** Individuare **Shadow API**: endpoint attivi a runtime ma non documentati/dichiarati nel codice.
- **Tecnica.** È un **plugin event-driven** (`ShadowAPIDetectorPlugin`, implementa `IDetector`). Si sottoscrive a `EVENT_STATIC_SCAN_COMPLETED` (per costruire l'insieme delle rotte statiche note in formato `METHOD:PATH`) e a `EVENT_TRAFFIC_CAPTURED` (traffico Mitmproxy). Qualsiasi endpoint osservato nel traffico ma assente dall'inventario statico solleva un alert critico. Il confronto avviene su path normalizzati (`APIEndpointNormalizer`), così le varianti parametriche non generano falsi positivi.
- **Output.** `Finding` con `source=SHADOW_API`, `RuntimeEvidence` e `RiskContext`; comunica esclusivamente via bus (`EVENT_FINDING_DETECTED`), senza conoscere gli altri componenti — esempio concreto del disaccoppiamento di ADR-002.

### 2.12 Remediation Intelligence (trasversale)

A valle del rilevamento, il motore di *Remediation Intelligence* (`src/application/remediation/remediation_engine.py`) produce raccomandazioni di correzione. Dipende solo dalla porta `ILlmProvider`: il composition root (`server.py`) inietta `OllamaAdapter`; in assenza di provider o con Ollama offline ricade su una **knowledge base deterministica** locale (`src/infrastructure/llm/knowledge_base/`), mantenendo i test verdi in entrambi i casi.

---

## Parte III — Sintesi per la stesura del capitolo

Punti da valorizzare nel testo di tesi:

1. **Il contributo originale non è l'integrazione dei tool, ma la correlazione.** Checkov, Semgrep, Spectral e ZAP esistono già; il valore è il modello `Finding` unificato + il motore che eleva a `EXPOSURE`/severità superiore i rischi con conferma empirica runtime, distinguendoli dall'`HARDENING`.
2. **Determinismo scientifico dei test dinamici.** Il pattern Discovery → Seeding → Attack, con snapshot/rollback dello stato e differential testing semantico, è ciò che rende i risultati BOLA riproducibili e a bassa rumorosità.
3. **Configurabilità senza toccare il codice.** Catalogo Checkov, gerarchia dei ruoli BOLA, parametri di scoring e ruleset vivono in file di configurazione esterni (degradazione sicura se assenti).
4. **Estensibilità event-driven.** Un nuovo rilevatore si aggiunge come adapter (`IScanner`) o plugin (`IDetector`) senza modificare l'orchestratore.
5. **Onestà sui limiti.** Categorie API6/API9 non coperte da moduli dedicati; la natura assegnata da catalogo statico non conosce l'intento (un bucket pubblico può essere legittimo); i filtri di confidenza (≥0.70) e le inferenze statiche restano euristiche dichiarate.

> **Fonti nel repository** (per verifica/citazione): `docs/adr/adr-001-risk-scoring.md`, `adr-002-architecture-separation.md`, `adr-004-finding-nature.md`, `adr-005-risk-scoring.md`; `src/domain/entities.py`; `src/application/correlation/engine.py`; `src/application/orchestrator.py`; moduli `src/core/apiN_*/`; adapter `src/infrastructure/adapters/`.
