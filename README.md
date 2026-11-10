# virtual-wallet-openid4vp

Wallet de test côté serveur pour éprouver des **verifiers OpenID4VP**, et recevoir des attestations d'un émetteur
**OpenID4VCI** (grant pré-autorisé) pour les présenter ensuite. Formats visés : SD-JWT VC et mdoc (ISO 18013-5).

Stack : Java 21, Spring Boot 4.1, Maven, [eudi-lib-jvm-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt) (protocole),
[eudi-lib-jvm-sdjwt-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt) (SD-JWT VC), [Multipaz](https://github.com/openwallet-foundation/multipaz) (mdoc).

## Structure

Packages par domaine sous `io.github.wallet` (Java dans `src/main/java`, Kotlin dans `src/main/kotlin`) :

| Package | Contenu |
|---|---|
| `config` | Configuration globale : `WalletProperties`, base SQLite, trace HTTP entrante |
| `<domaine>.config` | Déclaration des beans du domaine (`@Bean`, pas de `@Service` / `@Repository`) |
| `<domaine>.dto` | DTO, suffixés `DTO` |
| `<domaine>.service` | Services ; `service.dao` : accès base (`IdentityDao`) |
| `<domaine>.support` | Classes de support (enums, clés, adaptateur EUDI…) |
| `<domaine>.web` | Controllers |

Domaines : `identity` (identités et claims), `credentials` (autorité de test, émission, stock), `presentation`
(flux OpenID4VP), `issuance` (réception OpenID4VCI).

Le code est en Java, sauf les classes qui appellent directement des API Kotlin (fonctions `suspend`, value classes,
DSL de construction) des libs EUDI et Multipaz. Elles exposent une API Java bloquante :

| Classe Kotlin | Pourquoi Kotlin |
|---|---|
| `presentation.support.openid4vp.OpenId4VpWalletClient` | API `suspend` et value classes de la lib OpenID4VP |
| `presentation.support.openid4vp.WalletConfigFactory` | arguments par défaut et value classes de `OpenId4VPConfig` |
| `presentation.support.openid4vp.VerifierTrust` | implémente l'interface `suspend` `X509CertificateTrust` |
| `presentation.support.openid4vp.ExchangeLog` | intercepteur Ktor (`suspend`) |
| `presentation.support.DcqlMatcher` | modèle DCQL fait de value classes |
| `presentation.support.PresentationBuilder` | présentation SD-JWT et signature mdoc (`suspend`) |
| `credentials.service.TestCredentialIssuer` | DSL `sdJwt { }` et signature COSE (`suspend`) |
| `credentials.support.WalletKeyMaterial(Loader)` | génération de clés et certificats Multipaz (`suspend`) |
| `credentials.support.ReceivedCredentialReader` | vérification SD-JWT (`Result`, `suspend`) et décodage COSE/MSO Multipaz |

## Logs

Log4j2 (`src/main/resources/log4j2-spring.xml`), console + `logs/wallet.log` (rotation quotidienne ou 10 Mo).
Chaque requête entrante porte un `requestId` ; les appels vers un verifier portent l'id de la présentation.

| Catégorie | INFO | DEBUG |
|---|---|---|
| `io.github.wallet.http.in` | méthode, URI, statut, durée des appels `/api` | en-têtes et corps (8 Ko max), autres chemins |
| `io.github.wallet.http.out` | méthode, URL, statut, durée des appels aux verifiers et émetteurs | en-têtes et corps (dont le `vp_token`) |
| `io.github.wallet` | opérations métier (identités, émission, présentation) | détail (requêtes SQL, matching DCQL, claims émis) |

Exemple : `./mvnw spring-boot:run -Dspring-boot.run.arguments=--logging.level.io.github.wallet=DEBUG`.

## Identités

Les identités (nom, prénom, date de naissance + claims additionnels) sont stockées en SQLite dans
`<wallet.data-dir>/wallet.db`. Une base vide est initialisée avec une personne fictive (Camille MARTIN).
Chaque identité reçoit 3 credentials, liés à la même clé wallet P-256 et **réémis à chaque modification** :

| id | format | type |
|---|---|---|
| `<identité>:pid-sd-jwt` | `dc+sd-jwt` | `urn:eudi:pid:1` |
| `<identité>:pid-mdoc` | `mso_mdoc` | `eu.europa.ec.eudi.pid.1` |
| `<identité>:mdl-mdoc` | `mso_mdoc` | `org.iso.18013.5.1.mDL` |

Claims additionnels : `name`, `type` (`STRING`, `NUMBER`, `BOOLEAN`, `DATE`), `value`, `scope` :
`ALL` (PID SD-JWT et PID mdoc), `SD_JWT` (un nom pointé comme `address.locality` crée un objet imbriqué, divulgable
à chaque niveau) ou `MDOC` (namespace `eu.europa.ec.eudi.pid.1`). Les claims posés par l'émetteur (`family_name`,
`birthdate`, `age_*`, `issuing_*`, `iss`, `cnf`…) ne peuvent pas être surchargés. Le mDL ne prend que les champs de base.

| Méthode | Chemin | Rôle |
|---|---|---|
| `GET` / `POST` | `/api/identities` | liste / création `{"familyName","givenName","birthDate","claims":[…]}` |
| `GET` / `PUT` / `DELETE` | `/api/identities/{id}` | lecture / nom, prénom, date / suppression |
| `POST` | `/api/identities/{id}/claims` | ajout d'un claim |
| `PUT` / `DELETE` | `/api/identities/{id}/claims/{claimId}` | modification / suppression d'un claim |

À la présentation, `POST /api/presentations` accepte `identityId`. Sans lui, le wallet prend la première identité qui
répond à toutes les requêtes DCQL : il ne mélange jamais les credentials de deux identités dans une réponse.

Chaîne de confiance : une IACA de test (racine auto-signée) signe le Document Signer mdoc et le certificat de
l'émetteur SD-JWT (envoyé en `x5c`). Les clés sont stockées en PEM dans `wallet.data-dir` et réutilisées
au redémarrage. **Le verifier doit faire confiance à cette racine** : `GET /api/trust/iaca.pem`.

## Présenter des credentials

Ouvrir `http://localhost:8080/` et coller la requête du verifier (`openid4vp://…`, contenu du QR code), ou l'envoyer par
`POST /api/presentations` (Bruno, script…). `http://localhost:8080/?request=<url-encodée>` l'envoie directement.

Toute requête reçue est **mise en attente** de la décision du porteur, comme sur un vrai wallet : la page interroge
`GET /api/presentations/pending` toutes les 2 s et affiche une carte par demande, avec le verifier, les credentials
demandés et chaque claim avec **la valeur qui sera divulguée**. Le porteur clique **Partager** ou **Refuser** ;
une requête invalide peut être renvoyée au verifier (si possible) ou **ignorée**. Le titre de l'onglet indique le
nombre de demandes en attente. Les demandes sont gardées en mémoire (perdues au redémarrage).

Ce qui est géré :
- résolution via la lib EUDI : `request_uri` (GET/POST), JAR signé, préfixes `x509_san_dns`, `x509_hash`, `redirect_uri` ;
- DCQL : format, `vct_values` / `doctype_value`, `claims` (chemins, `values`), `claim_sets` (première option satisfaisable) ;
- SD-JWT VC : divulgation sélective des seuls claims demandés + KB-JWT (`aud` = client_id, `nonce`) ;
- mdoc : `DeviceResponse` signé par la clé wallet, SessionTranscript `OpenID4VPHandover` (OpenID4VP 1.0, annexe B.2.6.1) ;
- réponse `direct_post` ou `direct_post.jwt` (ECDH-ES, A128GCM/A256GCM).

Non géré pour l'instant : `credential_sets` (chaque requête est servie si possible), `transaction_data`,
réponse mdoc en mode `query`/`fragment`, DC API.

### API

| Méthode | Chemin | Rôle |
|---|---|---|
| `GET` | `/api/credentials` | credentials et claims |
| `GET` | `/api/trust/iaca.pem` | racine de l'autorité de test |
| `POST` | `/api/presentations` `{"requestUri": "…"}` | résout la requête, la met en attente, renvoie un `id` et la correspondance DCQL |
| `GET` | `/api/presentations/pending` | demandes en attente, de la plus ancienne à la plus récente (claims demandés + valeurs) |
| `GET` / `DELETE` | `/api/presentations/{id}` | une demande en attente / l'ignorer sans répondre au verifier |
| `POST` | `/api/presentations/{id}/accept` | envoie le `vp_token` |
| `POST` | `/api/presentations/{id}/decline` | envoie `access_denied` |
| `POST` | `/api/presentations/{id}/report-error` | renvoie l'erreur de résolution au verifier (si possible) |
| `GET` | `/api/presentations/faults` | défauts injectables |
| `GET` | `/api/presentations/{id}/exchanges` | échanges HTTP d'une présentation |
| `GET` | `/api/presentations/exchanges` | 500 derniers échanges HTTP |

## Recevoir une attestation (OpenID4VCI)

Scénario de [l'animation](docs/openid4vci-animation.html) (PR #2) : le porteur, déjà connecté chez l'émetteur, y demande
l'enrôlement de son wallet ; l'émetteur affiche une Credential Offer pré-autorisée. Coller l'offre dans la page
(*Recevoir une attestation*), ou `POST /api/offers`, ou ouvrir `http://localhost:8080/?offer=<url-encodée>`.

1. **Offre** : `openid-credential-offer://?credential_offer=…` (par valeur), `…?credential_offer_uri=…` (par
   référence) ou JSON brut. Seul le grant `pre-authorized_code` est géré, avec ou sans `tx_code`.
2. **Metadata** : `/.well-known/openid-credential-issuer` puis `/.well-known/oauth-authorization-server` (à
   défaut `openid-configuration`) de l'AS de l'offre, sinon du premier `authorization_servers`, sinon de
   l'émetteur. Forme normative (suffixe inséré avant le chemin), puis forme concaténée si 404.
   `credential_issuer` doit être identique à celui de l'offre.
3. L'offre est **mise en attente** : la carte affiche l'émetteur, les credentials proposés, le champ `tx_code`
   et l'identité qui les recevra. **Accepter** déroule la suite ; **Ignorer** n'envoie rien à l'émetteur.
4. **Token** : `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`, `pre-authorized_code`, `tx_code`.
5. **Proof** : par credential, une **clé P-256 neuve** (deux credentials ne sont pas corrélables par leur clé) et un
   proof JWT `openid4vci-proof+jwt` (`jwk`, `aud` = `credential_issuer`, `iat`, `nonce` du nonce endpoint s'il
   existe, `c_nonce` du token sinon ; pas d'`iss` : accès anonyme).
6. **Credential** : `credential_configuration_id` (ou `credential_identifier` si le token en renvoie), `proofs.jwt`.
   Sur `invalid_nonce`, un second essai avec un nouveau nonce. Puis `credential_accepted` au notification endpoint.
7. **Contrôle et stockage** : le credential est lu (SD-JWT : signature vérifiée si `x5c`, `typ`, `vct`, `cnf` = clé
   du proof ; mdoc : signature `x5chain`, empreintes du MSO, `deviceKey` = clé du proof). Une anomalie non
   bloquante devient un **avertissement** (affiché et conservé) : le credential reste présentable, pour tester ce
   qu'en fait un verifier. Il est stocké en SQLite (table `received_credential`, avec la clé privée en JWK) et
   rechargé au démarrage.

Le credential reçu rejoint ceux de l'identité choisie et se **présente en OpenID4VP** comme les autres : le KB-JWT
(ou la DeviceSignature mdoc) est signé par la clé enregistrée à l'enrôlement. Il n'est pas touché par les
modifications de l'identité (contrairement aux credentials de test, réémis) et disparaît avec elle.

Non géré : grant `authorization_code`, DPoP (l'offre l'indique quand l'AS l'annonce), chiffrement de la réponse
credential, metadata signées, émission différée, attestation de clé, credentials autres que SD-JWT VC / mdoc.
Le wallet ne joue pas l'émetteur : l'application à tester le fait.

| Méthode | Chemin | Rôle |
|---|---|---|
| `POST` | `/api/offers` `{"offer": "…"}` | lit l'offre et les metadata, la met en attente, renvoie un `id` |
| `GET` | `/api/offers/pending` | offres en attente |
| `GET` / `DELETE` | `/api/offers/{id}` | une offre / l'ignorer |
| `POST` | `/api/offers/{id}/accept` `{"txCode", "identityId", "faults"}` | émission ; **502** si l'émetteur refuse (`step`, `oauthError`) |
| `GET` | `/api/offers/faults` | défauts injectables |
| `GET` | `/api/offers/{id}/exchanges`, `/api/offers/exchanges` | échanges HTTP avec l'émetteur |
| `GET` | `/api/received-credentials` | credentials reçus et leurs avertissements |
| `DELETE` | `/api/received-credentials/{id}` | supprime un credential reçu |

### Tester la robustesse d'un émetteur

`accept` prend aussi `faults` ; un émetteur correct doit refuser chacun :

| Défaut | Effet |
|---|---|
| `PROOF_WRONG_AUDIENCE` / `PROOF_WRONG_NONCE` / `PROOF_NO_NONCE` | `aud` / `nonce` du proof incorrect ou absent (pas de nouvel essai) |
| `PROOF_STALE` | `iat` du proof daté de la veille |
| `PROOF_WRONG_TYP` | `typ` `JWT` au lieu de `openid4vci-proof+jwt` |
| `PROOF_BAD_SIGNATURE` / `PROOF_KEY_MISMATCH` | signature altérée / faite par une autre clé que le `jwk` |
| `ACCESS_TOKEN_TAMPERED` | access token altéré au credential endpoint |
| `TOKEN_REPLAY` | rejoue le `pre-authorized_code` après usage ; avertissement si l'émetteur l'accepte |

`IssuanceApiTests` déroule le scénario complet contre un émetteur de test (offre avec `tx_code`, nonce, proof,
SD-JWT VC `account_id`) puis la présentation OpenID4VP du credential reçu.

## Tester la robustesse d'un verifier

`accept` prend un corps optionnel `{"faults": ["SD_JWT_WRONG_NONCE", …]}` (cases à cocher dans la page). Un verifier
correct doit rejeter chacun de ces défauts, sauf `OVER_DISCLOSURE` :

| Défaut | Effet |
|---|---|
| `SD_JWT_WRONG_NONCE` / `SD_JWT_WRONG_AUDIENCE` | `nonce` / `aud` du KB-JWT incorrect |
| `SD_JWT_STALE_KB` | `iat` du KB-JWT vieux de 24 h |
| `SD_JWT_BAD_KB_SIGNATURE` / `SD_JWT_KB_WRONG_KEY` | KB-JWT altéré ou signé par une clé autre que `cnf` |
| `SD_JWT_NO_KB` | pas de KB-JWT |
| `SD_JWT_BAD_ISSUER_SIGNATURE` / `SD_JWT_FORGED_DISCLOSURE` | signature émetteur altérée / disclosure modifiée |
| `MDOC_WRONG_NONCE` / `MDOC_WRONG_CLIENT_ID` | SessionTranscript calculé avec d'autres valeurs |
| `MDOC_DEVICE_KEY_MISMATCH` | DeviceSignature faite avec une clé autre que celle du MSO |
| `MDOC_TAMPERED_ELEMENT` / `MDOC_BAD_ISSUER_SIGNATURE` | élément modifié / issuerAuth altéré |
| `VP_TOKEN_WRONG_QUERY_ID` | `vp_token` indexé par un id DCQL inconnu |
| `OVER_DISCLOSURE` | divulgue tout le credential (valide, mais à signaler côté vie privée) |

`FaultInjectionTest` vérifie que chaque défaut est bien détecté par des vérifications indépendantes
(lib SD-JWT EUDI et vérification `DeviceResponse` de Multipaz).

## Essai contre le verifier de référence EUDI

`verifier-backend.eudiw.dev` (requêtes signées `x509_hash`, réponse `direct_post.jwt` ECDH-ES) :

1. lancer le wallet avec `--wallet.trust-all-verifiers=true` (ou ajouter la racine du verifier aux trust anchors) ;
2. `POST https://verifier-backend.eudiw.dev/ui/presentations` avec `dcql_query`, `nonce`, `request_uri_method: "get"`,
   `"intended_use_id": "TEST-01"` (obligatoire) et `"issuer_chain"` = contenu de `/api/trust/iaca.pem`
   pour que le verifier fasse confiance à l'autorité de test ;
3. construire `openid4vp://?client_id=…&request_uri=…` depuis la réponse et le coller dans la page ;
4. `GET /ui/presentations/{transaction_id}` côté verifier pour voir ce qu'il a reçu.

Résultat au 2026-11-03 : mDL mdoc accepté de bout en bout ; PID SD-JWT conforme après passage de
`issuing_authority` / `issuing_country` en claims divulgables (exigé par les type metadata `urn:eudi:pid:1`).

## Collection Bruno

`bruno/` contient une collection [Bruno](https://www.usebruno.com/) documentée (onglet *Docs* de la collection,
de chaque dossier et de chaque requête) : infos, CRUD des identités, présentation, injection de défauts,
scénario complet contre le verifier EUDI et réception OpenID4VCI (`06 Emission OpenID4VCI`, qui demande une offre
réelle dans la variable `credentialOffer`). Ouvrir le dossier dans Bruno et choisir l'environnement `local`.

En ligne de commande (app démarrée sur le port 8080) :

```
npm i -g @usebruno/cli
cd bruno
bru run "01 Infos" "02 Identites" "03 Presentation" "04 Defauts" --env local
```

Sans `requestUri`, la collection construit une requête de démo par valeur : les réponses vers le verifier
finissent en `502` (verifier injoignable), c'est attendu. `05 Verifier EUDI` exige l'accès à `*.eudiw.dev`.

## Confiance dans les verifiers

Les requêtes signées (`x509_san_dns`, `x509_hash`) sont acceptées si la chaîne `x5c` se valide (PKIX, sans
révocation) jusqu'à un certificat de `wallet.verifier-trust-anchors`, ou contient ce certificat
(verifier auto-signé). `wallet.trust-all-verifiers=true` désactive la vérification : réservé aux essais.

## Lancer

```bash
./mvnw verify
./mvnw spring-boot:run
```

## Configuration

| Propriété | Défaut | Rôle |
|---|---|---|
| `wallet.trust-all-verifiers` | `false` | Accepte toute chaîne de certificats pour les clients `x509_san_dns` / `x509_hash`. Réservé aux tests. |
| `wallet.data-dir` | `./wallet-data` | Clés et certificats PEM de l'autorité de test et du wallet, base SQLite (identités, credentials reçus). |
| `wallet.verifier-trust-anchors` | `[]` | Fichiers PEM des racines de verifiers de confiance. |

## Feuille de route

1. Squelette et adaptateur Kotlin ✅
2. Credentials de test (SD-JWT VC, mdoc) émis au démarrage, clé wallet ✅
3. Flux de présentation : résolution, sélection DCQL, KB-JWT / DeviceResponse, `direct_post(.jwt)`, UI minimale ✅
4. Outils de test : journal des échanges, injection d'erreurs, trust store ✅ — essai contre le verifier de référence EUDI à faire
5. Réception OpenID4VCI (pré-autorisé, proof JWT, SD-JWT VC / mdoc), présentation des credentials reçus ✅ — DPoP à faire
