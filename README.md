# swiyu4health – Generic Issuer & Verifier Setup

> **Umgebung:** swiyu Integration (`swiyu-int`)  
> **Stand:** Februar 2026  
> **Server:** `swiyu.ywesee.com`

## Übersicht

Dieses Repository enthält die Konfiguration für einen swiyu Generic Issuer und Verifier für Arztausweise (GLN-basiert).

| Service | URL | Port intern |
|---------|-----|-------------|
| Issuer OID4VCI | https://swiyu.ywesee.com/issuer | 8080 |
| Verifier OID4VP | https://swiyu.ywesee.com/verifier | 8083 |
| Verifier Management | nur intern | 8084 |

---

## Voraussetzungen

Vor dem Setup müssen folgende Schritte **manuell** abgeschlossen sein:

### 1. Portal-Registrierung

1. ePortal → [swiyu Trust Infrastructure](https://www.eid.admin.ch) → Business Partner anlegen
2. [API Self-Service Portal](https://selfservice.api.admin.ch) → App anlegen → beide APIs abonnieren:
   - `swiyucorebusiness_identifier`
   - `swiyucorebusiness_status`

### 2. DID erstellen und registrieren

```bash
# Java 21 erforderlich
cd ~/Downloads/swiyu/

# Schritt 1: Identifier-Eintrag (DID Space) im Registry erstellen
ACCESS_TOKEN="<access_token_vom_portal>"
PARTNER_ID="<dein_partner_id>"

curl -s -X POST \
  "https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/${PARTNER_ID}/identifier-entries" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool
# → Speichere die zurückgegebene "id" als IDENTIFIER_UUID

# Schritt 2: DID-Log generieren
IDENTIFIER_UUID="<id_aus_schritt_1>"
java -jar didtoolbox-1.3.1-jar-with-dependencies.jar create \
  --identifier-registry-url \
  "https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/${IDENTIFIER_UUID}" \
  --signing-key-file .didtoolbox/id_ed25519 \
  --verifying-key-files .didtoolbox/id_ed25519.pub \
  --assert "assert-key-01,.didtoolbox/assert-key-01.pub" \
  --auth "auth-key-01,.didtoolbox/auth-key-01.pub" > /tmp/didlog.jsonl

# Schritt 3: DID-Log im Registry publizieren
curl --data-binary @/tmp/didlog.jsonl \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/jsonl+json" \
  -X PUT \
  "https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/${PARTNER_ID}/identifier-entries/${IDENTIFIER_UUID}"

# Schritt 4: DID verifizieren
curl -s "https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/${IDENTIFIER_UUID}/did.jsonl"
```

Der vollständige DID hat die Form:
```
did:tdw:<SCID>:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:<IDENTIFIER_UUID>
```

---

## .env Konfiguration

Erstelle `~/software/swiyu4health/.env` mit folgenden Werten:

```bash
# Domain
EXTERNAL_DOMAIN=swiyu.ywesee.com

# Issuer DID (aus didtoolbox output)
ISSUER_DID=did:tdw:<SCID>:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:<UUID>
ISSUER_DID_VERIFICATION_METHOD=${ISSUER_DID}#assert-key-01
ISSUER_SIGNING_KEY="-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"

# Status List (gleicher DID, key-2 oder assert-key-01)
STATUS_LIST_SIGNING_KEY="-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"
STATUS_LIST_VERIFICATION_METHOD=${ISSUER_DID}#assert-key-01

# Verifier DID (kann gleicher DID sein wie Issuer)
VERIFIER_DID=${ISSUER_DID}
VERIFIER_DID_VERIFICATION_METHOD=${ISSUER_DID}#assert-key-01
VERIFIER_SIGNING_KEY="-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"

# swiyu API (aus API Self-Service Portal)
SWIYU_PARTNER_ID=<business_partner_uuid>
SWIYU_STATUS_REGISTRY_CUSTOMER_KEY=<customer_key>
SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET=<customer_secret>
SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN=<refresh_token>

# Diese URLs sind fix (Stand Feb 2026, swiyu-int):
SWIYU_STATUS_REGISTRY_API_URL=https://status-reg-api.trust-infra.swiyu-int.admin.ch
SWIYU_STATUS_REGISTRY_TOKEN_URL=https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect/token
```

---

## Setup ausführen

```bash
sudo bash swiyu-setup.sh
```

---

## Credentials ausstellen

### 1. Statusliste erstellen (einmalig nach Setup)

```bash
curl -s -X POST http://localhost:8080/management/api/status-list \
  -H "Content-Type: application/json" \
  -d '{"type":"TOKEN_STATUS_LIST","maxLength":100000,"config":{"bits":2}}' \
  | python3 -m json.tool
# → statusRegistryUrl speichern!
```

### 1b. Pflichtdateien ab v2.1.1

Ab swiyu-issuer v2.1.1 sind **zwei** Konfigurationsdateien erforderlich:

#### issuer_metadata.json

```json
{
  "version": "1.0",
  "credential_issuer": "https://swiyu.ywesee.com/issuer",
  "credential_endpoint": "https://swiyu.ywesee.com/issuer/oid4vci/api/credential",
  "nonce_endpoint": "https://swiyu.ywesee.com/issuer/oid4vci/api/nonce",
  "credential_configurations_supported": { ... }
}
```

> **Wichtig:**
> - `"version": "1.0"` ist Pflicht (nicht `"1"`, nicht weglassen)
> - `"nonce_endpoint"` ist Pflicht
> - Beide Felder fehlen in der `sample.compose.yml` Vorlage → manuell ergänzen! Siehe [PR #228](https://github.com/swiyu-admin-ch/swiyu-issuer/pull/228).

#### display Pflichtfeld in issuer_metadata.json

Das Top-Level `display` Array ist ein **Pflichtfeld** – der iOS Wallet Decoder wirft einen Fehler wenn es fehlt oder `null` ist (kein `decodeIfPresent`). Die Wallet bricht dann nach dem ersten Request still ab und zeigt „Ungültiger Nachweis".

```json
{
  "version": "1.0",
  "credential_issuer": "https://swiyu.ywesee.com/issuer",
  "credential_endpoint": "...",
  "nonce_endpoint": "...",
  "display": [
    {
      "name": "ywesee GmbH",
      "locale": "de-CH"
    }
  ],
  "credential_configurations_supported": { ... }
}
```

#### openid_metadata.json (NEU ab v2.1.1)

```json
{
  "issuer": "https://swiyu.ywesee.com/issuer",
  "token_endpoint": "https://swiyu.ywesee.com/issuer/oid4vci/api/token"
}
```

Diese Datei wird von der Wallet über `/.well-known/oauth-authorization-server` abgerufen um den Token-Endpoint zu finden. Ohne diese Datei gibt der Service **500 Internal Server Error** zurück und die Wallet bricht den Credential-Abruf ab.

**docker-compose.yml Konfiguration:**
```yaml
environment:
  METADATA_CONFIG_FILE: file:/config/issuer_metadata.json
  OPENID_CONFIG_FILE: file:/config/openid_metadata.json   # NEU!

volumes:
  - ./config/issuer_metadata.json:/config/issuer_metadata.json:ro
  - ./config/openid_metadata.json:/config/openid_metadata.json:ro  # NEU!
```

### 2. Credential erstellen

```bash
STATUS_REGISTRY_URL="https://status-reg.trust-infra.swiyu-int.admin.ch/api/v1/statuslist/<id>.jwt"

curl -s -X POST http://localhost:8080/management/api/credentials \
  -H "Content-Type: application/json" \
  -d "{
    \"metadata_credential_supported_id\": [\"doctor-credential\"],
    \"credential_subject_data\": {
      \"firstName\": \"Hans\",
      \"lastName\": \"Muster\",
      \"gln\": \"7601000000000\"
    },
    \"offer_validity_seconds\": 86400,
    \"credential_valid_until\": \"2030-01-01T00:00:00Z\",
    \"credential_valid_from\": \"2026-01-01T00:00:00Z\",
    \"status_lists\": [\"${STATUS_REGISTRY_URL}\"]
  }" | python3 -m json.tool
```

### 3. QR-Code für swiyu Wallet

```bash
echo "<offer_deeplink>" | qrencode -t ANSIUTF8
```

---

## Verifikation erstellen

```bash
curl -s -X POST http://localhost:8084/management/api/verifications \
  -H "Content-Type: application/json" \
  -d '{
    "accepted_issuer_dids": ["<ISSUER_DID>"],
    "response_mode": "direct_post",
    "presentation_definition": {
      "id": "00000000-0000-0000-0000-000000000000",
      "input_descriptors": [{
        "id": "11111111-1111-1111-1111-111111111111",
        "format": {
          "vc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256"],
            "kb-jwt_alg_values": ["ES256"]
          }
        },
        "constraints": {
          "fields": [
            {"path": ["$.vct"], "filter": {"type": "string", "const": "doctor-credential-sdjwt"}},
            {"path": ["$.firstName"]},
            {"path": ["$.lastName"]}
          ]
        }
      }]
    }
  }' | python3 -m json.tool
# → verification_deeplink als QR-Code ausgeben
```

---

## Dienste verwalten

```bash
# Status prüfen
sudo docker ps
sudo docker logs swiyu-issuer-service -f
sudo docker logs swiyu-verifier -f

# Neustart (ohne DB-Verlust)
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml \
  --env-file /opt/swiyu/issuer/.env restart swiyu-issuer-service

# Neustart mit DB-Reset (Token muss erneuert werden!)
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml \
  --env-file /opt/swiyu/issuer/.env down -v
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml \
  --env-file /opt/swiyu/issuer/.env up -d

# Metadaten prüfen
curl -s https://swiyu.ywesee.com/issuer/.well-known/openid-credential-issuer | python3 -m json.tool
curl -s https://swiyu.ywesee.com/verifier/oid4vp/api/openid-client-metadata.json | python3 -m json.tool
```

---


---

## Trust Registry – Wallet-Akzeptanz

Die swiyu Wallet zeigt **„Ungültiger Nachweis"** wenn der Issuer-DID kein Trust Statement in der Trust Registry hat, oder wenn das Trust Statement nicht validiert werden kann. Das ist unabhängig davon ob Issuer und Verifier korrekt laufen.

### Wie die Wallet die Trust Registry prüft

Die iOS Wallet verwendet **zwei verschiedene Endpunkte**:

| Endpunkt | Zweck | Auth |
|----------|-------|------|
| `trust-reg.trust-infra.swiyu-int.admin.ch` | Lesen (Wallet) | keine |
| `trust-reg-api.trust-infra.swiyu-int.admin.ch` | Schreiben (Authoring) | Bearer Token |

Die Wallet ruft beim Credential-Import auf:
```
GET https://trust-reg.trust-infra.swiyu-int.admin.ch/api/v1/truststatements/identity/<ISSUER_DID>
```
- Antwort `[]` → kein Trust Statement → „Ungültiger Nachweis"
- Antwort `[...]` → Trust Statement vorhanden → Wallet validiert es

**Wichtig:** Die Wallet validiert das Trust Statement vollständig:
1. JWS-Signatur des Trust Registry DIDs verifizieren
2. Status List des Trust Statements prüfen
3. Subject DID muss mit Issuer DID übereinstimmen

### Bekanntes Problem: Trust Registry DID nicht auflösbar (Stand Feb 2026)

Der Trust Registry DID (`2e246676-...`) ist im Identifier Registry nicht auflösbar:
```bash
curl https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/2e246676-209a-4c21-aceb-721f8a90b212/did.json
# → NOT_FOUND
```
Das bedeutet die Wallet kann die JWS-Signatur des Trust Statements nicht verifizieren und zeigt „Ungültiger Nachweis" – auch wenn das Trust Statement vorhanden ist. Gemeldet als [Issue #231](https://github.com/swiyu-admin-ch/swiyu-issuer/issues/231).

### Status prüfen (Lese-Endpunkt)

```bash
ISSUER_DID="<dein_issuer_did>"

curl -s "https://trust-reg.trust-infra.swiyu-int.admin.ch/api/v1/truststatements/identity/${ISSUER_DID}"
# [] = kein Trust Statement → Wallet zeigt "Ungültiger Nachweis"
# [...] = Trust Statement vorhanden → Wallet akzeptiert Credentials
```

### Access Token holen (für Authoring API)

> ⚠️ Den Refresh Token **immer aus der Datenbank holen** – nicht aus `.env`!
> Der Issuer-Service rotiert den Token automatisch und speichert den neuen in PostgreSQL.

```bash
# Aktuellen Refresh Token aus DB
REFRESH_TOKEN=$(sudo docker exec swiyu-issuer-db psql -U issuer -d issuerdb \
  -tAc "SELECT refresh_token FROM token_set WHERE api_target='STATUS_REGISTRY';")

CUSTOMER_SECRET=$(grep SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET /opt/swiyu/issuer/.env | cut -d= -f2)
CLIENT_ID=$(grep SWIYU_STATUS_REGISTRY_CUSTOMER_KEY /opt/swiyu/issuer/.env | cut -d= -f2)

ACCESS_TOKEN=$(curl -s -X POST \
  "https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CUSTOMER_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['access_token'])")
```

### Trust Statement erstellen

> **Stand Feb 2026:** `trust-reg-api` gibt 503 zurück (pods down). Siehe [GitHub Issue #225](https://github.com/swiyu-admin-ch/swiyu-verifier/issues/225). Sobald verfügbar:

```bash
curl -s -X POST \
  "https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/truststatements" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"subjectDid\": \"${ISSUER_DID}\"}" \
  | python3 -m json.tool
```

> **Voraussetzung:** `swiyucorebusiness_trust` im [API Self-Service Portal](https://selfservice.api.admin.ch) abonniert. Zugang beantragen bei: **swiyu@eid.admin.ch**

## Bekannte Fallstricke

### display Pflichtfeld (Top-Level)

Der iOS Wallet Decoder (`CredentialMetadata.swift`) behandelt das Top-Level `display` Array als **Pflichtfeld** – es verwendet `decode` statt `decodeIfPresent`. Wenn `display` fehlt oder `null` ist:

- Wallet ruft `.well-known/openid-credential-issuer` ab (200 OK)
- Wallet bricht **still** ab ohne weiteren Request
- Wallet zeigt „Ungültiger Nachweis"
- Keine Fehlermeldung im Server-Log

**Lösung:** Top-Level `display` in `issuer_metadata.json` ergänzen:
```json
"display": [
  { "name": "ywesee GmbH", "locale": "de-CH" }
]
```

### version und nonce_endpoint in issuer_metadata.json

Ab **swiyu-issuer v2.1.1** sind zwei neue Pflichtfelder in der `issuer_metadata.json` erforderlich:

```json
{
  "version": "1.0",
  "nonce_endpoint": "https://<domain>/issuer/oid4vci/api/nonce",
  ...
}
```

**Fehlermeldungen ohne diese Felder:**
- Ohne `version`: `Invalid value for version. Current is null but the constraint is must not be null`
- Mit `"version": "1"`: `Current is 1 but the constraint is Only version 1.0 is supported`
- Ohne `nonce_endpoint`: Wallet kann Credential nicht abrufen

Diese Felder fehlen in der offiziellen `sample.compose.yml` Vorlage (Stand Feb 2026) – sie müssen manuell ergänzt werden. Siehe [PR #228](https://github.com/swiyu-admin-ch/swiyu-issuer/pull/228).

### Refresh Token

Der `SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN` ist **einmalig verwendbar**. Nach dem ersten erfolgreichen Start speichert der Issuer-Service den neuen Token in der PostgreSQL-Datenbank.

**Problem:** Falls die Datenbank gelöscht wird (`down -v`) oder der Service beim ersten Start abstürzt, ist der Token verbraucht und muss erneuert werden.

**Lösung:**
1. Im [API Self-Service Portal](https://selfservice.api.admin.ch) → App → **„Token aktualisieren"**
2. Neuen Token in `/opt/swiyu/issuer/.env` eintragen: `sudo vim /opt/swiyu/issuer/.env`
3. Service mit frischer DB starten: `down -v && up -d`

### file: Prefix

Beide Metadata-Dateien benötigen den `file:` Prefix in der Umgebungsvariable:
```
METADATA_CONFIG_FILE: file:/config/issuer_metadata.json
OPENID_CLIENT_METADATA_FILE: file:/config/verifier_metadata.json
```

### Status Registry API URL

Die korrekte URL laut Dokumentation (Stand Feb 2026):
```
https://status-reg-api.trust-infra.swiyu-int.admin.ch
```
Nicht `status-reg` (ohne `-api`).

### Token URL

Vollständiger Pfad erforderlich:
```
https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect/token
```

### DID-Format

Der DID muss **ohne** `__underscores__` sein. Das Format mit `__identifier-reg...__` entsteht bei lokalem Testing ohne echte Registry-URL. Korrekt:
```
did:tdw:<SCID>:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:<UUID>
```

### vp_formats im Verifier

Die `verifier_metadata.json` muss `vp_formats` mit `jwt_vp` enthalten (Java-Pflichtfeld):
```json
"vp_formats": {
  "vc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] },
  "jwt_vp": { "alg_values": ["ES256"], "alg": ["ES256"] }
}
```

---

## Dateistruktur

```
/opt/swiyu/
├── issuer/
│   ├── docker-compose.yml
│   ├── .env                    (chmod 600)
│   ├── status_registry_url.txt (nach init_status_list)
│   └── config/
│       ├── issuer_metadata.json
│       └── openid_metadata.json   (NEU ab v2.1.1)
└── verifier/
    ├── docker-compose.yml
    ├── .env                    (chmod 600)
    └── config/
        ├── verifier_metadata.json
        └── sample_verification_request.json

~/Downloads/swiyu/didtoolbox-java-1.3.1/.didtoolbox/
├── id_ed25519          (DID Update Key – sicher aufbewahren!)
├── id_ed25519.pub
├── assert-key-01       (Signing Key für Credentials)
├── assert-key-01.pub
├── auth-key-01
└── auth-key-01.pub
```

---

## Referenzen

- [Generic Issuer Cookbook](https://swiyu-admin-ch.github.io/cookbooks/onboarding-generic-issuer/)
- [Generic Verifier Cookbook](https://swiyu-admin-ch.github.io/cookbooks/onboarding-generic-verifier/)
- [Base & Trust Registry Cookbook](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/)
- [swiyu-issuer GitHub](https://github.com/swiyu-admin-ch/swiyu-issuer)
- [swiyu-verifier GitHub](https://github.com/swiyu-admin-ch/swiyu-verifier)
- [didtoolbox GitHub](https://github.com/swiyu-admin-ch/didtoolbox-java)
