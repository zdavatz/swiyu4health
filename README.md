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

## Bekannte Fallstricke

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
│       └── issuer_metadata.json
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
