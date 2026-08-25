# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

swiyu4health is an infrastructure-as-code repository for deploying a **swiyu Generic Issuer and Verifier** for doctor credentials (Arztausweise/GLN-based) on the Swiss Digital Identity Infrastructure (swiyu Trust Infrastructure, `swiyu-int` environment).

The repository contains no application source code. All business logic lives in upstream Docker images. This repo provides:
- `setup` — a Bash script (~1100 lines) that automates the full deployment on Debian/Ubuntu
- `create_credential` — a Bash script to issue credentials and display QR codes (requires `curl`, `jq`, `qrencode`)
- `README.md` — comprehensive documentation in German with troubleshooting
- `.env` — credentials and configuration (not committed)

## Architecture

```
Wallet/Client
    ↓
Apache Reverse Proxy (TLS, swiyu.ywesee.com)
    ├─ /issuer    → port 8080 → swiyu-issuer Docker container → PostgreSQL
    ├─ /verifier  → port 8083 → swiyu-verifier Docker container → PostgreSQL
    └─ /verifier-mgmt/ → port 8083/management (IP-whitelist: 65.109.136.203, 65.109.163.188, 192.168.0.1 — or X-API-Key)
```

- **Issuer (OID4VCI):** Issues SD-JWT verifiable credentials via `ghcr.io/swiyu-admin-ch/swiyu-issuer:4.1.0-unhardened`
- **Verifier (OID4VP):** Verifies credentials via `ghcr.io/swiyu-admin-ch/swiyu-verifier:4.1.2-unhardened`
- Both share the **same DID**, but **different keys**: the issuer signs credentials with `assert-key-01` (`assertionMethod`), the verifier signs authorization requests with `auth-key-01` (`authentication`)
- Deployed to `/opt/swiyu/{issuer,verifier}/` with systemd units
- Consumer: `ch.oddb.org` (65.109.163.188) creates verifications via `/verifier-mgmt/` — see `src/util/swiyu_client.rb` there

## Key Commands

```bash
# Deploy/update everything (idempotent, requires root)
sudo bash setup

# Health checks
curl http://localhost:8080/actuator/health   # Issuer
curl http://localhost:8083/actuator/health   # Verifier

# View logs
sudo docker logs swiyu-issuer-service -f
sudo docker logs swiyu-verifier -f

# Restart service (preserves DB)
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml --env-file /opt/swiyu/issuer/.env restart swiyu-issuer-service

# Restart with DB reset (WARNING: refresh token consumed, must regenerate)
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml --env-file /opt/swiyu/issuer/.env down -v
sudo docker compose -f /opt/swiyu/issuer/docker-compose.yml --env-file /opt/swiyu/issuer/.env up -d

# Check metadata
curl -s https://swiyu.ywesee.com/issuer/.well-known/openid-credential-issuer | python3 -m json.tool

# Issue credential and show QR code
./create_credential --first-name Hans --last-name Muster --gln 7601000000000 --valid-year
./create_credential --first-name Hans --last-name Muster --gln 7601000000000 --valid-month
```

There are no tests, linters, or CI/CD pipelines.

## Critical Constraints

1. **Separate signing keys per DID relation:** the DID document maps `authentication → auth-key-01` and `assertionMethod → assert-key-01`. The verifier signs *authorization requests*, so `VERIFIER_SIGNING_KEY` must be the **`auth-key-01`** key; the issuer and status list sign *credentials*, so they use `assert-key-01`. Using `assert-key-01` for the verifier makes wallets reject the request
2. **Never use the `:stable` image tag:** upstream does not maintain it — in August 2026 it still pointed at 2.1.2 (December 2025) while 4.x was current. Pin explicit versions in `.env` (`ISSUER_IMAGE_TAG`, `VERIFIER_IMAGE_TAG`)
3. **Verifier 4.x speaks DCQL only:** `presentation_definition` is rejected with `dcqlQuery: must not be null`. Consumers must send `dcql_query` (see `ch.oddb.org` `src/util/swiyu_client.rb`)
4. **One-time refresh token:** `SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN` is consumed on first use and rotated into PostgreSQL. DB wipe = must regenerate token via API Self-Service Portal
5. **EC keys in .env:** Must be single-line with `\n` escapes, **in double quotes**. `setup` writes them unquoted into `/opt/swiyu/*/.env` because it loads `.env` via `export "$line"` without quote removal — the quotes are already part of the value. Do not add another pair
6. **No `EnvironmentFile=` in the systemd units:** systemd does not expand the `\n` escapes and its process environment wins over the `.env` that `docker compose` parses correctly. Result would be `No PEM-encoded keys found`. The units pass `--env-file` to compose instead
7. **DB passwords must be preserved across `setup` runs:** `POSTGRES_PASSWORD` only applies when the volume is first initialised. A freshly generated password leaves the role unchanged and both services crash-loop with `password authentication failed`. `setup` now reads the deployed value first
8. **Issuer 3.2.0+ enforces DPoP and request encryption by default:** with `application.dpop-enforce=true` the wallet aborts after `POST /oid4vci/api/nonce` showing `use_dpop_nonce`; with `encryption_required: true` it never calls the credential endpoint at all. Both are switched off via `APPLICATION_DPOP_ENFORCE` / `APPLICATION_ENCRYPTION_ENFORCE` in the issuer `.env` — turn them back on one at a time and re-test issuance
9. **The OID4VCI well-known lives at the root:** wallets first request `/.well-known/openid-credential-issuer/<issuer-path>` and only then fall back to `/<issuer-path>/.well-known/openid-credential-issuer`. `setup` installs a `RewriteRule` in the HTTPS vhost for this; without it the first request 404s
10. **`logo_uri` must resolve:** `issuer_metadata.json` and `verifier_metadata.json` both point at `https://<domain>/logo.png`. `setup` writes a placeholder to `/var/www/html/logo.png`; replace it with a real logo, but never let it 404
11. **Metadata `version` was replaced by `profile_version`:** the 4.x issuer rebuilds the metadata itself and emits `profile_version` (Swiss Profile) instead of the `version: "1.0"` field older wallets required. The `version` key in `issuer_metadata.json` is ignored — that is expected, not a defect
12. **iOS Wallet mandatory metadata fields:** `display` array, `nonce_endpoint`, `cryptographic_binding_methods_supported: ["jwk"]` — missing any causes silent "Ungültiger Nachweis" failure
13. **Wallet 2-min timeout:** Must scan QR with wallet's internal scanner within 2 minutes of PIN entry, otherwise no Key Binding (`cnf` claim missing)

## Debugging the Wallet Flow

The wallet reports every rejected authorization request as a bare `invalid_request` and never contacts the server again, so the logs are the only evidence.

- **Apache access log:** `/var/log/apache2/swiyu-access.log`. If empty, check `other_vhosts_access.log` — the HTTPS vhost `swiyu-le-ssl.conf` only logs to the dedicated file since `setup` injects `CustomLog` there. Two `<VirtualHost *:443>` with the same `ServerName` exist; `swiyu-le-ssl.conf` wins (loads first alphabetically) and `swiyu.conf`'s vhost block is ignored
- **Reading the pattern:** `GET …/request-object/<id>` followed by `POST …/response-data` means the wallet submitted and the reason is in the verifier log. A `GET` with no `POST` means the wallet rejected the request object itself — the fault is then in the request object's content, not the credential
- **Ground truth:** `select state, count(*) from management group by 1;` in `swiyu-verifier-db`. Only `PENDING` rows means no wallet ever submitted anything
- **Issuance has its own chain**, visible in the same log: metadata → `oauth-authorization-server` → `POST /oid4vci/api/token` → `POST /oid4vci/api/nonce` → `POST /oid4vci/api/credential`. Whichever step is missing is where the wallet gave up
- **Version skew is the first thing to check**, not the last. Compare the running image label against the registry before suspecting configuration — see the `:stable` constraint above

## Presented Claims (DCQL)

With DCQL the verifier groups the presented claims by query id and wraps them in an array, because one query can match several credentials:

```json
"credential_subject_data": { "doctor_credential": [ { "vct": "...", "gln": "...", "cnf": {...} } ] }
```

The old `presentation_definition` flow returned the claims flat. Consumers must handle the nesting — `ch.oddb.org` does so in `SwiyuMiddleware#extract_claims`.

## Editing the Setup Script

The `setup` script generates: Docker Compose files, environment files, metadata JSON configs, Apache vhost, and systemd units. When modifying it, be aware that:
- Configuration is written to `/opt/swiyu/` on the target server
- The script sources `.env` from the repo root for all credentials
- Metadata JSON (issuer_metadata.json, openid_metadata.json, verifier_metadata.json) is generated inline via heredocs
- The script is idempotent — safe to re-run

## Standards & Protocols

- **DID method:** `did:tdw` (TrustWeb DID) via didtoolbox-java
- **Credential format:** SD-JWT with ES256 (ECDSA P-256)
- **Issuance:** OID4VCI (OpenID for Verifiable Credentials Issuance)
- **Verification:** OID4VP (OpenID for Verifiable Presentations)
- **Auth:** OAuth 2.0 via Keycloak (keymanager-prd.api.admin.ch)
