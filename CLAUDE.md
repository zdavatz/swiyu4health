# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

swiyu4health is an infrastructure-as-code repository for deploying a **swiyu Generic Issuer and Verifier** for doctor credentials (Arztausweise/GLN-based) on the Swiss Digital Identity Infrastructure (swiyu Trust Infrastructure, `swiyu-int` environment).

The repository contains no application source code. All business logic lives in upstream Docker images. This repo provides:
- `setup` — a Bash script (~1100 lines) that automates the full deployment on Debian/Ubuntu
- `README.md` — comprehensive documentation in German with troubleshooting
- `.env` — credentials and configuration (not committed)

## Architecture

```
Wallet/Client
    ↓
Apache Reverse Proxy (TLS, swiyu.ywesee.com)
    ├─ /issuer    → port 8080 → swiyu-issuer Docker container → PostgreSQL
    ├─ /verifier  → port 8083 → swiyu-verifier Docker container → PostgreSQL
    └─ /verifier-mgmt/ → port 8083/management (IP-whitelisted: 65.109.136.203)
```

- **Issuer (OID4VCI):** Issues SD-JWT verifiable credentials via `ghcr.io/swiyu-admin-ch/swiyu-issuer:stable`
- **Verifier (OID4VP):** Verifies credentials via `ghcr.io/swiyu-admin-ch/swiyu-verifier:stable`
- Both share the **same DID** and **same EC signing key** (`assert-key-01`)
- Deployed to `/opt/swiyu/{issuer,verifier}/` with systemd units

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
```

There are no tests, linters, or CI/CD pipelines.

## Critical Constraints

1. **Shared signing key:** `VERIFIER_SIGNING_KEY` must be identical to `ISSUER_SIGNING_KEY` — both use `assert-key-01` (NOT `auth-key-01`)
2. **One-time refresh token:** `SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN` is consumed on first use and rotated into PostgreSQL. DB wipe = must regenerate token via API Self-Service Portal
3. **EC keys in .env:** Must be single-line with `\n` escapes (Docker Compose cannot parse multiline values)
4. **iOS Wallet mandatory metadata fields:** `version: "1.0"`, `display` array, `nonce_endpoint`, `cryptographic_binding_methods_supported: ["jwk"]` — missing any causes silent "Ungültiger Nachweis" failure
5. **Wallet 2-min timeout:** Must scan QR with wallet's internal scanner within 2 minutes of PIN entry, otherwise no Key Binding (`cnf` claim missing)

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
