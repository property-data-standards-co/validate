# PDTF Validation Service

Public credential validation service for the Property Data Trust Framework. Verifies Verifiable Credentials through a 4-stage pipeline and issues signed **Validation Receipts** — themselves VCs — as cryptographic proof of the result.

**Service DID:** `did:web:validate.propdata.org.uk`

## Quick Start

```bash
# Verify a credential
curl -X POST https://validate.propdata.org.uk/v1/verify \
  -H "Content-Type: application/json" \
  -d '{ "verifiableCredential": { ... } }'
```

Response:
```json
{
  "valid": true,
  "result": {
    "stages": {
      "structure": { "passed": true, "errors": [] },
      "signature": { "passed": true, "errors": [] },
      "trust": { "passed": true, "errors": [] },
      "status": { "passed": true, "errors": [] }
    },
    "warnings": []
  },
  "receipt": {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://propdata.org.uk/credentials/v2"],
    "type": ["VerifiableCredential", "ValidationReceipt"],
    "issuer": "did:web:validate.propdata.org.uk",
    "credentialSubject": {
      "validationResult": "valid",
      "checks": { ... },
      "evidence": { ... }
    },
    "proof": { ... }
  }
}
```

## Validation Pipeline

| Stage | What it checks |
|-------|---------------|
| **Structure** | W3C VC 2.0 envelope, required fields, context URIs |
| **Signature** | `DataIntegrityProof` (eddsa-jcs-2022), issuer/proof DID binding |
| **Trust** | Issuer authorisation in the Trusted Issuer Registry |
| **Status** | Revocation/suspension via Bitstring Status List |

All stages run regardless of earlier failures — you always get the complete picture.

## Validation Receipts

Every response includes a signed receipt: a Verifiable Credential issued by the validation service itself. The receipt includes:

- **Result** — `valid` or `invalid`
- **Per-stage results** — which checks passed, failed, or were skipped
- **Evidence chain** — Federation registry hash, status list fetch time, service version
- **Cryptographic proof** — the receipt is signed by the service's Ed25519 key

Relying parties can verify the receipt independently — the service's DID is in the federation trust registry, and every piece of evidence references public data.

## Trust Model

The validation service processes only public data:

1. **Proof verification** — deterministic Ed25519 math
2. **Trust lookup** — publicly auditable git-hosted registry
3. **Status list check** — public URLs per W3C spec
4. **Structure validation** — against published schemas

Anyone can run their own instance and compare results. The receipts make the service's reasoning transparent and independently verifiable.

## API

### `POST /v1/verify`

Validate a Verifiable Credential.

**Request body:**
```json
{
  "verifiableCredential": { ... },
  "credentialPaths": ["Property:/energyEfficiency/certificate"]
}
```

Or send the VC directly as the body (auto-detected).

`credentialPaths` is optional — when provided, the Trust check verifies the issuer is authorised for those specific entity:path combinations.

**Response:** `200 OK` with `{ valid, result, receipt }`.

### `GET /v1/health`

Service health check. Returns version and service DID.

### `GET /.well-known/did.json`

The service's DID document for `did:web` resolution.

## Running Locally

```bash
npm install
cp .env.example .env
# Edit .env with a signing key (generate with: npx @pdtf/core keygen)

npm run dev
```

## Deployment (Cloud Run)

```bash
gcloud run deploy pdtf-validate \
  --source . \
  --region europe-west2 \
  --project propdata-org-uk \
  --set-env-vars "SERVICE_DID=did:web:validate.propdata.org.uk,SIGNING_KEY_HEX=..." \
  --allow-unauthenticated
```

## Architecture

```
validate.propdata.org.uk
├── POST /v1/verify          Stateless validation endpoint
│   ├── Stage 1: Structure   Local check
│   ├── Stage 2: Signature   Local crypto (Ed25519)
│   ├── Stage 3: Trust         OpenID Federation Trust Marks
│   ├── Stage 4: Status      Fetch status list URL
│   └── Receipt              Sign result as VC
├── GET  /v1/health          Health check
└── GET  /.well-known/did.json  DID document
```

No database. No queues. No state beyond in-memory caches with TTL expiry.

## License

Apache-2.0
