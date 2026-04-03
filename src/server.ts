/**
 * PDTF Validation Service — HTTP API.
 *
 * Endpoints:
 *   POST /v1/verify         — Validate a VC, returns result + signed receipt
 *   GET  /v1/health         — Service health check
 *   GET  /v1/.well-known/did.json — Service DID document
 */
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { loadConfig } from './config.js';
import { ValidatorService } from './validator-service.js';
import type { VerifiableCredential } from '@pdtf/core';

const config = loadConfig();
const service = new ValidatorService(config);

const app = new Hono();

// ── Middleware ────────────────────────────────────────────────────────

app.use('*', async (c, next) => {
  c.header('X-PDTF-Service-DID', config.serviceDid);
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type');
  await next();
});

app.options('*', (c) => new Response(null, { status: 204 }));

// ── POST /v1/verify ──────────────────────────────────────────────────

app.post('/v1/verify', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  // Accept { verifiableCredential: ... } or the VC directly
  const vc = (body.verifiableCredential ?? body) as VerifiableCredential;

  if (!vc['@context'] || !vc.type) {
    return c.json({
      error: 'Invalid request. Send a Verifiable Credential as JSON.',
      hint: 'Wrap in { "verifiableCredential": { ... } } or send the VC directly.',
    }, 400);
  }

  const credentialPaths = body.credentialPaths as string[] | undefined;

  try {
    const response = await service.validate(vc, { credentialPaths });

    return c.json({
      valid: response.valid,
      result: response.result,
      receipt: response.receipt,
    }, response.valid ? 200 : 200); // Always 200 — validity is in the body
  } catch (err) {
    console.error('Validation error:', err);
    return c.json({
      error: 'Internal validation error',
      message: err instanceof Error ? err.message : 'Unknown error',
    }, 500);
  }
});

// ── GET /v1/health ───────────────────────────────────────────────────

app.get('/v1/health', (c) => {
  return c.json(service.health());
});

// ── GET /.well-known/did.json ────────────────────────────────────────

app.get('/.well-known/did.json', (c) => {
  // Serve the service's DID document for did:web resolution
  const did = config.serviceDid;
  const vmId = `${did}#validation-key`;

  return c.json({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        // Public key served from the key material
        // In production, this would be the multibase-encoded public key
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    service: [
      {
        id: `${did}#validation-service`,
        type: 'CredentialValidationService',
        serviceEndpoint: `https://validate.propdata.org.uk/v1/verify`,
      },
    ],
  });
});

// ── Start ────────────────────────────────────────────────────────────

async function main() {
  serve({
    fetch: app.fetch,
    port: config.port,
  }, (info) => {
    console.log(`PDTF Validation Service v0.1.0`);
    console.log(`  DID:  ${config.serviceDid}`);
    console.log(`  TIR:  ${config.tirRegistryUrl}`);
    console.log(`  Port: ${info.port}`);
    console.log(`  Ready.`);
  });
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
