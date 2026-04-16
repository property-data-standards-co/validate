/**
 * Tests for the PDTF Validation Service.
 *
 * Uses real @pdtf/core signing + validation — no mocks for crypto.
 * Only external fetches (TIR, status lists, did:web) are stubbed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  VcSigner,
  type KeyProvider,
  type VerifiableCredential,
} from '@pdtf/core';

// We test the receipt + validation logic through the HTTP API
import { Hono } from 'hono';

// ── Helpers ──────────────────────────────────────────────────────────

const TEST_SEED = 'abababababababababababababababababababababababababababababababab';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

class TestKeyProvider implements KeyProvider {
  private readonly secretKey: Uint8Array;
  private publicKey: Uint8Array | null = null;

  constructor(secretKeyHex: string) {
    this.secretKey = hexToBytes(secretKeyHex);
  }

  async init(): Promise<void> {
    const { ed25519 } = await import('@noble/curves/ed25519');
    this.publicKey = ed25519.getPublicKey(this.secretKey) as Uint8Array;
  }

  async generateKey(): Promise<string> { return 'test-key'; }

  async sign(_keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const { ed25519 } = await import('@noble/curves/ed25519');
    return ed25519.sign(data, this.secretKey) as Uint8Array;
  }

  async getPublicKey(): Promise<Uint8Array> {
    return this.publicKey!;
  }

  async resolveDidKey(): Promise<string> {
    throw new Error('Not used');
  }
}

let testSigner: VcSigner;
let testDid: string;

beforeAll(async () => {
  const { deriveDidKey } = await import('@pdtf/core');
  const keyProvider = new TestKeyProvider(TEST_SEED);
  await keyProvider.init();
  const pubKey = await keyProvider.getPublicKey('test-key');
  testDid = deriveDidKey(pubKey);
  testSigner = new VcSigner(keyProvider, 'test-key', testDid);
});

async function signTestVc(overrides?: Partial<Parameters<VcSigner['sign']>[0]>): Promise<VerifiableCredential> {
  return testSigner.sign({
    type: 'PropertyDataCredential',
    credentialSubject: {
      id: 'urn:pdtf:uprn:100023336956',
      energyEfficiency: { rating: 'B', score: 85 },
    },
    ...overrides,
  });
}

// ── Tests ────────────────────────────────────────────────────────────

describe('Validation Service', () => {
  describe('signed VC structure', () => {
    it('produces a valid signed VC', async () => {
      const vc = await signTestVc();

      expect(vc.proof).toBeDefined();
      expect(vc.proof!.type).toBe('DataIntegrityProof');
      expect(vc.proof!.cryptosuite).toBe('eddsa-jcs-2022');
      expect(vc.proof!.proofValue).toMatch(/^z/);
      expect(vc.issuer).toBe(testDid);
    });
  });

  describe('receipt structure', () => {
    it('issues a ValidationReceipt VC', async () => {
      const { createReceiptIssuer, issueReceipt } = await import('../receipt.js');

      // Create a receipt issuer with a different key
      const receiptIssuer = await createReceiptIssuer({
        port: 8080,
        serviceDid: 'did:web:validate.propdata.org.uk',
        signingKeyHex: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        signingKeyId: 'test-receipt-key',
        federationRegistryUrl: 'https://example.com/tir',
        federationCacheTtlMs: 3600000,
        didCacheTtlMs: 3600000,
        maxBodySize: 1048576,
        logLevel: 'error',
      });

      const receipt = await issueReceipt(
        receiptIssuer,
        'urn:uuid:test-vc-001',
        {
          valid: true,
          stages: {
            structure: { passed: true, errors: [] },
            signature: { passed: true, errors: [] },
            trust: { passed: true, errors: [], details: { issuerSlug: 'test' } },
            status: { passed: true, skipped: true, errors: [] },
          },
          warnings: [],
        },
        { serviceVersion: '0.1.0' },
      );

      expect(receipt.type).toContain('ValidationReceipt');
      expect(receipt.type).toContain('VerifiableCredential');
      expect(receipt.issuer).toBe('did:web:validate.propdata.org.uk');
      expect(receipt.proof).toBeDefined();

      const subject = receipt.credentialSubject as Record<string, unknown>;
      expect(subject.id).toBe('urn:uuid:test-vc-001');
      expect(subject.validationResult).toBe('valid');

      const checks = subject.checks as Record<string, unknown>;
      expect(checks.structure).toEqual({ status: 'pass' });
      expect(checks.signature).toEqual({ status: 'pass' });
      expect(checks.status).toEqual({ status: 'skipped' });
    });

    it('receipt reflects failed validation', async () => {
      const { createReceiptIssuer, issueReceipt } = await import('../receipt.js');

      const receiptIssuer = await createReceiptIssuer({
        port: 8080,
        serviceDid: 'did:web:validate.propdata.org.uk',
        signingKeyHex: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        signingKeyId: 'test-receipt-key',
        federationRegistryUrl: 'https://example.com/tir',
        federationCacheTtlMs: 3600000,
        didCacheTtlMs: 3600000,
        maxBodySize: 1048576,
        logLevel: 'error',
      });

      const receipt = await issueReceipt(
        receiptIssuer,
        'urn:uuid:tampered-vc',
        {
          valid: false,
          stages: {
            structure: { passed: true, errors: [] },
            signature: { passed: false, errors: ['Proof verification failed'] },
            trust: { passed: false, skipped: true, errors: [] },
            status: { passed: false, skipped: true, errors: [] },
          },
          warnings: ['Signature invalid — skipped TIR and status checks'],
        },
        { serviceVersion: '0.1.0' },
      );

      const subject = receipt.credentialSubject as Record<string, unknown>;
      expect(subject.validationResult).toBe('invalid');
      expect(subject.warnings).toContain('Signature invalid — skipped TIR and status checks');

      const checks = subject.checks as Record<string, unknown>;
      expect((checks.signature as Record<string, unknown>).status).toBe('fail');
    });
  });

  describe('end-to-end signing and verification', () => {
    it('VC signed by test signer can be verified by @pdtf/core', async () => {
      const { verifyProof } = await import('@pdtf/core');

      const vc = await signTestVc();
      const keyProvider = new TestKeyProvider(TEST_SEED);
      await keyProvider.init();
      const pubKeyBytes = await keyProvider.getPublicKey('test-key');

      const valid = verifyProof({ document: vc, publicKey: pubKeyBytes });
      expect(valid).toBe(true);
    });

    it('tampered VC fails verification', async () => {
      const { verifyProof } = await import('@pdtf/core');

      const vc = await signTestVc();
      // Tamper
      (vc.credentialSubject as Record<string, unknown>).energyEfficiency = { rating: 'A', score: 99 };

      const keyProvider = new TestKeyProvider(TEST_SEED);
      await keyProvider.init();
      const pubKeyBytes = await keyProvider.getPublicKey('test-key');

      const valid = verifyProof({ document: vc, publicKey: pubKeyBytes });
      expect(valid).toBe(false);
    });
  });
});
