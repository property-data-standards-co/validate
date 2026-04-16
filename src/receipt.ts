/**
 * Validation Receipt — a signed VC attesting to the validation result.
 *
 * The receipt includes the full evidence chain so relying parties can
 * independently verify the validator's claim.
 */
import { ed25519 } from '@noble/curves/ed25519';
import {
  VcSigner,
  deriveDidKey,
  type KeyProvider,
  type KeyRecord,
  type KeyCategory,
  type ValidationResult,
} from '@pdtf/core';
import type { ServiceConfig } from './config.js';

/** In-memory KeyProvider backed by a hex-encoded Ed25519 secret key. */
class StaticKeyProvider implements KeyProvider {
  private readonly secretKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private readonly did: string;
  private readonly keyId: string;

  constructor(secretKeyHex: string, keyId: string) {
    this.secretKey = hexToBytes(secretKeyHex);
    this.publicKey = ed25519.getPublicKey(this.secretKey);
    this.did = deriveDidKey(this.publicKey);
    this.keyId = keyId;
  }

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    return {
      keyId,
      did: this.did,
      publicKey: this.publicKey,
      category,
      createdAt: new Date().toISOString(),
    };
  }

  async sign(_keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(data, this.secretKey);
  }

  async getPublicKey(_keyId: string): Promise<Uint8Array> {
    return this.publicKey;
  }

  async resolveDidKey(_keyId: string): Promise<string> {
    return this.did;
  }
}

export interface ReceiptEvidence {
  /** TIR git commit hash used for the check */
  federationRegistryHash?: string;
  /** When the status list was fetched */
  statusListFetched?: string;
  /** SHA-256 hash of the resolved DID document */
  didDocumentHash?: string;
  /** Service version */
  serviceVersion: string;
}

export interface ReceiptIssuer {
  signer: VcSigner;
}

export function createReceiptIssuer(config: ServiceConfig): ReceiptIssuer {
  const keyProvider = new StaticKeyProvider(config.signingKeyHex, config.signingKeyId);
  const signer = new VcSigner(keyProvider, config.signingKeyId, config.serviceDid);
  return { signer };
}

export async function issueReceipt(
  issuer: ReceiptIssuer,
  vcId: string | undefined,
  result: ValidationResult,
  evidence: ReceiptEvidence,
): Promise<Record<string, unknown>> {
  const checks: Record<string, unknown> = {};

  for (const [stage, stageResult] of Object.entries(result.stages)) {
    checks[stage] = {
      status: stageResult.skipped ? 'skipped' : stageResult.passed ? 'pass' : 'fail',
      ...(stageResult.errors.length > 0 && { errors: stageResult.errors }),
      ...(stageResult.details && { details: stageResult.details }),
    };
  }

  const receipt = await issuer.signer.sign({
    type: 'ValidationReceipt',
    id: `urn:uuid:${crypto.randomUUID()}`,
    credentialSubject: {
      id: vcId ?? `urn:uuid:${crypto.randomUUID()}`,
      validationResult: result.valid ? 'valid' : 'invalid',
      checks,
      evidence,
      ...(result.warnings.length > 0 && { warnings: result.warnings }),
    },
  });

  return receipt as unknown as Record<string, unknown>;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
