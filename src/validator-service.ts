/**
 * ValidatorService — wraps @pdtf/core's VcValidator with receipt issuance.
 *
 * Stateless: all state lives in the TIR cache and DID resolver cache,
 * which are in-memory with TTL expiry.
 */
import {
  VcValidator,
  DidResolver,
  BootstrapTrustResolver,
  type TrustResolver,
  type ValidationResult,
  type VerifiableCredential,
} from '@pdtf/core';
import {
  createReceiptIssuer,
  issueReceipt,
  type ReceiptIssuer,
  type ReceiptEvidence,
} from './receipt.js';
import type { ServiceConfig } from './config.js';

const SERVICE_VERSION = '0.1.0';

export interface ValidateResponse {
  /** Whether the VC is valid */
  valid: boolean;
  /** Full stage-by-stage result */
  result: ValidationResult;
  /** Signed Validation Receipt (a VC itself) */
  receipt: Record<string, unknown>;
}

export class ValidatorService {
  private readonly validator: VcValidator;
  private readonly didResolver: DidResolver;
  private readonly trustResolver: TrustResolver;
  private readonly receiptIssuer: ReceiptIssuer;
  private readonly config: ServiceConfig;

  constructor(config: ServiceConfig) {
    this.config = config;
    this.validator = new VcValidator();
    this.didResolver = new DidResolver({
      defaultTtlMs: config.didCacheTtlMs,
    });
    this.trustResolver = new BootstrapTrustResolver({
      registryUrl: config.tirRegistryUrl,
      ttlMs: config.tirCacheTtlMs,
    });
    this.receiptIssuer = createReceiptIssuer(config);
  }

  async validate(
    vc: VerifiableCredential,
    options?: { credentialPaths?: string[] },
  ): Promise<ValidateResponse> {
    const result = await this.validator.validate(vc, {
      didResolver: this.didResolver,
      trustResolver: this.trustResolver,
      credentialPaths: options?.credentialPaths,
    });

    const evidence: ReceiptEvidence = {
      serviceVersion: SERVICE_VERSION,
      statusListFetched: new Date().toISOString(),
    };

    const receipt = await issueReceipt(
      this.receiptIssuer,
      vc.id,
      result,
      evidence,
    );

    return {
      valid: result.valid,
      result,
      receipt,
    };
  }

  /** Health check — returns service info. */
  health(): Record<string, unknown> {
    return {
      status: 'ok',
      version: SERVICE_VERSION,
      serviceDid: this.config.serviceDid,
      federationRegistryUrl: this.config.tirRegistryUrl,
    };
  }
}
