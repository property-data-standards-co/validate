/**
 * Service configuration — environment-driven, no config files.
 */

export interface ServiceConfig {
  /** Port to listen on */
  port: number;

  /** The DID of this validation service (used as issuer of receipts) */
  serviceDid: string;

  /** Hex-encoded Ed25519 secret key for signing receipts */
  signingKeyHex: string;

  /** Key ID for the signing key (used in verificationMethod) */
  signingKeyId: string;

  /** TIR registry URL (git-hosted JSON) */
  federationRegistryUrl: string;

  /** TIR cache TTL in ms */
  federationCacheTtlMs: number;

  /** DID resolver cache TTL in ms */
  didCacheTtlMs: number;

  /** Maximum request body size in bytes */
  maxBodySize: number;

  /** Log level */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export function loadConfig(): ServiceConfig {
  return {
    port: parseInt(process.env.PORT ?? '8080', 10),
    serviceDid: requireEnv('SERVICE_DID'),
    signingKeyHex: requireEnv('SIGNING_KEY_HEX'),
    signingKeyId: process.env.SIGNING_KEY_ID ?? 'validation-service-key',
    federationRegistryUrl: process.env.FEDERATION_REGISTRY_URL
      ?? 'https://raw.githubusercontent.com/property-data-standards-co/tir/main/registry.json',
    federationCacheTtlMs: parseInt(process.env.FEDERATION_CACHE_TTL_MS ?? '3600000', 10),
    didCacheTtlMs: parseInt(process.env.DID_CACHE_TTL_MS ?? '3600000', 10),
    maxBodySize: parseInt(process.env.MAX_BODY_SIZE ?? '1048576', 10), // 1MB
    logLevel: (process.env.LOG_LEVEL ?? 'info') as ServiceConfig['logLevel'],
  };
}

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  return value;
}
