export abstract class SnpmError extends Error {
  abstract readonly code: string;
  abstract readonly exitCode: number;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class RegistryTimeoutError extends SnpmError {
  readonly code = 'E_REGISTRY_TIMEOUT';
  readonly exitCode = 5;
  constructor(readonly url: string, readonly timeoutMs: number, options?: { cause?: unknown }) {
    super(`Registry request timed out after ${timeoutMs}ms: ${url}`, options);
  }
}

export class NetworkUnavailableError extends SnpmError {
  readonly code = 'E_NETWORK';
  readonly exitCode = 5;
}

export class MalformedMetadataError extends SnpmError {
  readonly code = 'E_MALFORMED_METADATA';
  readonly exitCode = 6;
  constructor(readonly pkg: string, readonly reason: string) {
    super(`Malformed registry metadata for ${pkg}: ${reason}`);
  }
}

export class QuarantineViolationError extends SnpmError {
  readonly code = 'E_QUARANTINE';
  readonly exitCode = 4;
  constructor(readonly pkg: string, readonly range: string, readonly blocked: readonly string[], readonly minAgeMs: number) {
    super(`No version of ${pkg}@${range} is older than ${minAgeMs / 3_600_000}h (blocked: ${blocked.join(', ') || 'none'})`);
  }
}

export class IntegrityMismatchError extends SnpmError {
  readonly code = 'E_INTEGRITY';
  readonly exitCode = 3;
  constructor(readonly spec: string, readonly expected: string, readonly actual: string) {
    super(`Integrity mismatch for ${spec}`);
  }
}

export class MalwareDetectedError extends SnpmError {
  readonly code = 'E_MALWARE';
  readonly exitCode = 3;
  constructor(readonly spec: string, readonly engine: 'clamd' | 'heuristic', readonly signature: string) {
    super(`Malware detected in ${spec} by ${engine}: ${signature}`);
  }
}

export class AntivirusSocketDropError extends SnpmError {
  readonly code = 'E_AV_SOCKET_DROP';
  readonly exitCode = 7;
}

export class AntivirusUnavailableError extends SnpmError {
  readonly code = 'E_AV_UNAVAILABLE';
  readonly exitCode = 7;
}

export class PathTraversalError extends SnpmError {
  readonly code = 'E_PATH_TRAVERSAL';
  readonly exitCode = 3;
  constructor(readonly entry: string) {
    super(`Refusing to write outside sandbox: ${entry}`);
  }
}

export class TarballTooLargeError extends SnpmError {
  readonly code = 'E_TARBALL_TOO_LARGE';
  readonly exitCode = 8;
  constructor(readonly spec: string, readonly bytes: number, readonly max: number) {
    super(`${spec} tarball is ${bytes} bytes (max ${max})`);
  }
}

export const isSnpmError = (e: unknown): e is SnpmError => e instanceof SnpmError;
