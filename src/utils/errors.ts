export abstract class SnpmError extends Error {
  abstract readonly code: string;
  abstract readonly exitCode: number;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

// ---- network / registry (exit 5, 9) ---------------------------------------

export class RegistryTimeoutError extends SnpmError {
  override readonly code = 'E_REGISTRY_TIMEOUT';
  override readonly exitCode = 5;
  constructor(readonly url: string, readonly timeoutMs: number, options?: { cause?: unknown }) {
    super(`Registry request timed out after ${timeoutMs}ms: ${url}`, options);
  }
}

export class NetworkUnavailableError extends SnpmError {
  override readonly code = 'E_NETWORK';
  override readonly exitCode = 5;
}

export class RegistryHttpError extends SnpmError {
  override readonly code = 'E_REGISTRY_HTTP';
  override readonly exitCode = 5;
  constructor(readonly url: string, readonly status: number) {
    super(`Registry responded ${status}: ${url}`);
  }
}

export class ResponseTooLargeError extends SnpmError {
  override readonly code = 'E_RESPONSE_TOO_LARGE';
  override readonly exitCode = 8;
  constructor(readonly url: string, readonly bytes: number, readonly max: number) {
    super(`Response from ${url} exceeded ${max} bytes (saw ${bytes})`);
  }
}

export class PackageNotFoundError extends SnpmError {
  override readonly code = 'E_NOT_FOUND';
  override readonly exitCode = 9;
  constructor(readonly pkg: string) {
    super(`Package not found in registry: ${pkg}`);
  }
}

// ---- metadata / resolution (exit 2, 6, 9, 10) -----------------------------

export class MalformedMetadataError extends SnpmError {
  override readonly code = 'E_MALFORMED_METADATA';
  override readonly exitCode = 6;
  constructor(readonly pkg: string, readonly reason: string) {
    super(`Malformed registry metadata for ${pkg}: ${reason}`);
  }
}

export class InvalidPackageNameError extends SnpmError {
  override readonly code = 'E_INVALID_NAME';
  override readonly exitCode = 2;
  constructor(readonly pkg: string) {
    super(`Invalid package name: ${JSON.stringify(pkg)}`);
  }
}

export class UnsupportedSpecError extends SnpmError {
  override readonly code = 'E_UNSUPPORTED_SPEC';
  override readonly exitCode = 10;
  constructor(readonly pkg: string, readonly spec: string) {
    super(`${pkg}: spec ${JSON.stringify(spec)} is not a registry range (git/file/url/workspace specs are refused)`);
  }
}

export class NoMatchingVersionError extends SnpmError {
  override readonly code = 'E_NO_MATCH';
  override readonly exitCode = 9;
  constructor(readonly pkg: string, readonly range: string) {
    super(`No version of ${pkg} satisfies ${JSON.stringify(range)}`);
  }
}

export class DependencyGraphTooLargeError extends SnpmError {
  override readonly code = 'E_GRAPH_TOO_LARGE';
  override readonly exitCode = 8;
  constructor(readonly max: number) {
    super(`Dependency graph exceeded ${max} nodes (possible dependency bomb)`);
  }
}

// ---- security (exit 3, 4, 7) ----------------------------------------------

export class QuarantineViolationError extends SnpmError {
  override readonly code = 'E_QUARANTINE';
  override readonly exitCode = 4;
  constructor(readonly pkg: string, readonly range: string, readonly blocked: readonly string[], readonly minAgeMs: number) {
    super(`No version of ${pkg}@${range} is older than ${minAgeMs / 3_600_000}h (blocked: ${blocked.join(', ') || 'none'})`);
  }
}

export class IntegrityMismatchError extends SnpmError {
  override readonly code = 'E_INTEGRITY';
  override readonly exitCode = 3;
  constructor(readonly spec: string, readonly expected: string, readonly actual: string) {
    super(`Integrity mismatch for ${spec}`);
  }
}

export class MalwareDetectedError extends SnpmError {
  override readonly code = 'E_MALWARE';
  override readonly exitCode = 3;
  constructor(readonly spec: string, readonly engine: 'clamd' | 'heuristic', readonly signature: string) {
    super(`Malware detected in ${spec} by ${engine}: ${signature}`);
  }
}

export class AntivirusSocketDropError extends SnpmError {
  override readonly code = 'E_AV_SOCKET_DROP';
  override readonly exitCode = 7;
}

export class AntivirusUnavailableError extends SnpmError {
  override readonly code = 'E_AV_UNAVAILABLE';
  override readonly exitCode = 7;
}

export class PathTraversalError extends SnpmError {
  override readonly code = 'E_PATH_TRAVERSAL';
  override readonly exitCode = 3;
  constructor(readonly entry: string) {
    super(`Refusing to write outside sandbox: ${entry}`);
  }
}

export class TarballTooLargeError extends SnpmError {
  override readonly code = 'E_TARBALL_TOO_LARGE';
  override readonly exitCode = 8;
  constructor(readonly spec: string, readonly bytes: number, readonly max: number) {
    super(`${spec} tarball is ${bytes} bytes (max ${max})`);
  }
}

export const isSnpmError = (e: unknown): e is SnpmError => e instanceof SnpmError;
