import { join } from 'node:path';
import type { Clock } from '../utils/clock.ts';
import {
  MalformedMetadataError,
  NetworkUnavailableError,
  PackageNotFoundError,
  RegistryHttpError,
  RegistryTimeoutError,
} from '../utils/errors.ts';
import { atomicWrite } from '../utils/fs-layout.ts';
import { BoundedPool, SingleFlight } from '../utils/pool.ts';
import type { Transport } from '../utils/transport.ts';
import { encodePackageName, parsePackument, type ParseResult } from './manifest.ts';

// Full document, NOT `application/vnd.npm.install-v1+json` (corgi): corgi drops the `time` block
// the quarantine gate depends on.
const ACCEPT_FULL = 'application/json';

export interface CachedMeta {
  readonly etag?: string;
  readonly fetchedAt: number;
  readonly body: string;
}

export interface MetaStore {
  read(name: string): Promise<CachedMeta | undefined>;
  write(name: string, entry: CachedMeta): Promise<void>;
}

export class MemoryMetaStore implements MetaStore {
  readonly entries = new Map<string, CachedMeta>();
  async read(name: string): Promise<CachedMeta | undefined> {
    return this.entries.get(name);
  }
  async write(name: string, entry: CachedMeta): Promise<void> {
    this.entries.set(name, entry);
  }
}

/** Disk store under .snpm/cache/meta, keyed by sha256(name) so names never touch the path. */
export class FsMetaStore implements MetaStore {
  constructor(private readonly dir: string) {}

  private pathFor(name: string): string {
    const h = new Bun.CryptoHasher('sha256').update(name).digest('hex');
    return join(this.dir, h.slice(0, 2), `${h}.json`);
  }

  async read(name: string): Promise<CachedMeta | undefined> {
    const f = Bun.file(this.pathFor(name));
    if (!(await f.exists())) return undefined;
    let raw: unknown;
    try {
      raw = await f.json();
    } catch {
      return undefined; // torn/corrupt cache entry: treat as miss
    }
    if (typeof raw !== 'object' || raw === null) return undefined;
    const fetchedAt = 'fetchedAt' in raw ? raw.fetchedAt : undefined;
    const body = 'body' in raw ? raw.body : undefined;
    const etag = 'etag' in raw ? raw.etag : undefined;
    if (typeof fetchedAt !== 'number' || typeof body !== 'string') return undefined;
    return typeof etag === 'string' ? { etag, fetchedAt, body } : { fetchedAt, body };
  }

  async write(name: string, entry: CachedMeta): Promise<void> {
    await atomicWrite(this.pathFor(name), JSON.stringify(entry));
  }
}

export interface RegistryOptions {
  readonly registry: string;
  readonly timeoutMs: number;
  /** Serve from cache without revalidating inside this window. */
  readonly freshTtlMs: number;
  /** On network failure, fall back to cache up to this age. Stale meta is quarantine-safe:
   *  it can only list *older* versions, never newer ones. */
  readonly staleMaxMs: number;
  readonly maxMetaBytes: number;
}

export const DEFAULT_REGISTRY_OPTIONS: RegistryOptions = {
  registry: 'https://registry.npmjs.org',
  timeoutMs: 30_000,
  freshTtlMs: 5 * 60_000,
  staleMaxMs: 24 * 3_600_000,
  maxMetaBytes: 64 * 1024 * 1024, // some packuments (e.g. @types/node) are tens of MB
};

export type RegistryEvent =
  | { readonly kind: 'cache-hit'; readonly name: string }
  | { readonly kind: 'revalidated'; readonly name: string }
  | { readonly kind: 'fetched'; readonly name: string; readonly bytes: number }
  | { readonly kind: 'stale-fallback'; readonly name: string; readonly ageMs: number; readonly cause: string }
  | { readonly kind: 'metadata-warning'; readonly error: MalformedMetadataError };

const isTransient = (err: unknown): err is Error =>
  err instanceof NetworkUnavailableError ||
  err instanceof RegistryTimeoutError ||
  (err instanceof RegistryHttpError && err.status >= 500);

function decodeUtf8(name: string, bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new MalformedMetadataError(name, 'response is not valid UTF-8');
  }
}

export class RegistryClient {
  private readonly memo = new SingleFlight<string, ParseResult>();
  private readonly base: string;
  private readonly tarballHosts: ReadonlySet<string>;

  constructor(
    private readonly transport: Transport,
    private readonly pool: BoundedPool,
    private readonly store: MetaStore,
    private readonly clock: Clock,
    private readonly opts: RegistryOptions = DEFAULT_REGISTRY_OPTIONS,
    private readonly onEvent: (e: RegistryEvent) => void = () => {},
  ) {
    this.base = opts.registry.replace(/\/+$/, '');
    this.tarballHosts = new Set([new URL(this.base).hostname]);
  }

  /** Synchronous hit if this packument already resolved in-process. */
  peek(name: string): ParseResult | undefined {
    return this.memo.peek(name);
  }

  packument(name: string): Promise<ParseResult> {
    return this.memo.get(name, () => this.pool.run(() => this.load(name)));
  }

  private parse(name: string, body: string): ParseResult {
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      throw new MalformedMetadataError(name, 'response is not valid JSON');
    }
    const result = parsePackument(name, json, { allowedTarballHosts: this.tarballHosts });
    for (const w of result.warnings) this.onEvent({ kind: 'metadata-warning', error: w });
    return result;
  }

  private async load(name: string): Promise<ParseResult> {
    const url = `${this.base}/${encodePackageName(name)}`;
    const now = this.clock.now();
    const cached = await this.store.read(name);

    if (cached !== undefined && now - cached.fetchedAt < this.opts.freshTtlMs) {
      this.onEvent({ kind: 'cache-hit', name });
      return this.parse(name, cached.body);
    }

    try {
      const res = await this.transport.get(url, {
        accept: ACCEPT_FULL,
        timeoutMs: this.opts.timeoutMs,
        maxBytes: this.opts.maxMetaBytes,
        ...(cached?.etag !== undefined ? { etag: cached.etag } : {}),
      });

      if (res.status === 304 && cached !== undefined) {
        this.onEvent({ kind: 'revalidated', name });
        await this.store.write(name, { ...cached, fetchedAt: now });
        return this.parse(name, cached.body);
      }
      if (res.status === 404) throw new PackageNotFoundError(name);
      if (res.status !== 200) throw new RegistryHttpError(url, res.status);

      const body = decodeUtf8(name, res.body);
      const result = this.parse(name, body); // parse BEFORE caching: never persist garbage
      const etag = res.headers.get('etag');
      await this.store.write(name, etag !== null ? { etag, fetchedAt: now, body } : { fetchedAt: now, body });
      this.onEvent({ kind: 'fetched', name, bytes: res.body.byteLength });
      return result;
    } catch (err: unknown) {
      if (isTransient(err) && cached !== undefined && now - cached.fetchedAt < this.opts.staleMaxMs) {
        this.onEvent({ kind: 'stale-fallback', name, ageMs: now - cached.fetchedAt, cause: err.message });
        return this.parse(name, cached.body);
      }
      throw err;
    }
  }
}
