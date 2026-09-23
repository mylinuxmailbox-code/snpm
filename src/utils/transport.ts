import {
  NetworkUnavailableError,
  RegistryHttpError,
  RegistryTimeoutError,
  ResponseTooLargeError,
} from './errors.ts';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;
export type Sleep = (ms: number) => Promise<void>;

export interface GetInit {
  readonly accept: string;
  readonly timeoutMs: number;
  readonly maxBytes: number;
  readonly etag?: string;
}

export interface TransportResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: Headers;
  readonly body: Uint8Array;
}

export interface Transport {
  get(url: string, init: GetInit): Promise<TransportResponse>;
}

export interface RetryPolicy {
  readonly attempts: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
}

export const DEFAULT_RETRY: RetryPolicy = { attempts: 3, baseDelayMs: 200, maxDelayMs: 5_000 };

const USER_AGENT = `snpm/0.0.1 bun/${Bun.version} ${process.platform}-${process.arch}`;

const isNamedError = (e: unknown, name: string): boolean =>
  typeof e === 'object' && e !== null && 'name' in e && e.name === name;

/** Status codes worth retrying. 4xx (except 408/429) are the client's fault: never retry. */
const isRetryableStatus = (s: number): boolean => s === 408 || s === 429 || s >= 500;

function parseRetryAfter(h: string | null, maxMs: number): number | undefined {
  if (h === null) return undefined;
  const secs = Number(h);
  if (Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, maxMs);
  const at = Date.parse(h);
  return Number.isFinite(at) ? Math.min(Math.max(0, at - Date.now()), maxMs) : undefined;
}

/** Drain a body with a hard byte cap, cancelling the stream the moment it's exceeded. */
async function readCapped(res: Response, max: number, url: string): Promise<Uint8Array> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) {
    await res.body?.cancel();
    throw new ResponseTooLargeError(url, declared, max);
  }
  const body = res.body;
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new ResponseTooLargeError(url, total, max);
    }
    chunks.push(value);
  }
  if (chunks.length === 1 && chunks[0] !== undefined) return chunks[0];
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export class HttpTransport implements Transport {
  constructor(
    private readonly fetchImpl: FetchLike = fetch,
    private readonly retry: RetryPolicy = DEFAULT_RETRY,
    private readonly sleep: Sleep = (ms) => Bun.sleep(ms),
  ) {}

  async get(url: string, init: GetInit): Promise<TransportResponse> {
    let lastError: unknown;
    for (let attempt = 0; attempt < this.retry.attempts; attempt++) {
      let delay = Math.min(this.retry.baseDelayMs * 2 ** attempt, this.retry.maxDelayMs);
      delay += Math.floor(Math.random() * this.retry.baseDelayMs); // jitter
      try {
        const res = await this.once(url, init);
        if (!isRetryableStatus(res.status)) return res;
        lastError = new RegistryHttpError(url, res.status);
        delay = parseRetryAfter(res.headers.get('retry-after'), this.retry.maxDelayMs) ?? delay;
      } catch (err: unknown) {
        if (isNamedError(err, 'TimeoutError')) {
          lastError = new RegistryTimeoutError(url, init.timeoutMs, { cause: err });
        } else if (err instanceof TypeError || isNamedError(err, 'ConnectionRefused') || isNamedError(err, 'FailedToOpenSocket')) {
          lastError = new NetworkUnavailableError(`Network unreachable: ${url}`, { cause: err });
        } else {
          throw err; // ResponseTooLargeError, programmer errors: never retry
        }
      }
      if (attempt < this.retry.attempts - 1) await this.sleep(delay);
    }
    throw lastError instanceof Error ? lastError : new NetworkUnavailableError(`Request failed: ${url}`);
  }

  private async once(url: string, init: GetInit): Promise<TransportResponse> {
    const headers = new Headers({ accept: init.accept, 'user-agent': USER_AGENT });
    if (init.etag !== undefined) headers.set('if-none-match', init.etag);
    const res = await this.fetchImpl(url, {
      method: 'GET',
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(init.timeoutMs),
    });
    if (res.status === 304 || isRetryableStatus(res.status) || res.status >= 400) {
      await res.body?.cancel();
      return { url, status: res.status, headers: res.headers, body: new Uint8Array(0) };
    }
    const body = await readCapped(res, init.maxBytes, url);
    return { url, status: res.status, headers: res.headers, body };
  }
}
