import { describe, expect, test } from 'bun:test';
import {
  NetworkUnavailableError,
  RegistryHttpError,
  RegistryTimeoutError,
  ResponseTooLargeError,
} from '../../src/utils/errors.ts';
import { HttpTransport, type FetchLike } from '../../src/utils/transport.ts';
import { noSleep } from '../helpers/mock-registry.ts';

const init = { accept: 'application/json', timeoutMs: 1_000, maxBytes: 1024 };
const policy = { attempts: 3, baseDelayMs: 1, maxDelayMs: 5 };

describe('HttpTransport', () => {
  test('retries 503 then succeeds', async () => {
    let n = 0;
    const f: FetchLike = async () => (++n < 3 ? new Response('', { status: 503 }) : new Response('ok'));
    const res = await new HttpTransport(f, policy, noSleep).get('https://r/x', init);
    expect(res.status).toBe(200);
    expect(new TextDecoder().decode(res.body)).toBe('ok');
    expect(n).toBe(3);
  });

  test('does not retry 404', async () => {
    let n = 0;
    const f: FetchLike = async () => { n += 1; return new Response('', { status: 404 }); };
    expect((await new HttpTransport(f, policy, noSleep).get('https://r/x', init)).status).toBe(404);
    expect(n).toBe(1);
  });

  test('persistent 5xx surfaces RegistryHttpError', async () => {
    const f: FetchLike = async () => new Response('', { status: 502 });
    await expect(new HttpTransport(f, policy, noSleep).get('https://r/x', init)).rejects.toBeInstanceOf(RegistryHttpError);
  });

  test('network drop -> NetworkUnavailableError after all attempts', async () => {
    let n = 0;
    const f: FetchLike = async () => { n += 1; throw new TypeError('fetch failed'); };
    await expect(new HttpTransport(f, policy, noSleep).get('https://r/x', init)).rejects.toBeInstanceOf(NetworkUnavailableError);
    expect(n).toBe(3);
  });

  test('timeout -> RegistryTimeoutError', async () => {
    // A hung server. The keepalive timer mimics a live socket: AbortSignal.timeout timers are
    // unref'd, so without it the runtime may exit before the abort ever fires.
    const f: FetchLike = (_u, i) =>
      new Promise((_, reject) => {
        const keepalive = setTimeout(() => reject(new Error('mock never aborted')), 5_000);
        i.signal?.addEventListener('abort', () => {
          clearTimeout(keepalive);
          reject(i.signal?.reason);
        });
      });
    const t = new HttpTransport(f, { attempts: 1, baseDelayMs: 1, maxDelayMs: 1 }, noSleep);
    await expect(t.get('https://r/x', { ...init, timeoutMs: 20 })).rejects.toBeInstanceOf(RegistryTimeoutError);
  });

  test('body over cap is cut off (declared and streamed)', async () => {
    const declared: FetchLike = async () => new Response('x'.repeat(10), { headers: { 'content-length': '999999' } });
    await expect(new HttpTransport(declared, policy, noSleep).get('https://r/x', init)).rejects.toBeInstanceOf(ResponseTooLargeError);
    const streamed: FetchLike = async () =>
      new Response(new ReadableStream({ pull(ctl) { ctl.enqueue(new Uint8Array(600)); } }));
    await expect(new HttpTransport(streamed, policy, noSleep).get('https://r/x', init)).rejects.toBeInstanceOf(ResponseTooLargeError);
  });

  test('sends If-None-Match when etag given', async () => {
    let seen: string | null = null;
    const f: FetchLike = async (_u, i) => { seen = new Headers(i.headers).get('if-none-match'); return new Response(null, { status: 304 }); };
    const res = await new HttpTransport(f, policy, noSleep).get('https://r/x', { ...init, etag: '"abc"' });
    expect(res.status).toBe(304);
    expect(seen).toBe('"abc"');
  });
});
