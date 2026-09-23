import { AntivirusSocketDropError, AntivirusUnavailableError, MalwareDetectedError } from '../utils/errors.ts';
export interface ClamdTarget { readonly kind: 'unix' | 'tcp'; readonly path?: string; readonly hostname?: string; readonly port?: number; }
export interface ClamdScanOptions { readonly chunkBytes: number; readonly timeoutMs: number; }
export interface ScanResult { readonly clean: boolean; readonly signature?: string; }
const enc = new TextEncoder();
const decoder = new TextDecoder();
export class ClamdScanner {
  constructor(private readonly target: ClamdTarget, private readonly opts: ClamdScanOptions) {}
  async scan(bytes: Uint8Array, spec: string): Promise<ScanResult> {
    try {
      const reply = await this.command(bytes);
      if (reply.includes('FOUND')) {
        const signature = reply.replace(/^stream:\s*/, '').replace(/\s*FOUND\0?$/, '').trim();
        throw new MalwareDetectedError(spec, 'clamd', signature || 'unknown signature');
      }
      if (!/stream:\s*OK/.test(reply)) throw new AntivirusSocketDropError(`Unexpected clamd reply: ${reply}`);
      return { clean: true };
    } catch (err: unknown) {
      if (err instanceof MalwareDetectedError || err instanceof AntivirusSocketDropError) throw err;
      throw new AntivirusUnavailableError(`ClamAV connection failed: ${String(err)}`, { cause: err });
    }
  }
  private async command(bytes: Uint8Array): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let socket: { end(): unknown; write(data: string | Uint8Array): unknown } | undefined;
      const chunks: Uint8Array[] = [];
      let finished = false;
      const timer = setTimeout(() => finish(new AntivirusSocketDropError('ClamAV response timeout')), this.opts.timeoutMs);
      const finish = (err?: unknown): void => {
        if (finished) return;
        finished = true; clearTimeout(timer); socket?.end();
        if (err !== undefined) reject(err); else resolve(decoder.decode(concat(chunks)));
      };
      const handlers = {
        data(_s: unknown, data: Uint8Array) { chunks.push(new Uint8Array(data)); if (decoder.decode(concat(chunks)).includes('\0')) finish(); },
        error(_s: unknown, error: Error) { finish(error); },
        close() { if (!finished) finish(new AntivirusSocketDropError('ClamAV socket closed before reply')); },
      };
      const connecting = this.target.kind === 'unix'
        ? Bun.connect({ unix: this.target.path ?? '', socket: handlers })
        : Bun.connect({ hostname: this.target.hostname ?? '127.0.0.1', port: this.target.port ?? 3310, socket: handlers });
      connecting.then((s) => {
        socket = s;
        s.write(enc.encode('zINSTREAM\0'));
        for (let offset = 0; offset < bytes.byteLength; offset += this.opts.chunkBytes) {
          const chunk = bytes.subarray(offset, Math.min(offset + this.opts.chunkBytes, bytes.byteLength));
          const frame = new Uint8Array(4 + chunk.byteLength);
          new DataView(frame.buffer).setUint32(0, chunk.byteLength, false);
          frame.set(chunk, 4); s.write(frame);
        }
        s.write(new Uint8Array(4));
      }, (err: unknown) => finish(err));
    });
  }
}
function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const size = chunks.reduce((n, b) => n + b.byteLength, 0);
  const out = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return out;
}
