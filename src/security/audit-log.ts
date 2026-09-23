import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { MalformedMetadataError } from '../utils/errors.ts';
export interface AuditEvent { readonly at: string; readonly kind: string; readonly package?: string; readonly detail?: string; }
interface AuditLine extends AuditEvent { readonly previous: string; readonly digest: string; }
const hash = (text: string): string => new Bun.CryptoHasher('sha256').update(text).digest('hex');
let queue: Promise<void> = Promise.resolve();
export function appendAudit(path: string, event: AuditEvent): Promise<void> { const next = queue.then(() => appendSerial(path, event)); queue = next.then(() => {}, () => {}); return next; }
async function appendSerial(path: string, event: AuditEvent): Promise<void> {
  await mkdir(dirname(path), { recursive: true }); const file = Bun.file(path); const prior = await file.exists() ? await file.text() : ''; let previous = '0'.repeat(64);
  for (const [index, line] of prior.split('\n').filter(Boolean).entries()) {
    let parsed: unknown; try { parsed = JSON.parse(line); } catch { throw new MalformedMetadataError('audit.log', `invalid JSON at line ${index + 1}`); }
    if (typeof parsed !== 'object' || parsed === null || !('digest' in parsed) || !('previous' in parsed)) throw new MalformedMetadataError('audit.log', `invalid hash-chain fields at line ${index + 1}`);
    const digest = Reflect.get(parsed, 'digest'); const predecessor = Reflect.get(parsed, 'previous');
    if (typeof digest !== 'string' || predecessor !== previous) throw new MalformedMetadataError('audit.log', `hash-chain predecessor mismatch at line ${index + 1}`);
    const payload: Record<string, unknown> = {}; for (const [key, value] of Object.entries(parsed)) if (key !== 'digest') payload[key] = value;
    if (hash(JSON.stringify(payload)) !== digest) throw new MalformedMetadataError('audit.log', `hash mismatch at line ${index + 1}`); previous = digest;
  }
  const payload = { ...event, previous }; const line: AuditLine = { ...payload, digest: hash(JSON.stringify(payload)) };
  await Bun.write(path, `${prior}${JSON.stringify(line)}\n`);
}
