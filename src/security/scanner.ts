import { AntivirusUnavailableError, MalwareDetectedError } from '../utils/errors.ts';
import type { ScanVerdict } from './types.ts';
import { scanHeuristics, blockFindings } from './heuristics.ts';
import { ClamdScanner, type ClamdTarget } from './clamd.ts';
import { unpackTarball, type TarLimits, type TarFile } from '../utils/tar.ts';

export interface ScannerOptions {
  readonly mode: 'strict' | 'auto' | 'heuristic-only';
  readonly clamdTargets?: readonly ClamdTarget[];
  readonly onFallback?: (reason: string) => void;
  readonly chunkBytes: number;
  readonly timeoutMs: number;
  readonly tarLimits?: TarLimits;
}
export interface PackageScan { readonly verdict: ScanVerdict; readonly files: readonly TarFile[]; }
export async function scanPackage(spec: string, tarball: Uint8Array, options: ScannerOptions): Promise<PackageScan> {
  const files = unpackTarball(tarball, spec, options.tarLimits);
  const findings = scanHeuristics(files);
  const blocked = blockFindings(findings);
  if (blocked !== undefined) throw new MalwareDetectedError(spec, 'heuristic', `${blocked.indicator} in ${blocked.file}`);
  if (options.mode === 'heuristic-only') return { verdict: findings.length ? { kind: 'suspicious', findings } : { kind: 'clean', engine: 'heuristic' }, files };
  const targets = options.clamdTargets ?? [];
  if (targets.length === 0) {
    if (options.mode === 'strict') throw new AntivirusUnavailableError('strict scanner mode requires a configured ClamAV endpoint');
    options.onFallback?.('no ClamAV endpoint configured; heuristic-only scan used');
    return { verdict: findings.length ? { kind: 'suspicious', findings } : { kind: 'clean', engine: 'heuristic' }, files };
  }
  let lastError: unknown;
  for (const target of targets) {
    try {
      await new ClamdScanner(target, { chunkBytes: options.chunkBytes, timeoutMs: options.timeoutMs }).scan(tarball, spec);
      return { verdict: findings.length ? { kind: 'suspicious', findings } : { kind: 'clean', engine: 'clamd' }, files };
    } catch (err: unknown) {
      if (err instanceof MalwareDetectedError) throw err;
      lastError = err;
    }
  }
  if (options.mode === 'strict') throw lastError instanceof Error ? lastError : new AntivirusUnavailableError('ClamAV unavailable');
  options.onFallback?.(`ClamAV unavailable; heuristic-only fallback used: ${String(lastError)}`);
  return { verdict: findings.length ? { kind: 'suspicious', findings } : { kind: 'clean', engine: 'heuristic' }, files };
}
