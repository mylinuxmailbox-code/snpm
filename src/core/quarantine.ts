import { QuarantineViolationError } from '../utils/errors.ts';
import type { Selection, SelectionContext, VersionSelector } from './resolver.ts';

export interface QuarantineOptions {
  readonly nowMs: number;
  readonly minAgeMs?: number;
  readonly onBlocked?: (event: { readonly name: string; readonly range: string; readonly version: string; readonly ageMs?: number; readonly minAgeMs: number }) => void;
}

/**
 * Mandatory, range-preserving version age gate. The resolver supplies candidates already
 * filtered by the requested semver range and sorted newest-first. This selector only walks
 * that list, so it can never escape the range to find an older release.
 */
export function quarantineSelector(options: QuarantineOptions): VersionSelector {
  const minAgeMs = options.minAgeMs ?? 12 * 3_600_000;
  return {
    select(ctx: SelectionContext): Selection {
      const blocked: string[] = [];
      for (const version of ctx.candidates) {
        const publishedAt = ctx.packument.time.get(version);
        const ageMs = publishedAt === undefined ? undefined : options.nowMs - publishedAt;
        if (ageMs !== undefined && publishedAt !== undefined && publishedAt <= options.nowMs && ageMs >= minAgeMs) {
          return {
            version,
            rejected: blocked.map((v) => ({ version: v, reason: `blocked by mandatory ${minAgeMs / 3_600_000}h quarantine` })),
          };
        }
        blocked.push(version);
        options.onBlocked?.({
          name: ctx.spec.name,
          range: ctx.spec.range,
          version,
          ...(ageMs === undefined ? {} : { ageMs }),
          minAgeMs,
        });
      }
      throw new QuarantineViolationError(ctx.spec.name, ctx.spec.range, blocked, minAgeMs);
    },
  };
}
