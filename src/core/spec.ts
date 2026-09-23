import { UnsupportedSpecError } from '../utils/errors.ts';
import { assertValidName } from './manifest.ts';

export interface RegistrySpec {
  /** Name as it appears in the dependent's manifest (folder name in node_modules). */
  readonly alias: string;
  /** Real registry package name (differs from alias for `npm:` aliases). */
  readonly name: string;
  readonly range: string;
}

// Anything that would fetch code from outside the registry bypasses the quarantine gate,
// integrity pinning and provenance. Refused outright rather than half-supported.
const REFUSED = /^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|workspace:|portal:|patch:)/i;
const GH_SHORTHAND = /^[^@./][^/\s]*\/[^/\s]+(?:#.*)?$/;

export function parseSpec(alias: string, raw: string): RegistrySpec {
  assertValidName(alias);
  const spec = raw.trim();
  if (spec.startsWith('npm:')) return parseAlias(alias, raw, spec.slice(4));
  if (REFUSED.test(spec) || GH_SHORTHAND.test(spec) || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('~/')) {
    throw new UnsupportedSpecError(alias, raw);
  }
  return { alias, name: alias, range: spec === '' ? '*' : spec };
}

function parseAlias(alias: string, raw: string, body: string): RegistrySpec {
  const at = body.lastIndexOf('@');
  const name = at > 0 ? body.slice(0, at) : body;
  const range = at > 0 ? body.slice(at + 1).trim() : '*';
  assertValidName(name);
  if (range.startsWith('npm:') || REFUSED.test(range)) throw new UnsupportedSpecError(alias, raw);
  return { alias, name, range: range === '' ? '*' : range };
}
