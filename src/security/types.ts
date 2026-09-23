import type { HeuristicFinding } from './heuristics.ts';
export type ScanVerdict =
  | { readonly kind: 'clean'; readonly engine: 'clamd' | 'heuristic' }
  | { readonly kind: 'infected'; readonly engine: 'clamd' | 'heuristic'; readonly signature: string }
  | { readonly kind: 'suspicious'; readonly findings: readonly HeuristicFinding[] };
