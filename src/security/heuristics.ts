export interface HeuristicFinding { readonly severity: 'high' | 'medium'; readonly indicator: string; readonly file: string; }
export interface ScannableFile { readonly path: string; readonly data: Uint8Array; }
const HIGH: readonly { readonly id: string; readonly re: RegExp }[] = [
  { id: 'eval+base64-decode', re: /\beval\s*\([^\n]{0,256}(?:atob\s*\(|Buffer\.from\s*\([^\n]{0,128}base64)/i },
  { id: 'environment-exfiltration', re: /process\.env[\s\S]{0,300}(?:fetch\s*\(|https?\.request|http\.request|dns\.lookup)/i },
  { id: 'credential-path-access', re: /(?:\.npmrc|\.ssh\/|\.aws\/credentials|wallet\.dat)/i },
  { id: 'install-script-shell', re: /child_process[\s\S]{0,200}(?:exec|spawn)\s*\(/i },
];
const MEDIUM: readonly { readonly id: string; readonly re: RegExp }[] = [
  { id: 'dynamic-function', re: /new\s+Function\s*\(/i },
  { id: 'encoded-blob', re: /(?:[A-Za-z0-9+/]{2048,}={0,2}|[0-9a-f]{4096,})/i },
];
export function scanHeuristics(files: readonly ScannableFile[]): readonly HeuristicFinding[] {
  const findings: HeuristicFinding[] = []; const decoder = new TextDecoder();
  for (const file of files) { const text = decoder.decode(file.data);
    for (const rule of HIGH) if (rule.re.test(text)) findings.push({ severity: 'high', indicator: rule.id, file: file.path });
    for (const rule of MEDIUM) if (rule.re.test(text)) findings.push({ severity: 'medium', indicator: rule.id, file: file.path });
  }
  return findings;
}
export function blockFindings(findings: readonly HeuristicFinding[]): HeuristicFinding | undefined { return findings.find((f) => f.severity === 'high'); }
