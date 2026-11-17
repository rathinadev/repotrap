import { sanitizeEvidence } from '../text.ts';
import { exfilEndpoint } from '../patterns.ts';
import type { CorrelationRule, FileContext, Finding, RawFinding, RepoContext } from '../types.ts';

const PAYLOAD_CATEGORIES = new Set(['OBF', 'NET', 'STEAL', 'SYS']);

function resolveRef(ctx: RepoContext, ref: string, from: string): FileContext | undefined {
  const direct = ctx.byPath.get(ref);
  if (direct) return direct;
  // Relative to the referencing file's folder (e.g. a devcontainer script next to devcontainer.json)
  const dir = from.includes('/') ? from.slice(0, from.lastIndexOf('/') + 1) : '';
  const relative = ctx.byPath.get(dir + ref);
  if (relative) return relative;
  for (const f of ctx.files) if (f.path.endsWith(`/${ref}`)) return f;
  return undefined;
}

export const CHAIN_001: CorrelationRule = {
  kind: 'correlation',
  id: 'CHAIN-001',
  title: 'Auto-run trigger executes a suspicious file',
  category: 'CHAIN',
  severity: 'critical',
  advice:
    'Opening or building this project automatically runs a file that itself contains malicious-looking code. This combination is the signature of repository traps. Do not open, build or run this repository.',
  check(ctx, findings) {
    const out: RawFinding[] = [];
    const byFile = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!f.file) continue;
      const list = byFile.get(f.file) ?? [];
      list.push(f);
      byFile.set(f.file, list);
    }
    for (const trigger of findings) {
      if (trigger.category !== 'EXEC' || !trigger.file || !trigger.refs?.length) continue;
      for (const ref of trigger.refs) {
        const target = resolveRef(ctx, ref, trigger.file);
        if (!target || target.path === trigger.file) continue;
        const payload = (byFile.get(target.path) ?? []).filter((x) => PAYLOAD_CATEGORIES.has(x.category) || x.ruleId === 'BIN-002');
        if (payload.length === 0) continue;
        out.push({
          file: trigger.file,
          line: trigger.line,
          evidence: trigger.evidence,
          message: `${trigger.ruleId} runs ${target.path}, which contains: ${[...new Set(payload.map((p) => p.title))].join('; ')}`,
          refs: [target.path],
        });
        break;
      }
    }
    return out;
  },
};

export const CHAIN_002: CorrelationRule = {
  kind: 'correlation',
  id: 'CHAIN-002',
  title: 'Credential theft combined with an exfiltration channel',
  category: 'CHAIN',
  severity: 'critical',
  advice:
    'The repository reads stored credentials and also contains an address commonly used to receive stolen data (a webhook, bot or paste service, or a raw IP). Treat this repository as an information stealer.',
  check(ctx, findings) {
    const theft = findings.find((f) => f.ruleId === 'STEAL-001');
    if (!theft) return [];
    for (const f of ctx.files) {
      if (f.text === undefined || f.isDoc || f.isData) continue;
      const lines = f.lines();
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (line.length > 50_000) continue;
        const endpoint = exfilEndpoint(line);
        if (endpoint) {
          return [
            {
              file: f.path,
              line: i + 1,
              evidence: sanitizeEvidence(line),
              message: `Credential access in ${theft.file ?? 'the repository'} and an exfiltration endpoint (${sanitizeEvidence(endpoint, 60)}) in ${f.path}`,
            },
          ];
        }
      }
    }
    return [];
  },
};

export const CHAIN_RULES: CorrelationRule[] = [CHAIN_001, CHAIN_002];
