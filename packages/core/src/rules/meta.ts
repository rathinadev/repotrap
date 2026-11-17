import { sanitizeEvidence } from '../text.ts';
import { ARCHIVE_EXT, EXECUTABLE_EXT, detectMagic, zipFirstEntryEncrypted } from '../patterns.ts';
import type { CorrelationRule, FileContext, FileRule, RawFinding } from '../types.ts';

const README_RE = /^readme(?:\.(?:md|markdown|mdx|txt|rst|adoc))?$/;
export const isReadme = (f: FileContext): boolean => README_RE.test(f.base);

const AV_DISABLE =
  /\b(?:disable|turn\s+off|deactivate|pause|switch\s+off)\s+(?:your\s+|the\s+|all\s+)?(?:anti-?virus|windows\s+defender|defender|av|real-?time\s+protection|smartscreen|security\s+software)\b/i;
const AV_EXCLUDE =
  /\badd\s+(?:an?\s+|the\s+\w+\s+)?(?:to\s+(?:the\s+)?)?exclusions?\b|\bexclude\s+(?:the\s+|this\s+)?(?:folder|file|directory|program)\s+from\s+(?:your\s+)?(?:anti-?virus|defender|scanning)/i;
const ARCHIVE_PASSWORD = /\bpass(?:word|wd|code)?(?:\s*is)?(?:\s*[:=]|\s+[–-]\s)\s*["'`*]*[\w!@#$%^&*.-]{3,}/i;
const ARCHIVE_CONTEXT = /\b(?:zip|rar|7z|7-zip|archive|extract|unpack|download|release)\b/i;
const FALSE_POSITIVE = /\bfalse\s+positives?\b|\bflagged\s+(?:by|as)\s+(?:a\s+)?(?:virus|malware|trojan|anti-?virus|defender)\b/i;
const RUN_AS_ADMIN = /\brun\s+(?:it\s+|this\s+|the\s+\w+\s+)?as\s+(?:an?\s+)?admin(?:istrator)?\b/i;

export const META_007: FileRule = {
  kind: 'file',
  id: 'META-007',
  title: 'README asks you to weaken your protection',
  category: 'META',
  severity: 'high',
  advice:
    'Legitimate projects almost never ask you to turn off antivirus or to unpack a password-protected archive. These instructions are typical of malware lures. Do not follow them.',
  appliesTo: (f) => f.text !== undefined && isReadme(f),
  check(f) {
    const lines = f.lines();
    const out: RawFinding[] = [];
    let falsePositive: number | undefined;
    let runAsAdmin: number | undefined;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (AV_DISABLE.test(line) || AV_EXCLUDE.test(line)) {
        out.push({ line: i + 1, evidence: sanitizeEvidence(line), message: 'Instructions to disable or bypass antivirus' });
      }
      const context = [lines[i - 2], lines[i - 1], line, lines[i + 1]].join(' ');
      if (ARCHIVE_PASSWORD.test(line) && ARCHIVE_CONTEXT.test(context)) {
        out.push({ line: i + 1, evidence: sanitizeEvidence(line), message: 'Download is a password-protected archive, which hides its contents from scanners' });
      }
      if (falsePositive === undefined && FALSE_POSITIVE.test(line)) falsePositive = i + 1;
      if (runAsAdmin === undefined && RUN_AS_ADMIN.test(line)) runAsAdmin = i + 1;
    }
    if (falsePositive !== undefined && runAsAdmin !== undefined) {
      out.push({
        severity: 'medium',
        line: falsePositive,
        evidence: sanitizeEvidence(lines[falsePositive - 1] ?? ''),
        message: 'Claims antivirus alerts are false positives and asks you to run as administrator',
      });
    }
    return out;
  },
};

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i;
const YOUNG_OWNER_DAYS = 90;

export const META_003: CorrelationRule = {
  kind: 'correlation',
  id: 'META-003',
  title: 'Looks like a fake exploit (proof-of-concept) repository',
  category: 'META',
  severity: 'medium',
  advice:
    'New accounts publishing "exploits" for CVEs together with binaries, archives or obfuscated code are a known way to infect security researchers. Only run exploit code you have read in full, inside an isolated VM.',
  check(ctx, findings) {
    const repo = ctx.repo;
    if (!repo?.ownerCreatedAt) return [];
    const ageDays = (ctx.now.getTime() - Date.parse(repo.ownerCreatedAt)) / 864e5;
    if (!Number.isFinite(ageDays) || ageDays >= YOUNG_OWNER_DAYS) return [];

    const readme = ctx.files.find((f) => isReadme(f) && !f.path.includes('/'));
    const mentionsCve = CVE_RE.test(repo.name) || CVE_RE.test(repo.description ?? '') || CVE_RE.test(readme?.text ?? '');
    if (!mentionsCve) return [];

    const signals: string[] = [];
    const executable = ctx.files.some((f) => ['pe', 'elf', 'macho'].includes(detectMagic(f.head)) || EXECUTABLE_EXT.has(f.ext));
    const encrypted = ctx.files.some((f) => zipFirstEntryEncrypted(f.head));
    const archive = ctx.files.some((f) => ARCHIVE_EXT.has(f.ext) || detectMagic(f.head) === 'zip');
    const obfuscated = findings.some((x) => x.category === 'OBF' || x.category === 'BIN');
    if (executable) signals.push('executables');
    if (encrypted) signals.push('a password-protected archive');
    else if (archive) signals.push('archives');
    if (obfuscated) signals.push('obfuscated or disguised files');
    if (signals.length === 0) return [];

    return [
      {
        severity: executable || encrypted ? 'high' : 'medium',
        file: readme?.path,
        message: `Owner account is ${Math.max(0, Math.floor(ageDays))} days old, the repository presents a CVE exploit, and it ships ${signals.join(', ')}`,
      },
    ];
  },
};

export const META_FILE_RULES: FileRule[] = [META_007];
export const META_CORRELATION_RULES: CorrelationRule[] = [META_003];
