import { sanitizeEvidence } from '../text.ts';
import { detectMagic, looksLikeScript } from '../patterns.ts';
import type { FileRule, RawFinding } from '../types.ts';

/** Extensions whose real content should be media or documents, never code or executables. */
const MEDIA_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'webp', 'tif', 'tiff', 'heic',
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  'mp3', 'mp4', 'wav', 'ogg', 'flac', 'mov', 'avi', 'mkv', 'webm',
  'pdf', 'psd',
]);

export const BIN_002: FileRule = {
  kind: 'file',
  id: 'BIN-002',
  title: 'File content does not match its extension',
  category: 'BIN',
  severity: 'critical',
  advice:
    'A file named like an image, font or document actually contains a program or script. Attackers use this to hide payloads that another file then runs. Do not open or run anything in this repository.',
  appliesTo: (f) => MEDIA_EXT.has(f.ext),
  check(f) {
    const magic = detectMagic(f.head);
    const out: RawFinding[] = [];
    if (magic === 'pe' || magic === 'elf' || magic === 'macho') {
      const kind = magic === 'pe' ? 'a Windows executable' : magic === 'elf' ? 'a Linux executable' : 'a macOS executable';
      out.push({ message: `.${f.ext} file is actually ${kind}`, evidence: `${f.path} (${magic.toUpperCase()} header)` });
    } else if (f.text !== undefined && looksLikeScript(f.text)) {
      const firstCode = f.lines().find((l) => l.trim().length > 0) ?? '';
      out.push({ line: 1, message: `.${f.ext} file contains script code`, evidence: sanitizeEvidence(firstCode) });
    }
    return out;
  },
};

const NTLM_LEAK_EXT = new Set(['url', 'scf', 'library-ms', 'searchconnector-ms']);
const REMOTE_PATH: RegExp[] = [
  /\\\\(?!\?\\|\.\\)[A-Za-z0-9._-]+(?:@SSL)?(?:@\d+)?\\/, // UNC path \\host\share
  /\bfile:\/\/(?!\/|localhost\b)[^\s"'<>]+/i, // file://host/share
  /<url>\s*(?:https?:\/\/|\\\\)[^<]+<\/url>/i, // library-ms / searchConnector-ms locations
  /\bIcon(?:File|Resource)\s*=\s*https?:\/\//i,
];

export const BIN_008: FileRule = {
  kind: 'file',
  id: 'BIN-008',
  title: 'Windows shortcut or folder file points to a remote location',
  category: 'BIN',
  severity: 'high',
  advice:
    'Windows contacts this remote server as soon as you browse the folder in Explorer, which can send your Windows login hash to an attacker. Do not open this folder in Windows Explorer.',
  appliesTo: (f) => f.text !== undefined && (NTLM_LEAK_EXT.has(f.ext) || f.base === 'desktop.ini'),
  check(f) {
    const lines = f.lines();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (REMOTE_PATH.some((r) => r.test(line))) {
        return [{ line: i + 1, evidence: sanitizeEvidence(line), message: `${f.base} references a remote path that Windows resolves automatically` }];
      }
    }
    return [];
  },
};

export const BIN_RULES: FileRule[] = [BIN_002, BIN_008];
