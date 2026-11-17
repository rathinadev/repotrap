import { sanitizeEvidence } from '../text.ts';
import { NETWORK_RE } from '../patterns.ts';
import type { FileRule } from '../types.ts';

// Spaces are written as \x20 and IDs are split so this file never matches itself.
const CREDENTIAL_MARKERS: { name: string; re: RegExp }[] = [
  { name: 'browser saved passwords', re: /Login\x20Data\b|logins\.json\b|key[34]\.db\b/ },
  { name: 'browser encryption key', re: /Local\x20State\b/ },
  { name: 'browser autofill/cards', re: /Web\x20Data\b/ },
  { name: 'browser cookies', re: /[\\/]Cookies\b|cookies\.sqlite\b/ },
  { name: 'SSH private keys', re: /\.ssh[\\/]+id_(?:rsa|ed25519|ecdsa|dsa)\b/ },
  { name: 'AWS credentials', re: /\.aws[\\/]+credentials\b/ },
  { name: 'macOS keychain', re: /login\.keychain(?:-db)?\b|security\s+find-generic-password/ },
  { name: 'crypto wallet files', re: /wallet\.dat\b|Electrum[\\/]+wallets|Exodus[\\/]+exodus\.wallet|Local\x20Extension\x20Settings/ },
  {
    name: 'crypto wallet extensions',
    re: new RegExp(
      [
        'nkbihfbeog' + 'aeaoehlefnkodbefgpgknn', // MetaMask
        'bfnaelmome' + 'imhlpmgjnjophhpkkoljpa', // Phantom
        'hnfanknocf' + 'eofbddgcijnmhnfnkdnaad', // Coinbase Wallet
        'ibnejdfjmm' + 'kpcnlpebklmnkoeoihofec', // TronLink
        'fhbohimael' + 'bohpjbbldcngcnapndodjp', // Binance Wallet
      ].join('|'),
    ),
  },
];

export const STEAL_001: FileRule = {
  kind: 'file',
  id: 'STEAL-001',
  title: 'Reads stored credentials and sends data over the network',
  category: 'STEAL',
  severity: 'high',
  advice:
    'This file looks for saved passwords, keys or wallets and also makes network requests, which is how information stealers work. Do not run it on a machine with real credentials.',
  appliesTo: (f) => f.text !== undefined && !f.isDoc && !f.isData,
  check(f) {
    const text = f.text ?? '';
    if (!NETWORK_RE.test(text)) return [];
    const found: string[] = [];
    let firstIdx = -1;
    for (const m of CREDENTIAL_MARKERS) {
      const idx = text.search(m.re);
      if (idx >= 0) {
        found.push(m.name);
        if (firstIdx < 0 || idx < firstIdx) firstIdx = idx;
      }
    }
    const strong = found.includes('crypto wallet extensions') || found.includes('SSH private keys') || found.includes('AWS credentials');
    if (found.length < 2 && !strong) return [];
    const line = text.slice(0, firstIdx).split('\n').length;
    return [
      {
        line,
        evidence: sanitizeEvidence(f.lines()[line - 1] ?? ''),
        message: `Accesses ${found.join(', ')} in a file that also makes network requests`,
      },
    ];
  },
};

export const STEAL_RULES: FileRule[] = [STEAL_001];
