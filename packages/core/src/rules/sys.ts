import { scanLines } from './obf.ts';
import type { FileRule } from '../types.ts';

const DISABLE_SECURITY: RegExp[] = [
  /\bSet-MpPreference\b[^\n]*-(?:DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableArchiveScanning)\s+(?:\$true|1|true)\b/i,
  /\bAdd-MpPreference\b[^\n]*-Exclusion(?:Path|Process|Extension|IpAddress)\b/i,
  /\breg(?:\.exe)?\s+add\b[^\n]*Windows\s+Defender[^\n]*Disable/i,
  /\bsc(?:\.exe)?\s+(?:stop|config)\s+WinDefend\b/i,
  /\bnetsh\s+(?:advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable)/i,
  /\bspctl\s+--master-disable\b/,
  /\bxattr\s+(?:-r\s+)?-d\s+com\.apple\.quarantine\b/,
  /\bsetenforce\s+0\b/,
  /\bufw\s+disable\b/,
];

export const SYS_004: FileRule = {
  kind: 'file',
  id: 'SYS-004',
  title: 'Turns off security protections',
  category: 'SYS',
  severity: 'high',
  advice:
    'This code switches off antivirus, Gatekeeper, SELinux or the firewall, or excludes files from scanning. A normal project almost never needs to do that. Do not run it.',
  appliesTo: (f) => f.text !== undefined && !f.isDoc && !f.isData,
  check: (f) => scanLines(f, DISABLE_SECURITY, 'Security protection is disabled or bypassed'),
};

export const SYS_RULES: FileRule[] = [SYS_004];
