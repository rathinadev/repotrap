import { EXEC_RULES } from './exec.ts';
import { OBF_RULES } from './obf.ts';
import { NET_RULES } from './net.ts';
import { STEAL_RULES } from './steal.ts';
import { BIN_RULES } from './bin.ts';
import { SYS_RULES } from './sys.ts';
import { META_CORRELATION_RULES, META_FILE_RULES } from './meta.ts';
import { CHAIN_RULES } from './chain.ts';
import type { Rule } from '../types.ts';

/** The v1 launch set. File rules run first; correlation rules see their findings. */
export const ALL_RULES: readonly Rule[] = [
  ...EXEC_RULES,
  ...OBF_RULES,
  ...NET_RULES,
  ...STEAL_RULES,
  ...BIN_RULES,
  ...SYS_RULES,
  ...META_FILE_RULES,
  ...META_CORRELATION_RULES,
  ...CHAIN_RULES,
];
