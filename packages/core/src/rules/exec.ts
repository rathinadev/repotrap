import { decodeXmlEntities, lineAt, parseJsonc, sanitizeEvidence } from '../text.ts';
import { extractPathRefs, suspiciousCommand } from '../patterns.ts';
import type { FileRule, RawFinding } from '../types.ts';

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Flattens a VS Code task's command and args (including per-OS overrides) into one string. */
function taskCommandText(task: Json): string {
  const parts: string[] = [];
  const add = (v: unknown): void => {
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) v.forEach(add);
    else if (isObj(v) && typeof v.value === 'string') parts.push(v.value);
  };
  const addSpec = (spec: unknown): void => {
    if (!isObj(spec)) return;
    add(spec.command);
    add(spec.args);
  };
  addSpec(task);
  for (const os of ['windows', 'linux', 'osx']) addSpec(task[os]);
  return parts.join(' ');
}

function nthLineMatching(lines: string[], re: RegExp, n: number): number | undefined {
  let seen = 0;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i] ?? '') && seen++ === n) return i + 1;
  }
  return undefined;
}

const FOLDER_OPEN_RE = /"runOn"\s*:\s*"folderOpen"/;

export const EXEC_001: FileRule = {
  kind: 'file',
  id: 'EXEC-001',
  title: 'Task runs automatically when the folder is opened',
  category: 'EXEC',
  severity: 'high',
  advice:
    'Do not open this folder in VS Code or a VS Code-based editor. Read .vscode/tasks.json first: this task runs as soon as the workspace is trusted, without any further click.',
  appliesTo: (f) => f.text !== undefined && (/(^|\/)\.vscode\/tasks\.json$/.test(f.lower) || f.ext === 'code-workspace'),
  check(f) {
    const text = f.text ?? '';
    const lines = f.lines();
    const json = parseJsonc(text);
    const tasks = isObj(json) ? (f.ext === 'code-workspace' ? (isObj(json.tasks) ? json.tasks.tasks : undefined) : json.tasks) : undefined;

    if (!Array.isArray(tasks)) {
      // Unparseable or unusual file: fall back to the raw marker so malformed JSON can't hide a task.
      const out: RawFinding[] = [];
      lines.forEach((l, i) => {
        if (FOLDER_OPEN_RE.test(l)) {
          out.push({ line: i + 1, evidence: sanitizeEvidence(l), message: 'A task is set to run on folder open (file could not be fully parsed)' });
        }
      });
      return out;
    }

    const out: RawFinding[] = [];
    let occurrence = 0;
    for (const task of tasks) {
      if (!isObj(task) || !isObj(task.runOptions) || task.runOptions.runOn !== 'folderOpen') continue;
      const cmd = taskCommandText(task);
      const reasons = suspiciousCommand(cmd);
      const label = typeof task.label === 'string' ? task.label : '(unnamed)';
      out.push({
        severity: reasons.length > 0 ? 'critical' : 'high',
        line: nthLineMatching(lines, FOLDER_OPEN_RE, occurrence++),
        evidence: sanitizeEvidence(cmd || label),
        message:
          `Task "${sanitizeEvidence(label, 60)}" runs automatically when the folder is opened` +
          (reasons.length > 0 ? `; it ${reasons.join(', ')}` : ''),
        refs: extractPathRefs(cmd),
      });
    }
    return out;
  },
};

const DEVCONTAINER_RE = /(^|\/)\.devcontainer(\/[^/]+)?\/devcontainer\.json$|(^|\/)\.devcontainer\.json$/;

export const EXEC_002: FileRule = {
  kind: 'file',
  id: 'EXEC-002',
  title: 'Devcontainer runs a command on your machine before the container starts',
  category: 'EXEC',
  severity: 'high',
  advice:
    'initializeCommand runs on your own computer, not inside the container, when you open the folder in a container. Read the command before using "Reopen in Container".',
  appliesTo: (f) => f.text !== undefined && DEVCONTAINER_RE.test(f.lower),
  check(f) {
    const json = parseJsonc(f.text ?? '');
    const lines = f.lines();
    const line = nthLineMatching(lines, /"initializeCommand"\s*:/, 0);
    if (!isObj(json)) {
      return line === undefined
        ? []
        : [{ line, evidence: sanitizeEvidence(lines[line - 1] ?? ''), message: 'initializeCommand present (file could not be fully parsed)' }];
    }
    const ic = json.initializeCommand;
    if (ic === undefined) return [];
    const cmd = typeof ic === 'string' ? ic : Array.isArray(ic) ? ic.join(' ') : isObj(ic) ? Object.values(ic).flat().join(' ') : '';
    const reasons = suspiciousCommand(cmd);
    return [
      {
        severity: reasons.length > 0 ? 'critical' : 'high',
        line,
        evidence: sanitizeEvidence(cmd),
        message: 'initializeCommand runs on the host machine' + (reasons.length > 0 ? `; it ${reasons.join(', ')}` : ''),
        refs: extractPathRefs(cmd),
      },
    ];
  },
};

const MSBUILD_EXT = new Set(['csproj', 'vcxproj', 'vbproj', 'fsproj', 'props', 'targets', 'proj']);
const BUILD_EVENT_RE = /<(PreBuildEvent|PostBuildEvent|PreLinkEvent)>([\s\S]*?)<\/\1>/gi;
const EXEC_TASK_RE = /<Exec\b[^>]*?\bCommand\s*=\s*"([^"]*)"/gi;

export const EXEC_004: FileRule = {
  kind: 'file',
  id: 'EXEC-004',
  title: 'Build event or Exec task runs a command when the project is built',
  category: 'EXEC',
  severity: 'medium',
  advice:
    'Building this project in Visual Studio or with dotnet/msbuild runs this command. Read it before building; legitimate projects use build events too, so focus on what the command does.',
  appliesTo: (f) => f.text !== undefined && MSBUILD_EXT.has(f.ext),
  check(f) {
    const text = f.text ?? '';
    const out: RawFinding[] = [];
    const add = (index: number, raw: string, what: string): void => {
      const cmd = decodeXmlEntities(raw).trim();
      if (cmd.length === 0) return;
      const reasons = suspiciousCommand(cmd);
      out.push({
        severity: reasons.length > 0 ? 'critical' : 'medium',
        line: lineAt(text, index),
        evidence: sanitizeEvidence(cmd),
        message: `${what} runs a command at build time` + (reasons.length > 0 ? `; it ${reasons.join(', ')}` : ''),
        refs: extractPathRefs(cmd),
      });
    };
    for (const m of text.matchAll(BUILD_EVENT_RE)) add(m.index, m[2] ?? '', m[1] ?? 'Build event');
    for (const m of text.matchAll(EXEC_TASK_RE)) add(m.index, m[1] ?? '', 'Exec task');
    return out;
  },
};

export const EXEC_RULES: FileRule[] = [EXEC_001, EXEC_002, EXEC_004];
