import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

function matchPattern(prompt: ExtractedPrompt, pattern: RegExp): RuleMatch[] {
  const results: RuleMatch[] = [];
  const lines = prompt.text.split('\n');
  lines.forEach((line, i) => {
    if (pattern.test(line)) {
      results.push({
        evidence: line.trim(),
        lineStart: prompt.lineStart + i,
        lineEnd: prompt.lineStart + i,
      });
    }
  });
  return results;
}

export const commandInjectionRules: Rule[] = [
  {
    id: 'CMD-001',
    title: 'Shell command constructed with unsanitised variable interpolation',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never interpolate variables directly into shell command strings. Use an array-based spawn API (e.g. child_process.spawn with an args array) so the shell never sees the variable as part of the command string.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const execPattern = /(?:execSync|exec|execFile|spawnSync)\s*\(/i;
      const templateVarPattern = /`[^`]*\$\{[^}]+\}[^`]*`/;

      lines.forEach((line, i) => {
        // Case 1: exec call with template literal variable on the same line.
        if (execPattern.test(line) && templateVarPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        // Case 2: exec call where a variable assigned from a template literal
        // appears in the preceding 5 lines (assign-then-use pattern).
        if (execPattern.test(line)) {
          const lookback = lines.slice(Math.max(0, i - 5), i).join('\n');
          // Find variables assigned from template literals with interpolation
          const assignMatch = /(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{[^}]+\}/g;
          let m: RegExpExecArray | null;
          while ((m = assignMatch.exec(lookback)) !== null) {
            const varName = m[1];
            if (new RegExp(`\\b${varName}\\b`).test(line)) {
              results.push({
                evidence: line.trim(),
                lineStart: prompt.lineStart + i,
                lineEnd: prompt.lineStart + i,
              });
              break;
            }
          }
        }
      });

      return results;
    },
  },
  {
    id: 'CMD-002',
    title: 'Incomplete command substitution filtering — backtick bypass possible',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Block all forms of command substitution: $(), backticks, and ${ } in the same validation. Prefer an allowlist of safe command patterns over a denylist of dangerous ones.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const text = prompt.text;

      // Detect code that checks for $() substitution but not backticks, or vice versa.
      // Pattern: includes('$(') or includes("$(") present but no backtick check nearby,
      // or includes('`') check present but no $() check nearby.
      const blocksDollarParen =
        /includes\s*\(\s*['"`]\$\(\s*['"`]\s*\)/.test(text) ||
        /indexOf\s*\(\s*['"`]\$\(\s*['"`]/.test(text);

      const blocksBacktick =
        /includes\s*\(\s*['"`]`['"`]\s*\)/.test(text) ||
        /indexOf\s*\(\s*['"`]`['"`]/.test(text);

      if (blocksDollarParen && !blocksBacktick) {
        results.push({
          evidence: 'Filters $() command substitution but not backtick substitution',
          lineStart: prompt.lineStart,
          lineEnd: prompt.lineEnd,
        });
      } else if (blocksBacktick && !blocksDollarParen) {
        results.push({
          evidence: 'Filters backtick command substitution but not $() substitution',
          lineStart: prompt.lineStart,
          lineEnd: prompt.lineEnd,
        });
      }

      return results;
    },
  },
  {
    id: 'CMD-003',
    title: 'File path from glob or directory listing used in shell command',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Sanitise or validate file paths before using them in shell commands. Use shell-quote or shlex to escape arguments, or pass paths as array arguments to spawn() to avoid shell interpretation entirely.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Track all variables assigned from glob/readdir anywhere in the snippet.
      const globResultVars = new Set<string>();
      const globAssignPattern =
        /(?:const|let|var)\s+(\w+)\s*=\s*(?:glob\.sync|globSync|fs\.readdirSync|readdirSync|fg\.sync|globby\.sync)\s*\(/i;
      // Also track variables derived from those (e.g. const vsixPath = files[0])
      const derivedAssignPattern =
        /(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*(?:\[|\.)/;

      lines.forEach((line) => {
        const gm = globAssignPattern.exec(line);
        if (gm) globResultVars.add(gm[1]);
      });

      // Second pass: collect derived variables
      lines.forEach((line) => {
        const dm = derivedAssignPattern.exec(line);
        if (dm && globResultVars.has(dm[2])) {
          globResultVars.add(dm[1]);
        }
      });

      // Third pass: find exec calls that use any glob-derived variable
      const execPattern = /(?:execSync|exec|execFile|spawnSync)\s*\(/i;
      lines.forEach((line, i) => {
        if (!execPattern.test(line)) return;
        for (const varName of globResultVars) {
          // Variable appears in the exec call as template interpolation or concatenation
          if (
            new RegExp(`\\$\\{\\s*${varName}\\s*\\}`).test(line) ||
            new RegExp(`["'\`]\\s*\\+\\s*${varName}`).test(line)
          ) {
            results.push({
              evidence: line.trim(),
              lineStart: prompt.lineStart + i,
              lineEnd: prompt.lineStart + i,
            });
            break;
          }
        }
      });

      return results;
    },
  },
];
