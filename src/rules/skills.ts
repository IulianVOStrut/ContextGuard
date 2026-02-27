import path from 'path';
import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

/**
 * Returns true when the file is an OpenClaw skill file — either a SKILL.md
 * directly or any markdown file inside a skills/ or .openclaw/ directory tree.
 */
function isSkillFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  const norm = filePath.replace(/\\/g, '/').toLowerCase();
  return (
    base === 'skill.md' ||
    norm.includes('/skills/') ||
    norm.includes('.openclaw') ||
    norm.includes('clawhub')
  );
}

export const skillsRules: Rule[] = [
  {
    id: 'SKL-001',
    title: 'Skill instructs agent to write or modify skill files (self-authoring attack)',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skill files must never instruct the agent to create, write, or modify other SKILL.md files. Self-authoring gives a compromised skill persistence across sessions and reboots. Audit the skill body and remove any instructions referencing skill file creation or modification.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const WRITE_SKILL_PATTERN =
        /(?:write|create|save|generate|update|modify|overwrite)\s+(?:a\s+)?(?:new\s+)?(?:skill|SKILL\.md)|SKILL\.md.*(?:write|create|save|modify)|(?:add|save|write)\s+(?:this|the|a)\s+(?:new\s+)?skill\s+(?:file|to\b)/i;
      lines.forEach((line, i) => {
        if (WRITE_SKILL_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-002',
    title: 'Skill instructs agent to fetch or load skills from an external URL',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never load content from remote URLs at runtime. Remote skill loading allows an attacker to change skill behavior after installation by updating the remote file. Only use skills with static, locally stored SKILL.md files from trusted, pinned sources.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const REMOTE_LOAD_PATTERN =
        /(?:fetch|download|load|import|curl|wget|get)\s+(?:(?:the\s+)?skill|skills|SKILL\.md)\s+from\s+(?:https?:\/\/|github\.com|raw\.github|clawhub)|https?:\/\/[^\s]+SKILL\.md|extraDirs['":\s]+https?:\/\//i;
      lines.forEach((line, i) => {
        if (REMOTE_LOAD_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-003',
    title: 'Prompt injection in skill body targeting agent core instructions',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'This skill contains instruction-override phrases designed to hijack the agent\'s core identity or safety rules. This is an active prompt injection attack embedded in a skill. Remove or quarantine this skill immediately and audit your full skills directory for similar payloads.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const INJECTION_PATTERN =
        /ignore\s+(?:all\s+)?(?:previous|above|prior|your)\s+instructions?|disregard\s+(?:your\s+)?(?:system\s+prompt|instructions?|rules?|guidelines?|identity)|forget\s+(?:everything|all|your)\s+(?:above|before|prior|training)|you\s+are\s+now\s+(?:a\s+)?(?:different|new|another|unrestricted|unconstrained|jailbroken|free|DAN)\b|new\s+instructions?\s+override|override\s+(?:all\s+)?(?:previous|system|core)\s+instructions?/i;
      lines.forEach((line, i) => {
        if (INJECTION_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-004',
    title: 'Skill frontmatter uses command-dispatch: tool with raw argument mode',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'command-dispatch: tool combined with command-arg-mode: raw forwards unvalidated user input directly to a tool, bypassing all model safety reasoning. Ensure command-tool is scoped to a sandboxed, minimal-privilege tool, and validate or sanitise arguments before dispatch.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const CMD_DISPATCH_PATTERN = /command-dispatch\s*:\s*tool\b/i;
      const RAW_ARG_PATTERN = /command-arg-mode\s*:\s*raw\b/i;
      const hasDispatch = CMD_DISPATCH_PATTERN.test(prompt.text);
      const hasRawArg = RAW_ARG_PATTERN.test(prompt.text);
      if (hasDispatch) {
        lines.forEach((line, i) => {
          if (CMD_DISPATCH_PATTERN.test(line) || (hasRawArg && RAW_ARG_PATTERN.test(line))) {
            results.push({
              evidence: line.trim(),
              lineStart: prompt.lineStart + i,
              lineEnd: prompt.lineStart + i,
            });
          }
        });
      }
      return results;
    },
  },

  {
    id: 'SKL-005',
    title: 'Skill body instructs agent to access sensitive filesystem paths',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'This skill contains instructions to access sensitive files or directories (~/.ssh, ~/.env, /etc/passwd, etc.), which is a data exfiltration attack pattern. Remove the skill immediately and audit your agent workspace for additional malicious skills.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const SENSITIVE_PATH_PATTERN =
        /~\/\.(?:ssh|env|aws|config|gnupg|netrc|bash_history|zsh_history|npmrc|pypirc|docker)\b|\/etc\/(?:passwd|shadow|hosts|sudoers|crontab)\b|\.\.[/\\]\.\.[/\\]|(?:read|open|cat|get|fetch|access|load)\s+(?:the\s+)?(?:file\s+at\s+)?~\/\.(?:ssh|env|aws)/i;
      lines.forEach((line, i) => {
        if (SENSITIVE_PATH_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-006',
    title: 'Skill claims elevated privileges or instructs agent to bypass other skills',
    severity: 'high',
    confidence: 'medium',
    category: 'skills',
    remediation:
      'Skills must not claim system-level authority or attempt to override other skills\' behaviour. No skill has inherent authority over other installed skills; trust hierarchy is determined by workspace configuration only. Treat this skill as potentially malicious and remove it.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const PRIV_ESC_PATTERN =
        /(?:override|disable|bypass|ignore|supersede)\s+(?:all\s+)?(?:other\s+)?(?:skills?|restrictions?|safety\s+rules?|guardrails?)\b|this\s+skill\s+(?:has|grants?|gives?)\s+(?:elevated|full|unrestricted|admin|root|system)\s+(?:access|permissions?|privileges?)|you\s+(?:now\s+)?have\s+(?:full|unrestricted|elevated|root|admin)\s+(?:access|permissions?|control)\s+over/i;
      lines.forEach((line, i) => {
        if (PRIV_ESC_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-007',
    title: 'Hardcoded credential value in YAML frontmatter field',
    severity: 'critical',
    confidence: 'medium',
    category: 'skills',
    remediation:
      'API keys, tokens, and secrets must never be hardcoded in SKILL.md frontmatter. Skills published to ClawHub or any shared directory will expose these credentials publicly. Use environment variable references (e.g. $MY_API_KEY) or per-agent config blocks in your agent configuration file instead.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const YAML_CRED_KEY_PATTERN =
        /^\s*(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|api[_-]?token|password|bearer|private[_-]?key|client[_-]?secret)\s*:/i;
      const YAML_CRED_VALUE_PATTERN =
        /:\s*['"]?(?!\s*$)(?!\$\{)(?!\$[A-Z_])(?!\{\{)[a-zA-Z0-9+/=\-_]{16,}['"]?\s*$/;

      // Only inspect lines inside the YAML frontmatter block (between --- delimiters)
      let inFrontmatter = false;
      let frontmatterClosed = false;
      lines.forEach((line, i) => {
        if (i === 0 && line.trim() === '---') { inFrontmatter = true; return; }
        if (inFrontmatter && !frontmatterClosed && line.trim() === '---') {
          frontmatterClosed = true;
          return;
        }
        if (!inFrontmatter || frontmatterClosed) return;
        if (YAML_CRED_KEY_PATTERN.test(line) && YAML_CRED_VALUE_PATTERN.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },
];
