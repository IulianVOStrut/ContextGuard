import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const encodingRules: Rule[] = [
  {
    id: 'ENC-001',
    title: 'Base64 encoding of user-controlled variable near prompt construction',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Never use Base64 encoding to sanitise user input before inserting it into a prompt. LLMs can decode Base64 and may execute embedded instructions. Validate and delimit input as plaintext instead.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Skip plain-text files — Base64 API calls do not appear in raw prompts
      if (prompt.kind === 'raw') return [];

      // For full-file code-block extractions, require prompt-construction context
      // so we do not flag Base64 used in unrelated parts of the codebase.
      if (prompt.kind === 'code-block') {
        const hasPromptContext =
          /(?:messages\s*(?:\??\.)?\s*push|role\s*:\s*['"`](?:system|user)|systemPrompt\s*[=+]|\.prompt\s*[=+]|prompt\s*\+=)/i.test(
            prompt.text,
          );
        if (!hasPromptContext) return [];
      }

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // atob(variable) or btoa(variable) — argument is a variable, not a literal
      const base64VarPattern = /(?:atob|btoa)\s*\(\s*(?!['"`\d])\s*[a-zA-Z_$]/i;
      // Buffer.from(variable, 'base64') — decoding from base64 using a variable
      const bufferDecodePattern =
        /Buffer\.from\s*\(\s*(?!['"`\d])\s*[a-zA-Z_$][^,)]*,\s*['"]base64['"]/i;

      lines.forEach((line, i) => {
        if (base64VarPattern.test(line) || bufferDecodePattern.test(line)) {
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
    id: 'ENC-002',
    title: 'Hidden Unicode control characters detected in prompt asset',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Remove all invisible Unicode control characters (zero-width spaces, bidi overrides) from prompt source files. Add a Unicode normalization step to your ingestion pipeline and reject content containing unexpected control characters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Zero-width spaces, joiners, bidi overrides, and invisible formatting characters
      const hiddenUnicodePattern =
        /[\u200B-\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069\uFEFF]/;
      // Only flag when near instruction-like keywords to reduce false positives
      const instructionContextPattern =
        /(?:ignore|system|developer|tool|execute|override|instruction|forget|bypass|always|never)\b/i;

      lines.forEach((line, i) => {
        if (hiddenUnicodePattern.test(line) && instructionContextPattern.test(line)) {
          results.push({
            evidence: `[hidden Unicode] ${line.trim().replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '\u26AF')}`,
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });

      return results;
    },
  },
];
