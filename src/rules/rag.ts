import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const ragRules: Rule[] = [
  {
    id: 'RAG-001',
    title: 'Retrieved content injected as system-role message',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never assign retrieved or external content to role: "system". Use role: "tool" or role: "user" and label it as untrusted context with clear delimiters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Detect role: "system" assignments
      const systemRolePattern = /role\s*:\s*['"`]system['"`]/i;
      // Detect content: someVariable (not a string literal — negative lookahead on quote/digit)
      const contentVarPattern = /content\s*:\s*(?!['"`\d])\s*[a-zA-Z_$][a-zA-Z0-9_$.[\]]*/i;

      lines.forEach((line, i) => {
        if (!systemRolePattern.test(line)) return;
        // Check the same line and the next 3 lines for a variable content value
        const windowEnd = Math.min(i + 4, lines.length);
        const window = lines.slice(i, windowEnd).join('\n');
        if (contentVarPattern.test(window)) {
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
    id: 'RAG-002',
    title: 'Instruction-like phrases in document ingestion pipeline',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Filter instruction-like strings from documents at ingestion time, before they are stored or embedded. Use a phrase denylist and strip or reject documents that match.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const text = prompt.text;

      // Require evidence of a document iteration loop
      const ingestionPattern =
        /(?:\.(?:forEach|map|filter|reduce)\s*\(\s*(?:async\s+)?\(?(?:doc|chunk|passage|item|record|text)\b|for\s+(?:const|let|var)\s+\w+\s+of\s+\w*(?:docs?|chunks?|documents?|passages?|texts?|items?)\w*)/i;

      if (!ingestionPattern.test(text)) return [];

      // Look for corpus-poisoning instruction markers inside the loop body
      const poisonPattern =
        /(?:system\s*prompt\s*:|always\s+return|never\s+redact|debug\s+mode\s*[=:]\s*true|confidential\s+instructions?\s*:|override\s+(?:system|instructions?|constraints?)|ignore\s+(?:previous|all)\s+(?:instructions?|rules?|constraints?))/i;

      const lines = text.split('\n');
      lines.forEach((line, i) => {
        if (poisonPattern.test(line)) {
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
