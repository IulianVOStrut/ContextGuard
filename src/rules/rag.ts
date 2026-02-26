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
  {
    id: 'RAG-003',
    title: 'Agent memory written directly from user-controlled input',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Validate and sanitize all data before writing to memory stores. Store only structured, explicit facts (name, locale); never store free-form instructions or raw message content. Require user confirmation before persisting preferences.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Memory store write calls
      const memoryWritePattern =
        /(?:memory\s*(?:\??\.)?\s*(?:add|set|store|save|push|append)\s*\(|saveMemory\s*\(|storeMemory\s*\(|addMemory\s*\(|conversationStore\s*(?:\??\.)?\s*(?:set|add)\s*\(|memoryStore\s*(?:\??\.)?\s*(?:add|set)\s*\(|\.remember\s*\()/i;
      // User-controlled input sources on the same line
      const userInputPattern =
        /(?:req\.body|req\.query|req\.params|request\.body|ctx\.body|ctx\.request\.body|userInput|userMessage)\b/i;

      lines.forEach((line, i) => {
        if (memoryWritePattern.test(line) && userInputPattern.test(line)) {
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
    id: 'RAG-004',
    title: 'Prompt instructs model to treat retrieved context as highest priority',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Explicitly state that retrieved context is untrusted data and must not override developer instructions. Retrieved content should inform — not direct — model behavior.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:(?:retrieved|context|documents?|knowledge\s+base|search\s+results?).{0,60}(?:highest\s+priority|overrides?|takes?\s+precedence|more\s+important\s+than|supersedes?|always\s+follow|must\s+follow)|(?:always|must|strictly)\s+follow\s+(?:the\s+)?(?:retrieved|context|documents?|knowledge\s+base|search\s+results?))/i;
      return matchPattern(prompt, pattern);
    },
  },
];

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
