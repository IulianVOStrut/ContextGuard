import path from 'path';
import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const outputHandlingRules: Rule[] = [
  {
    id: 'OUT-001',
    title: 'LLM JSON output parsed without schema validation',
    severity: 'critical',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Always validate JSON parsed from LLM output using a schema library (Zod, AJV, Joi, Yup) before accessing properties or driving application logic. Never trust the model to conform to the requested schema.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Only analyse code-block extractions (full file context needed to check
      // for the presence or absence of a schema validator in the same file).
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // JSON.parse / json.loads called on a variable whose name suggests LLM output
      const llmOutputNames =
        /(?:content|message|output|completion|response|result|text|body|answer|reply)\b/i;
      const jsonParsePattern =
        /JSON\.parse\s*\(\s*(?!['"`{\[]|\d)\s*[a-zA-Z_$][a-zA-Z0-9_$.[\]'"]*\s*[)]/i;
      // Python json.loads with a variable argument
      const pyJsonLoadPattern =
        /json\.loads\s*\(\s*(?!['"`{\[]|\d)\s*[a-z_][a-z0-9_$.[\]'"]*\s*[)]/i;

      // Presence of a schema validation library in the file.
      // (?<!JSON)\.parse avoids matching JSON.parse — we want Zod/AJV .parse() only.
      const schemaValidatorPattern =
        /(?:(?<!JSON)\.parse\s*\(|\.safeParse\s*\(|\.validate\s*\(|ajv\b|new\s+Ajv|Joi\s*\.|z\s*\.\s*(?:object|string|number|array|boolean|enum|union|infer)\b|yup\s*\.)/i;
      // Python schema validators
      const pyValidatorPattern =
        /(?:pydantic|marshmallow|cerberus|voluptuous|jsonschema\.validate|TypeAdapter)/i;

      const hasValidator = schemaValidatorPattern.test(text) || pyValidatorPattern.test(text);
      if (hasValidator) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      lines.forEach((line, i) => {
        const isJsonParse = jsonParsePattern.test(line) || pyJsonLoadPattern.test(line);
        if (!isJsonParse) return;
        // Confirm the argument looks like LLM output (by variable name)
        if (!llmOutputNames.test(line)) return;
        results.push({
          evidence: line.trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      });

      return results;
    },
  },
  {
    id: 'OUT-002',
    title: 'LLM output rendered via Markdown or HTML without sanitization',
    severity: 'critical',
    confidence: 'medium',
    category: 'exfiltration',
    remediation:
      'Pipe all LLM-generated Markdown or HTML through DOMPurify (or equivalent) before rendering. Configure it to strip remote image sources and script tags to prevent data exfiltration via injected tracking pixels.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Markdown/HTML rendering calls
      const mdRenderPattern =
        /(?:marked\s*[.(]|marked\.parse\s*\(|markdownIt\s*[.(]|new\s+MarkdownIt|showdown|micromark\s*\(|dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:)/i;

      if (!mdRenderPattern.test(text)) return [];

      // Presence of a sanitizer in the same file
      const sanitizerPattern = /(?:DOMPurify|dompurify|sanitize\s*\(|createDOMPurify)/i;
      if (sanitizerPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      lines.forEach((line, i) => {
        if (!mdRenderPattern.test(line)) return;
        // Only flag when the argument is a variable (not a string literal)
        const afterCall = line.replace(mdRenderPattern, '');
        if (/^\s*['"`]/.test(afterCall)) return;
        results.push({
          evidence: line.trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      });

      return results;
    },
  },
  {
    id: 'OUT-003',
    title: 'LLM output used directly in exec(), eval(), or database query',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never execute LLM output as code or SQL. Parse the response into a strict schema first, then use parameterised queries or a dedicated command parser. Treat all model output as untrusted user input.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Dangerous execution sinks
      const execSinkPattern =
        /(?:\beval\s*\(|new\s+Function\s*\(|(?:exec|execSync|execFile)\s*\(|db\s*(?:\??\.)?\s*(?:query|execute|run)\s*\(|connection\s*(?:\??\.)?\s*query\s*\(|pool\s*(?:\??\.)?\s*query\s*\()/i;
      // Variable names that suggest LLM output as the argument
      const llmOutputArgPattern =
        /(?:llm|ai|gpt|claude|model|completion|response|output|result|answer|generated|message\.content|choices\[)/i;

      lines.forEach((line, i) => {
        if (execSinkPattern.test(line) && llmOutputArgPattern.test(line)) {
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
    id: 'OUT-004',
    title: 'Python eval() or exec() called with LLM-generated output',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never pass LLM-generated output to eval() or exec() in Python. Parse the response into a validated schema (e.g. Pydantic) first, then execute only predefined, constrained operations. Treat all model output as untrusted user input.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const ext = path.extname(filePath).toLowerCase();
      if (ext !== '.py') return [];

      const execSinkPattern = /\b(?:eval|exec)\s*\(/i;
      const llmOutputArgPattern =
        /(?:llm|ai|gpt|claude|model|completion|response|output|result|answer|generated|message\.content|choices\[)/i;

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      lines.forEach((line, i) => {
        if (execSinkPattern.test(line) && llmOutputArgPattern.test(line)) {
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
