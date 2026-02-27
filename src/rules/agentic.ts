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

export const agenticRules: Rule[] = [
  {
    id: 'AGT-001',
    title: 'Tool call parameter receives system-prompt content',
    severity: 'critical',
    confidence: 'high',
    category: 'agentic',
    remediation:
      'Never pass raw system-prompt or instructions fields as tool call arguments. Sanitise and bound the data before it reaches any tool parameter, and validate tool inputs against a strict schema.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Detect tool_call/function_call argument values that reference system: or instructions: content
      const pattern =
        /(?:tool_call|function_call)\s*[({].*?(?:["'](?:system|instructions?)["']\s*:\s*|arguments?\s*:\s*["'][^"']*(?:system|instructions?))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-002',
    title: 'Agent loop with no iteration or timeout guard',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Add a finite bound on agent loops: set max_iterations, max_steps, max_turns, timeout, or recursion_limit in your agent config or system prompt to prevent unbounded execution.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      // Applies to code-block kind in files containing an agent loop pattern
      if (prompt.kind !== 'code-block') return [];

      const guardPattern =
        /(?:max_iterations|max_steps|max_turns|timeout|recursion_limit)\s*[=:]/i;
      const loopPattern =
        /(?:while\s*(?:True|true|\(true\))|agent\.run\s*\(|AgentExecutor|\.invoke\s*\(|run_until_done|agent_loop)/i;

      if (!loopPattern.test(prompt.text)) return [];
      if (guardPattern.test(prompt.text)) return [];

      // Return a match at the first loop keyword location
      const lines = prompt.text.split('\n');
      const results: RuleMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (loopPattern.test(lines[i])) {
          results.push({
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          break; // one finding per file is enough
        }
      }
      void filePath;
      return results;
    },
  },
  {
    id: 'AGT-003',
    title: 'Agent memory written from unvalidated LLM output',
    severity: 'high',
    confidence: 'high',
    category: 'agentic',
    remediation:
      'Validate and sanitise LLM output before writing to agent memory or vector stores. Never pass raw model responses directly to memory.save(), memory.add(), or vectorstore.upsert() without schema validation.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      // Memory write calls with an argument that looks like an LLM output variable
      const pattern =
        /(?:memory\.(?:save|add|append)|vectorstore\.upsert|vector_store\.upsert|memory_store\.(?:set|add|write))\s*\(\s*(?:response|output|result|completion|llm_output|model_output|answer|generated)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-004',
    title: 'Plan injection — user input interpolated into agent planning prompt',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Wrap user input in a trust-boundary delimiter before including it in agent planning prompts. Use a structured object field (not string concatenation) and label user content as untrusted data, not instructions.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // User input interpolated into planning/task/goal/objective strings
      const pattern =
        /(?:plan|task|goal|objective|agent_instructions?)\s*[=+:]\s*[`"']?[^`"'\n]*\$\{?\s*(?:user(?:Input|Query|Message|Request)|request|query|input)\s*\}?/i;
      return matchPattern(prompt, pattern);
    },
  },
];
