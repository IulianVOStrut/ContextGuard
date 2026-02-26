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

export const jailbreakRules: Rule[] = [
  {
    id: 'JBK-001',
    title: 'Known jailbreak phrase detected',
    severity: 'critical',
    confidence: 'high',
    category: 'jailbreak',
    remediation: 'Remove jailbreak phrases from prompts. If testing robustness, use the attacks/ folder instead.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:ignore (all |previous |prior |above )?instructions?|developer mode|DAN[^a-z]|do anything now|jailbreak|pretend you (have no|are not|don't have)|act as if you have no (limits|restrictions?)|disregard (all |your |previous |the )?(?:instructions?|guidelines?|rules?|constraints?|policies?))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-002',
    title: 'Weak safety language that can be overridden',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    remediation: 'Replace weak directives ("always comply", "must answer") with bounded instructions that include explicit refusal conditions.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:always comply|must (always )?answer|no matter what|at all costs|under (any|all) circumstances|never (refuse|decline|say no)|you (cannot|can't|must not) (refuse|decline)|comply with (all|every|any) request)/i;
      const results = matchPattern(prompt, pattern);
      // Filter out false positives: "under any circumstances" in a safety/refusal context
      return results.filter(r => {
        const lower = r.evidence.toLowerCase();
        // "never ... under any circumstances" is a protective phrase, not a weakness
        if (/under (any|all) circumstances/.test(lower) &&
            /(?:never|do not|don't)\s.{0,60}under (any|all) circumstances/.test(lower)) {
          return false;
        }
        return true;
      });
    },
  },
  {
    id: 'JBK-003',
    title: 'Role-play escape hatch that undermines safety',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    remediation: 'If role-play is needed, explicitly state: "Even in role-play, you must not violate these guidelines."',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:pretend (you are|to be) (a|an) (?!assistant|helpful|AI).{0,40}(?:with no (limit|restriction|filter)|uncensored|unfiltered)|in this (scenario|story|game|simulation) you (can|may|are allowed to) (do|say|reveal) anything)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-004',
    title: 'Agent instructed to act without confirmation or human review',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    remediation:
      'Require explicit user confirmation for sensitive or irreversible actions. Remove language that disables human-in-the-loop review. Implement step-up authorisation for destructive tool calls.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:without\s+(?:asking|confirmation|user\s+approval|human\s+(?:review|approval|oversight))|no\s+(?:confirmation|approval|user\s+input)\s+(?:needed|required|necessary)|auto[-\s]?(?:run|execute|approve)\b|execute\s+immediately\b|don't\s+(?:ask|wait|pause|confirm)\b|proceed\s+automatically\b|take\s+action\s+(?:automatically|immediately|without\s+asking))/i;
      return matchPattern(prompt, pattern);
    },
  },
];
