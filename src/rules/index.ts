import type { Rule } from './types.js';
import { injectionRules } from './injection.js';
import { exfiltrationRules } from './exfiltration.js';
import { jailbreakRules } from './jailbreak.js';
import { unsafeToolsRules } from './unsafeTools.js';

export const allRules: Rule[] = [
  ...injectionRules,
  ...exfiltrationRules,
  ...jailbreakRules,
  ...unsafeToolsRules,
];

export { injectionRules, exfiltrationRules, jailbreakRules, unsafeToolsRules };
export type { Rule, RuleMatch } from './types.js';
export { calcRiskPoints, ruleToFinding } from './types.js';
export { scoreMitigations } from './mitigation.js';
