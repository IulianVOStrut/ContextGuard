import type { Rule } from './types.js';
import { injectionRules } from './injection.js';
import { exfiltrationRules } from './exfiltration.js';
import { jailbreakRules } from './jailbreak.js';
import { unsafeToolsRules } from './unsafeTools.js';
import { commandInjectionRules } from './commandInjection.js';

export const allRules: Rule[] = [
  ...injectionRules,
  ...exfiltrationRules,
  ...jailbreakRules,
  ...unsafeToolsRules,
  ...commandInjectionRules,
];

export { injectionRules, exfiltrationRules, jailbreakRules, unsafeToolsRules, commandInjectionRules };
export type { Rule, RuleMatch } from './types.js';
export { calcRiskPoints, ruleToFinding } from './types.js';
export { scoreMitigations } from './mitigation.js';
