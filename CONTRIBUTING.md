# Contributing to ContextHound

Thank you for your interest in contributing. This guide covers everything you need to get started.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold these standards. Report unacceptable behaviour to [abuse@ivos.pro](mailto:abuse@ivos.pro).

---

## Prerequisites

- Node.js 20 or higher
- npm 10 or higher

---

## Local Setup

```bash
git clone https://github.com/IulianVOStrut/ContextHound.git
cd ContextHound
npm install
npm run build
```

Run the scanner against a local directory to verify the build works:

```bash
node dist/cli.js scan --dir .
```

---

## Running Tests

```bash
# Run all tests once
npm test

# Watch mode
npm run test:watch
```

All 89 tests must pass before submitting a pull request.

---

## Project Structure

```
src/
├── cli.ts              # CLI entry point
├── types.ts            # Shared types
├── config/             # Config loading and defaults
├── scanner/            # File discovery and prompt extraction
├── rules/              # Security rules (one file per category)
├── scoring/            # Risk score calculation
└── report/             # Output formatters (console, JSON, SARIF)
tests/
├── fixtures/           # Sample files used as test inputs
├── rules.test.ts       # Unit tests for all rules
├── scoring.test.ts     # Unit tests for scoring
└── scanner.test.ts     # Integration tests
```

---

## Adding a New Rule

### 1. Choose the right file

Rules are grouped by category in `src/rules/`:

| File | Category | ID prefix |
|------|----------|-----------|
| `injection.ts` | Prompt injection | INJ |
| `exfiltration.ts` | Data/secret leakage | EXF |
| `jailbreak.ts` | Jailbreak phrases | JBK |
| `unsafeTools.ts` | Unsafe agentic tool use | TOOL |
| `commandInjection.ts` | Shell command injection | CMD |

If the new rule belongs to a new category, create a new file and register it in `src/rules/index.ts`.

### 2. Implement the Rule interface

```typescript
import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const myNewRule: Rule = {
  id: 'INJ-005',                   // next ID in category
  title: 'Short description',
  severity: 'high',                // low | medium | high | critical
  confidence: 'medium',            // low | medium | high
  category: 'injection',
  remediation: 'Actionable fix description shown to the user.',
  check(prompt: ExtractedPrompt, _filePath: string): RuleMatch[] {
    const results: RuleMatch[] = [];
    const lines = prompt.text.split('\n');
    lines.forEach((line, i) => {
      if (/your-pattern/i.test(line)) {
        results.push({
          evidence: line.trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      }
    });
    return results;
  },
};
```

Risk points are calculated automatically from `severity` and `confidence` using fixed weights; you do not need to set them manually.

### 3. Register the rule

Open `src/rules/index.ts` and add your rule to the appropriate export array:

```typescript
import { myNewRule } from './injection.js';

export const injectionRules: Rule[] = [
  // ... existing rules ...
  myNewRule,
];
```

### 4. Write tests

Add at least one positive case (should trigger) and one negative case (should not trigger) to `tests/rules.test.ts`:

```typescript
describe('INJ-005', () => {
  const rule = injectionRules.find(r => r.id === 'INJ-005')!;

  it('flags the vulnerable pattern', () => {
    const prompt = makePrompt('your vulnerable example here');
    expect(rule.check(prompt, 'test.ts')).toHaveLength(1);
  });

  it('does not flag safe usage', () => {
    const prompt = makePrompt('safe equivalent here');
    expect(rule.check(prompt, 'test.ts')).toHaveLength(0);
  });
});
```

Run `npm test` to confirm all tests pass.

---

## Commit Message Format

Use the [Conventional Commits](https://www.conventionalcommits.org/) style:

```
<type>: <short summary>
```

Common types:

| Type | When to use |
|------|-------------|
| `feat` | New rule or feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `chore` | Tooling, CI, dependencies |
| `test` | Tests only |
| `refactor` | Code change with no behaviour change |

Examples:

```
feat: add INJ-005 rule for multipart boundary bypass
fix: CMD-003 false negative when path is derived via map()
docs: add remediation guidance for EXF-002
chore: upgrade fast-glob to 3.3.3
```

---

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes; keep commits focused and atomic.
3. Run `npm test` and confirm all tests pass.
4. Run `npm run build` and confirm it compiles without errors.
5. Open a pull request against `main` with a clear description of what changed and why.
6. The CI workflow will run tests and the hound scanner automatically; fix any failures before requesting review.

For significant changes (new rule categories, changes to scoring, CLI behaviour), open an issue first to discuss the approach.

---

## Reporting Security Issues

Do not open a public issue for security vulnerabilities. Use the private advisory process described in [SECURITY.md](SECURITY.md).
