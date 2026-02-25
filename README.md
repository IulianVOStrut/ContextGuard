# ContextGuard

> Static analysis tool that scans your codebase for LLM prompt-injection vulnerabilities — runs offline, no API calls required.

[![CI](https://github.com/IulianVOStrut/ContextGuard/actions/workflows/prompt-audit.yml/badge.svg)](https://github.com/IulianVOStrut/ContextGuard/actions/workflows/prompt-audit.yml)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why ContextGuard?

As LLM-powered applications become common in production codebases, prompt injection has emerged as one of the most exploitable attack surfaces — yet most security scanners have no awareness of it.

ContextGuard brings static analysis to your prompt layer:

- Catches **injection paths** before they reach a model
- Flags **leaked credentials and internal infrastructure** embedded in prompts
- Detects **jailbreak-susceptible wording** in your system prompts
- Identifies **unconstrained agentic tool use** that could be weaponised
- Rewards **good security practice** — mitigations in your prompts reduce your score

It fits into your existing workflow as a CLI command, an `npm` script, or a GitHub Action — with zero external dependencies.

---

## Features

| | |
|---|---|
| **10 security rules** | Across 4 categories: injection, exfiltration, jailbreak, unsafe tool use |
| **Numeric risk score (0–100)** | Normalized repo-level score with low / medium / high / critical thresholds |
| **Mitigation detection** | Explicit safety language in your prompts reduces your score |
| **3 output formats** | Human-readable console, JSON, and SARIF for GitHub Code Scanning |
| **GitHub Action included** | Fails CI on high risk and uploads SARIF results automatically |
| **Fully offline** | No API calls, no telemetry, no paid dependencies |

---

## Installation

```bash
git clone https://github.com/IulianVOStrut/ContextGuard.git
cd ContextGuard
npm install
npm run build
```

To use `prompt-audit` as a global command:

```bash
npm link
```

---

## Quick Start

```bash
# Scan your project
prompt-audit scan --dir ./my-ai-project

# Or via npm script (scans current directory)
npm run prompt-audit

# Verbose output — shows remediations and confidence levels
prompt-audit scan --verbose

# Fail the build on any critical finding
prompt-audit scan --fail-on critical

# Export JSON and SARIF reports
prompt-audit scan --format console,json,sarif --out results
```

Exit codes: `0` = passed, `1` = threshold exceeded or `--fail-on` triggered.

---

## GitHub Actions

Add to your workflow to block merges when prompt risk is too high:

```yaml
# .github/workflows/prompt-audit.yml
name: Prompt Audit

on: [push, pull_request]

jobs:
  prompt-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm ci && npm run build

      - run: npm run prompt-audit -- --format console,sarif --out results.sarif

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings will appear in your repository's **Security → Code scanning** tab.

---

## Configuration

Create `.promptauditrc.json` in your project root to customise behaviour:

```json
{
  "include": ["**/*.ts", "**/*.js", "**/*.md", "**/*.txt", "**/*.yaml"],
  "exclude": [
    "**/node_modules/**",
    "**/dist/**",
    "**/tests/**",
    "**/attacks/**"
  ],
  "threshold": 60,
  "formats": ["console", "sarif"],
  "out": "results",
  "verbose": false,
  "failOn": "critical",
  "maxFindings": 50
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `include` | `**/*.{ts,js,md,txt,yaml,yml,json}` | Glob patterns to scan |
| `exclude` | `**/node_modules/**`, `**/dist/**`, etc. | Glob patterns to ignore |
| `threshold` | `60` | Fail if repo score ≥ this value |
| `formats` | `["console"]` | Output formats: `console`, `json`, `sarif` |
| `out` | auto | Base path for json/sarif output files |
| `verbose` | `false` | Show remediations and confidence per finding |
| `failOn` | — | Fail immediately on: `critical`, `high`, or `medium` |
| `maxFindings` | — | Stop after N findings |

---

## Risk Scoring

Each finding carries **risk points** calculated as:

```
risk_points = severity_weight × confidence_multiplier
```

Points are totalled, capped at 100, and classified:

| Score | Level | Suggested action |
|-------|-------|-----------------|
| 0–29 | 🟢 Low | No action required |
| 30–59 | 🟡 Medium | Review before merging |
| 60–79 | 🟠 High | Fix before merging |
| 80–100 | 🔴 Critical | Block deployment |

**Mitigation reduction:** if your prompts include explicit safety language (input delimiters, refusal-to-reveal instructions, tool allowlists), risk points for that prompt are reduced proportionally.

---

## Rules

### A — Injection (INJ)

| ID | Severity | Description |
|----|----------|-------------|
| INJ-001 | High | Direct user input concatenated into prompt without delimiter |
| INJ-002 | Medium | Missing "treat user content as data" boundary language |
| INJ-003 | High | RAG/retrieved context included without untrusted separator |
| INJ-004 | High | Tool-use instructions overridable by user content |

### B — Exfiltration (EXF)

| ID | Severity | Description |
|----|----------|-------------|
| EXF-001 | Critical | Prompt references secrets, API keys, or credentials |
| EXF-002 | Critical | Prompt instructs model to reveal system prompt or hidden instructions |
| EXF-003 | High | Prompt indicates access to confidential or private data |
| EXF-004 | High | Prompt includes internal URLs or infrastructure hostnames |

### C — Jailbreak (JBK)

| ID | Severity | Description |
|----|----------|-------------|
| JBK-001 | Critical | Known jailbreak phrase detected ("ignore instructions", "DAN", etc.) |
| JBK-002 | High | Weak safety wording ("always comply", "no matter what") |
| JBK-003 | High | Role-play escape hatch that undermines safety constraints |

### D — Unsafe Tool Use (TOOL)

| ID | Severity | Description |
|----|----------|-------------|
| TOOL-001 | Critical | Unbounded tool execution ("run any command", "browse anywhere") |
| TOOL-002 | Medium | Tool use described with no allowlist or usage policy |
| TOOL-003 | High | Code execution mentioned without sandboxing constraints |

---

## Example Output

```
=== ContextGuard Prompt Audit ===

src/prompts/assistant.ts (file score: 73)
  [HIGH] INJ-001: Direct user input concatenation without delimiter
    File: src/prompts/assistant.ts:12
    Evidence: Answer the user's question: ${userInput}
    Confidence: medium
    Risk points: 23
    Remediation: Wrap user input with clear delimiters (e.g., triple backticks)
                 and label it as "untrusted user content".

  [CRITICAL] EXF-001: Prompt references secrets, API keys, or credentials
    File: src/prompts/assistant.ts:8
    Evidence: The database password is: secret123.
    Confidence: high
    Risk points: 50
    Remediation: Remove all secret values from prompts. Use environment
                 variables server-side; never embed credentials in prompt text.

────────────────────────────────────────────────────────
Repo Risk Score: 87/100 (CRITICAL)
Threshold: 60
Total findings: 5
By severity: critical: 2  high: 2  medium: 1

✗ FAILED — score meets or exceeds threshold.
```

---

## Project Structure

```
src/
├── cli.ts                  # CLI entry point (Commander.js)
├── types.ts                # Shared TypeScript types
├── config/
│   ├── defaults.ts         # Default include/exclude globs and settings
│   └── loader.ts           # .promptauditrc.json loader
├── scanner/
│   ├── discover.ts         # File discovery via fast-glob
│   ├── extractor.ts        # Prompt extraction (raw, code, structured)
│   └── pipeline.ts         # Orchestrates the full scan
├── rules/
│   ├── types.ts            # Rule interface and scoring helpers
│   ├── injection.ts        # INJ-* rules
│   ├── exfiltration.ts     # EXF-* rules
│   ├── jailbreak.ts        # JBK-* rules
│   ├── unsafeTools.ts      # TOOL-* rules
│   ├── mitigation.ts       # Mitigation presence detection
│   └── index.ts            # Rule registry
├── scoring/
│   └── index.ts            # Risk score calculation
└── report/
    ├── console.ts          # ANSI-coloured terminal output
    ├── json.ts             # JSON report builder
    └── sarif.ts            # SARIF 2.1.0 report builder
attacks/                    # Example injection strings (not executed against models)
tests/
├── fixtures/               # Sample prompts for testing
├── rules.test.ts           # Unit tests for all rules
├── scoring.test.ts         # Unit tests for scoring logic
└── scanner.test.ts         # Integration tests for the scan pipeline
.github/
├── action.yml              # Reusable composite GitHub Action
└── workflows/
    └── prompt-audit.yml    # Sample CI workflow
```

---

## Limitations

- Rules use regex and structural heuristics, not full semantic analysis. False positives are possible — always review findings in context.
- Prompts are not executed against a model; this is purely static analysis.
- TypeScript/JavaScript extraction uses pattern matching rather than a full AST. Complex dynamic prompt construction may be missed.

---

## Contributing

Contributions are welcome. To add a new rule:

1. Add it to the appropriate file in `src/rules/` (or create a new one for a new category)
2. Register it in `src/rules/index.ts`
3. Add at least one positive and one negative test case in `tests/rules.test.ts`
4. Run `npm test` to verify all 28+ tests pass

---

## License

MIT
