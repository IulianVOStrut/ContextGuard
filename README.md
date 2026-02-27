# ContextHound

> Static analysis tool that scans your codebase for LLM prompt-injection and multimodal security vulnerabilities. Runs offline, no API calls required.

[![CI](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml/badge.svg)](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
---
## ☕ Support the project

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/D1D01UKFNS)
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/I_VO_S)
---

## Why ContextHound?

As LLM-powered applications become common in production codebases, prompt injection has emerged as one of the most exploitable attack surfaces; most security scanners have no awareness of it.

ContextHound brings static analysis to your prompt layer:

- Catches **injection paths** before they reach a model
- Flags **leaked credentials and internal infrastructure** embedded in prompts
- Detects **jailbreak-susceptible wording** in your system prompts
- Identifies **unconstrained agentic tool use** that could be weaponised
- Detects **RAG corpus poisoning** and retrieved content injected as system instructions
- Catches **encoding-based smuggling** (Base64 instructions that bypass string filters)
- Flags **unsafe LLM output consumption**: JSON without schema validation and Markdown without sanitization
- Detects **multimodal attack surfaces**: user-supplied image URLs to vision APIs, path traversal via vision message file reads, transcription output fed into prompts, and OCR text injected into system instructions
- Rewards **good security practice**: mitigations in your prompts reduce your score

It fits into your existing workflow as a CLI command, an `npm` script, or a GitHub Action, with zero external dependencies.

---

## Features

| | |
|---|---|
| \*\*61 security rules\*\* | Across 10 categories: injection, exfiltration, jailbreak, unsafe tool use, command injection, RAG poisoning, encoding, output handling, multimodal, skills marketplace |
| **Numeric risk score (0-100)** | Normalized repo-level score with low, medium, high and critical thresholds |
| **Mitigation detection** | Explicit safety language in your prompts reduces your score |
| **3 output formats** | Human-readable console, JSON, and SARIF for GitHub Code Scanning |
| **GitHub Action included** | Fails CI on high risk and uploads SARIF results automatically |
| **Multi-language scanning** | Detects LLM API usage in Python, Go, Rust, Java, C#, PHP, Ruby, Swift, Kotlin, Vue, Bash — not just TypeScript/JavaScript |
| **Fully offline** | No API calls, no telemetry, no paid dependencies |

---

## Installation

```bash
git clone https://github.com/IulianVOStrut/ContextHound.git
cd ContextHound
npm install
npm run build
```

To use `hound` as a global command:

```bash
npm link
```

---

## Quick Start

```bash
# Scan your project
hound scan --dir ./my-ai-project

# Or via npm script (scans current directory)
npm run hound

# Verbose output, shows remediations and confidence levels
hound scan --verbose

# Fail the build on any critical finding
hound scan --fail-on critical

# Export JSON and SARIF reports
hound scan --format console,json,sarif --out results
```

Exit codes: `0` = passed, `1` = threshold exceeded or `--fail-on` triggered.

---

## GitHub Actions

Add to your workflow to block merges when prompt risk is too high:

```yaml
# .github/workflows/context-hound.yml
name: Prompt Audit

on: [push, pull_request]

jobs:
  hound:
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

      - run: npm run hound -- --format console,sarif --out results.sarif

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings will appear in your repository's **Security > Code scanning** tab.

---

## Configuration

Create `.contexthoundrc.json` in your project root to customise behaviour:

```json
{
  "include": ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.rs", "**/*.md", "**/*.txt", "**/*.yaml"],
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
| `include` | `**/*.{ts,tsx,js,jsx,py,go,rs,java,kt,cs,php,rb,swift,vue,sh,bash,hs,md,txt,yaml,yml,json}` | Glob patterns to scan |
| `exclude` | `**/node_modules/**`, `**/dist/**`, etc. | Glob patterns to ignore |
| `threshold` | `60` | Fail if repo score is at or above this value |
| `formats` | `["console"]` | Output formats: `console`, `json`, `sarif` |
| `out` | auto | Base path for json/sarif output files |
| `verbose` | `false` | Show remediations and confidence per finding |
| `failOn` | unset | Fail immediately on: `critical`, `high`, or `medium` |
| `maxFindings` | unset | Stop after N findings |

---

## Risk Scoring

Each finding carries **risk points** calculated as:

```
risk_points = severity_weight x confidence_multiplier
```

Points are totalled, capped at 100, and classified:

| Score | Level | Suggested action |
|-------|-------|-----------------|
| 0-29 | 🟢 Low | No action required |
| 30-59 | 🟡 Medium | Review before merging |
| 60-79 | 🟠 High | Fix before merging |
| 80-100 | 🔴 Critical | Block deployment |

If your prompts include explicit safety language (input delimiters, refusal-to-reveal instructions, tool allowlists), risk points for that prompt are reduced proportionally.

---

## Rules

### A. Injection (INJ)

| ID | Severity | Description |
|----|----------|-------------|
| INJ-001 | High | Direct user input concatenated into prompt without delimiter |
| INJ-002 | Medium | Missing "treat user content as data" boundary language |
| INJ-003 | High | RAG/retrieved context included without untrusted separator |
| INJ-004 | High | Tool-use instructions overridable by user content |
| INJ-005 | High | Serialised user object (`JSON.stringify`) interpolated directly into a prompt template |
| INJ-006 | Medium | HTML comment containing hidden instruction verbs in user-controlled content |
| INJ-007 | Medium | User input wrapped in code-fence delimiters without stripping backticks first |
| INJ-008 | High | HTTP request data (`req.body`, `req.query`, `req.params`) interpolated into `role: "system"` template string |
| INJ-009 | Critical | HTTP request body parsed as the messages array directly — attacker controls role and content |
| INJ-010 | High | Plaintext role-label transcript (`User:`, `Assistant:`, `system:`) built with untrusted input concatenation |
| INJ-011 | High | Browser DOM or URL source (`window.location`, `document.cookie`, `getElementById`) fed directly into LLM call |

### B. Exfiltration (EXF)

| ID | Severity | Description |
|----|----------|-------------|
| EXF-001 | Critical | Prompt references secrets, API keys, or credentials |
| EXF-002 | Critical | Prompt instructs model to reveal system prompt or hidden instructions |
| EXF-003 | High | Prompt indicates access to confidential or private data |
| EXF-004 | High | Prompt includes internal URLs or infrastructure hostnames |
| EXF-005 | High | Sensitive variable (token, password, key) encoded as Base64 in output |
| EXF-006 | High | Full prompt or message array logged via `console.log` / `logger.*` without redaction |
| EXF-007 | Critical | Actual secret value embedded in prompt alongside a "never reveal" instruction |

### C. Jailbreak (JBK)

| ID | Severity | Description |
|----|----------|-------------|
| JBK-001 | Critical | Known jailbreak phrase detected ("ignore instructions", "DAN", etc.) |
| JBK-002 | High | Weak safety wording ("always comply", "no matter what") |
| JBK-003 | High | Role-play escape hatch that undermines safety constraints |
| JBK-004 | High | Agent instructed to act without confirmation or human review ("proceed automatically", "no confirmation needed") |
| JBK-005 | High | Evidence-erasure or cover-tracks instruction ("delete logs", "leave no trace") |
| JBK-006 | High | Policy-legitimacy framing combined with an unsafe action request ("as a penetration tester, escalate privileges") |

### D. Unsafe Tool Use (TOOL)

| ID | Severity | Description |
|----|----------|-------------|
| TOOL-001 | Critical | Unbounded tool execution ("run any command", "browse anywhere", backtick shell substitution) |
| TOOL-002 | Medium | Tool use described with no allowlist or usage policy |
| TOOL-003 | High | Code execution mentioned without sandboxing constraints |
| TOOL-004 | Critical | Tool description or schema field sourced from a user-controlled variable |
| TOOL-005 | Critical | Tool `name` or endpoint `url` sourced from user-controlled input (`req.body`, `req.query`, etc.) |

### E. Command Injection (CMD)

Detects vulnerable patterns in the code surrounding AI tools, where a successful prompt injection can escalate into full command execution. Informed by real CVEs found in Google's Gemini CLI by Cyera Research Labs (2025).

| ID | Severity | Description |
|----|----------|-------------|
| CMD-001 | Critical | Shell command built with unsanitised variable interpolation — JS/TS (`execSync(\`cmd ${var}\``), Python (`subprocess.run(f"cmd {var}")`), PHP (`shell_exec($var)`), Go (`exec.Command` + `fmt.Sprintf`), Rust (`Command::new` + `format!`) |
| CMD-002 | High | Incomplete command substitution filtering: blocks `$()` but not backticks, or vice versa |
| CMD-003 | High | File path from `glob.sync` or `readdirSync` used directly in a shell command without sanitisation |
| CMD-004 | Critical | Python `subprocess.run`/`subprocess.call` invoked with `shell=True` and a variable or f-string command argument |
| CMD-005 | Critical | PHP `shell_exec`, `system`, `passthru`, `exec`, or `popen` called with a `$variable` argument |

### F. RAG Poisoning (RAG)

Detects architectural mistakes in Retrieval-Augmented Generation pipelines that allow retrieved or ingested content to override system-level instructions.

| ID | Severity | Description |
|----|----------|-------------|
| RAG-001 | High | Retrieved or external content assigned to `role: "system"` in a messages array |
| RAG-002 | High | Instruction-like phrases ("system prompt:", "always return", "never redact") detected inside a document ingestion loop |
| RAG-003 | High | Agent memory store written directly from user-controlled input without validation |
| RAG-004 | Medium | Prompt instructs model to treat retrieved context as highest priority, overriding developer instructions |

### G. Encoding (ENC)

Detects encoding-based injection and evasion techniques where Base64 or similar encodings are used to smuggle instructions past string-based filters.

| ID | Severity | Description |
|----|----------|-------------|
| ENC-001 | Medium | `atob`, `btoa`, or `Buffer.from(x, 'base64')` called on a user-controlled variable near prompt construction |
| ENC-002 | High | Hidden Unicode control characters (zero-width spaces, bidi overrides) detected near instruction keywords |

### H. Output Handling (OUT)

Covers the output side of the LLM pipeline — how your application consumes model responses. Unsafe consumption can turn a prompt-injection payload into an application-level exploit.

| ID | Severity | Description |
|----|----------|-------------|
| OUT-001 | Critical | `JSON.parse()` (JS/TS) or `json.loads()` (Python) called on LLM output without schema validation (Zod, AJV, Joi, Pydantic, Marshmallow, etc.) |
| OUT-002 | Critical | LLM-generated Markdown or HTML rendered without DOMPurify or equivalent sanitizer |
| OUT-003 | Critical | LLM output used directly as argument to `exec()`, `eval()`, or `db.query()` |
| OUT-004 | Critical | Python `eval()` or `exec()` called with LLM-generated output as the argument |

### I. Multimodal (VIS)

Covers trust-boundary violations specific to vision, audio/video, and OCR pipelines. Multimodal inputs are an emerging injection vector: an attacker who controls an image URL, an audio file, or a scanned document can use these rules' patterns to smuggle instructions into the model.

| ID | Severity | Description |
|----|----------|-------------|
| VIS-001 | Critical | User-supplied image URL or base64 data forwarded to a vision API (gpt-4o, Claude 3, Gemini Vision) without domain or MIME validation |
| VIS-002 | Critical | `fs.readFile`/`readFileSync` called with a user-controlled path in a file that also builds a vision API message — path traversal into multimodal input |
| VIS-003 | High | Audio/video transcription output (Whisper, AssemblyAI, Deepgram, etc.) fed directly into prompt messages without sanitization — RAG poisoning via audio source |
| VIS-004 | High | OCR output (Tesseract, Google Vision) interpolated into a `role: "system"` message or system prompt variable |

### Skills Marketplace — `SKL` (7 rules) — v1.1

Targets OpenClaw `SKILL.md` files and any markdown files inside `skills/` directories. Fires on self-authoring attacks, remote skill loading, injected instructions, unsafe command dispatch, sensitive path access, privilege escalation claims, and hardcoded credentials in YAML frontmatter.

| ID | Severity | Description |
|----|----------|-------------|
| SKL-001 | Critical | Skill body instructs agent to write or modify other skill files — self-authoring attack that persists across agent restarts |
| SKL-002 | Critical | Skill body instructs agent to fetch or load skills from an external URL — allows attacker to change skill behavior after installation |
| SKL-003 | Critical | Skill body contains prompt injection phrases targeting agent core instructions (`ignore previous instructions`, `you are now unrestricted`, etc.) |
| SKL-004 | High | Skill frontmatter uses `command-dispatch: tool` with `command-arg-mode: raw` — forwards raw user input to a tool, bypassing model safety reasoning |
| SKL-005 | High | Skill body references sensitive filesystem paths (`~/.ssh`, `~/.env`, `/etc/passwd`, `../../`) for agent to read and potentially exfiltrate |
| SKL-006 | High | Skill body claims elevated privileges or instructs agent to override or disable other installed skills |
| SKL-007 | Critical | Hardcoded credential value (API key, token, password) found in YAML frontmatter — exposed to anyone who receives or installs the skill |
| SKL-008 | Critical | Heartbeat C2 — skill schedules periodic remote fetch to silently overwrite its own instructions after a clean install |
| SKL-009 | Critical | Agent identity denial — skill instructs agent to deny being AI, claim to be human, or adopt a deceptive persona |
| SKL-010 | Critical | Anti-scanner evasion — skill contains text explicitly designed to mislead security auditing tools |
| SKL-011 | Critical | SOUL.md / IDENTITY.md persistence — skill writes instructions to agent identity files that survive uninstallation |
| SKL-012 | High | Self-propagating worm — skill instructs agent to spread via SSH or `curl\|bash` to reachable hosts |
| SKL-013 | High | Autonomous financial transactions — skill executes crypto transactions or holds private keys without per-transaction user confirmation |

> **Scanning OpenClaw skills:** Run `npx hound scan --dir ./skills` or add `**/skills/**/*.md` and `**/SKILL.md` to your `include` config. ContextHound automatically emits skill files as `code-block` for multi-line rule analysis.

---

## Example Output

```
=== ContextHound Prompt Audit ===

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

✗ FAILED - score meets or exceeds threshold.
```

---

## Project Structure

```
src/
├── cli.ts                  # CLI entry point (Commander.js)
├── types.ts                # Shared TypeScript types
├── config/
│   ├── defaults.ts         # Default include/exclude globs and settings
│   └── loader.ts           # .contexthoundrc.json loader
├── scanner/
│   ├── discover.ts         # File discovery via fast-glob
│   ├── extractor.ts        # Prompt extraction (raw, code, structured)
│   ├── languages.ts        # LLM API trigger patterns per language extension
│   └── pipeline.ts         # Orchestrates the full scan
├── rules/
│   ├── types.ts            # Rule interface and scoring helpers
│   ├── injection.ts        # INJ-* rules
│   ├── exfiltration.ts     # EXF-* rules
│   ├── jailbreak.ts        # JBK-* rules
│   ├── unsafeTools.ts      # TOOL-* rules
│   ├── commandInjection.ts # CMD-* rules
│   ├── rag.ts              # RAG-* rules
│   ├── encoding.ts         # ENC-* rules
│   ├── outputHandling.ts   # OUT-* rules
│   ├── multimodal.ts       # VIS-* rules
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
    └── context-hound.yml    # CI workflow
```

---

## Limitations

- Rules use regex and structural heuristics, not full semantic analysis. False positives are possible; always review findings in context.
- Prompts are not executed against a model; this is purely static analysis.
- Extraction uses pattern matching rather than a full AST. Complex dynamic prompt construction may be missed.
- For non-JS/TS languages (Python, Go, Rust, etc.) a file is analysed only when an LLM library import is detected. Files that construct prompts without a recognised import will not be extracted.

---

## Contributing

Contributions are welcome. To add a new rule:

1. Add it to the appropriate file in `src/rules/` (or create a new one for a new category)
2. Register it in `src/rules/index.ts`
3. Add at least one positive and one negative test case in `tests/rules.test.ts`
4. Run `npm test` to verify all tests pass

---

## License

MIT
