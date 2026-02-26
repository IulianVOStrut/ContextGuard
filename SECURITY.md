# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, report them privately via [GitHub's private vulnerability reporting](https://github.com/IulianVOStrut/ContextHound/security/advisories/new).

Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested fix if you have one

You can expect an acknowledgement within 48 hours and a resolution or status update within 7 days.

## Scope

This tool runs entirely offline and makes no network requests at runtime. The main security considerations are:

- **False negatives**: a prompt with a real injection risk is not flagged. Please report these so the rules can be improved.
- **Supply chain**: vulnerabilities in npm dependencies. Dependabot is enabled on this repo and PRs are raised automatically for dependency updates.

## Out of Scope

- Vulnerabilities in the LLM systems that ContextHound scans (report those to the respective vendors)
- False positives (open a regular issue instead)
