# Attack Templates

This folder contains example prompt-injection attack strings used to test prompt robustness.

**These are NOT executed against any model.** They exist so the scanner can check whether your prompts contain explicit mitigations against known attack patterns.

## Files

| File | Attack Type |
|------|-------------|
| `ignore-previous.txt` | Instruction override attacks |
| `developer-mode.txt` | Developer/DAN mode jailbreaks |
| `reveal-secrets.txt` | Secret/credential exfiltration attempts |
| `tag-injection.txt` | Tag-based injection (XML/custom delimiters) |

## How the scanner uses these

The scanner checks whether your prompts include language that explicitly defends against these patterns:
- Does the prompt state instructions cannot be changed?
- Does it delimit and label user input as untrusted?
- Does it refuse to reveal the system prompt?
- Does it constrain tool use?

Presence of these mitigations reduces the overall risk score.
