import fs from 'fs';
import path from 'path';

export interface ExtractedPrompt {
  text: string;
  lineStart: number;
  lineEnd: number;
  kind: 'raw' | 'template-string' | 'object-field' | 'chat-message' | 'code-block';
}

const PROMPT_KEY_PATTERN = /(?:^|["'])(?:system|prompt|instructions?|messages?|role|content|context|directive)(?:["']|\s*:)/i;
const ROLE_CONTENT_PATTERN = /\{\s*["']?role["']?\s*:\s*["'][^"']+["']\s*,\s*["']?content["']?\s*:/i;
const SYSTEM_PHRASE_PATTERN = /(?:you are|your (role|task|job|purpose) is|do not|don't|never|always|must|system:|instructions?:|you must|as an? (ai|assistant|bot))/i;
// Patterns that trigger full-file code-block extraction so multi-line rules can
// analyse the complete context (CMD, RAG, and encoding rules rely on this).
const SHELL_EXEC_PATTERN = /(?:execSync|execFile|spawnSync)\s*\(|(?:exec|spawn)\s*\(\s*[`"']/i;
const MESSAGES_PUSH_PATTERN = /messages\s*(?:\??\.)?\s*push\s*\(\s*\{/i;
const BASE64_CALL_PATTERN =
  /(?:atob|btoa)\s*\(|\.toString\s*\(\s*['"]base64['"]\s*\)|Buffer\.from\s*\([^)]+,\s*['"]base64['"]/i;
const JSON_PARSE_PATTERN = /JSON\.parse\s*\(/i;
const MD_RENDER_PATTERN =
  /(?:marked\s*[.(]|marked\.parse\s*\(|markdownIt\s*[.(]|new\s+MarkdownIt|dangerouslySetInnerHTML\s*=)/i;

function isCodeFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.ts' || ext === '.js' || ext === '.tsx' || ext === '.jsx';
}

function isRawPromptFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.prompt', '.txt', '.md'].includes(ext);
}

export function extractPrompts(filePath: string): ExtractedPrompt[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  if (isRawPromptFile(filePath)) {
    return extractFromRaw(content);
  }

  if (filePath.endsWith('.json') || filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
    return extractFromStructured(content);
  }

  if (isCodeFile(filePath)) {
    return extractFromCode(content, filePath);
  }

  // For other text files, treat as raw
  return extractFromRaw(content);
}

function extractFromRaw(content: string): ExtractedPrompt[] {
  const lines = content.split('\n');
  // Return entire file as one block if it looks like a prompt
  if (SYSTEM_PHRASE_PATTERN.test(content) || content.length > 50) {
    return [{
      text: content,
      lineStart: 1,
      lineEnd: lines.length,
      kind: 'raw',
    }];
  }
  return [];
}

function extractFromStructured(content: string): ExtractedPrompt[] {
  const results: ExtractedPrompt[] = [];
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    if (PROMPT_KEY_PATTERN.test(line)) {
      // Grab up to 20 lines of context
      const start = idx;
      const end = Math.min(idx + 20, lines.length - 1);
      const snippet = lines.slice(start, end + 1).join('\n');
      results.push({
        text: snippet,
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'object-field',
      });
    }
  });

  return results;
}

function extractFromCode(content: string, _filePath: string): ExtractedPrompt[] {
  const results: ExtractedPrompt[] = [];
  const lines = content.split('\n');

  // Detect template literals / strings that look like prompts
  let inTemplateLiteral = false;
  let templateStart = 0;
  let templateLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Simple template literal detection (backtick strings)
    const backtickCount = (line.match(/`/g) || []).length;

    if (!inTemplateLiteral && backtickCount % 2 === 1) {
      // Opening backtick
      inTemplateLiteral = true;
      templateStart = i;
      templateLines = [line];
    } else if (inTemplateLiteral && backtickCount % 2 === 1) {
      // Closing backtick
      templateLines.push(line);
      const text = templateLines.join('\n');
      if (SYSTEM_PHRASE_PATTERN.test(text) || PROMPT_KEY_PATTERN.test(text)) {
        results.push({
          text,
          lineStart: templateStart + 1,
          lineEnd: i + 1,
          kind: 'template-string',
        });
      }
      inTemplateLiteral = false;
      templateLines = [];
    } else if (inTemplateLiteral) {
      templateLines.push(line);
      // Safety: bail on very long template literals
      if (templateLines.length > 200) {
        inTemplateLiteral = false;
        templateLines = [];
      }
    }

    // Detect OpenAI-style chat messages {role, content}
    if (ROLE_CONTENT_PATTERN.test(line)) {
      const start = i;
      const end = Math.min(i + 5, lines.length - 1);
      results.push({
        text: lines.slice(start, end + 1).join('\n'),
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'chat-message',
      });
    }

    // Detect object keys like system:, prompt:, instructions:
    if (PROMPT_KEY_PATTERN.test(line) && !ROLE_CONTENT_PATTERN.test(line)) {
      const start = i;
      const end = Math.min(i + 15, lines.length - 1);
      results.push({
        text: lines.slice(start, end + 1).join('\n'),
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'object-field',
      });
    }
  }

  // Expose the full file as a code-block when it contains patterns that require
  // multi-line analysis: shell exec calls (CMD rules), messages.push (RAG rules),
  // or Base64 API calls (ENC/EXF rules).
  if (
    SHELL_EXEC_PATTERN.test(content) ||
    MESSAGES_PUSH_PATTERN.test(content) ||
    BASE64_CALL_PATTERN.test(content) ||
    JSON_PARSE_PATTERN.test(content) ||
    MD_RENDER_PATTERN.test(content)
  ) {
    results.push({
      text: content,
      lineStart: 1,
      lineEnd: lines.length,
      kind: 'code-block',
    });
  }

  return results;
}
