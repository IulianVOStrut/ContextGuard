import fs from 'fs';
import path from 'path';
import type { AuditConfig, FileResult, Finding, ScanResult } from '../types.js';
import { discoverFiles } from './discover.js';
import { extractPrompts } from './extractor.js';
import { analyzePrompt, scoreFile, buildScanResult } from '../scoring/index.js';

async function loadHoundIgnore(cwd: string): Promise<string[]> {
  const p = path.join(cwd, '.houndignore');
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

// Inline concurrency limiter — avoids p-limit (ESM-only, incompatible with CommonJS)
function createLimiter(concurrency: number) {
  let active = 0;
  const queue: Array<() => void> = [];

  function next() {
    while (queue.length > 0 && active < concurrency) {
      active++;
      queue.shift()!();
    }
  }

  return function limit<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      queue.push(() => {
        fn().then(resolve, reject).finally(() => {
          active--;
          next();
        });
      });
      next();
    });
  };
}

export async function runScan(
  cwd: string,
  config: AuditConfig,
  onFinding?: (finding: Finding) => void
): Promise<ScanResult> {
  // Merge .houndignore patterns into exclude list
  const houndIgnorePatterns = await loadHoundIgnore(cwd);
  if (houndIgnorePatterns.length > 0) {
    config = { ...config, exclude: [...config.exclude, ...houndIgnorePatterns] };
  }

  const files = await discoverFiles(cwd, config);

  const concurrency = config.concurrency ?? 8;
  const limit = createLimiter(concurrency);

  const fileResults: FileResult[] = [];
  let totalFindings = 0;
  let aborted = false;

  const tasks = files.map(file =>
    limit(async () => {
      if (aborted) return;

      const prompts = extractPrompts(file);
      if (prompts.length === 0) return;

      const findings = analyzePrompt(prompts, file, config);
      if (findings.length === 0) return;

      if (aborted) return; // recheck after CPU work

      if (onFinding) {
        for (const f of findings) onFinding(f);
      }

      const fileScore = scoreFile(findings);
      fileResults.push({ file, findings, fileScore });

      totalFindings += findings.length;
      if (config.maxFindings && totalFindings >= config.maxFindings) {
        aborted = true;
      }
    })
  );

  await Promise.all(tasks);

  // Sort by file path for deterministic, diffable output
  fileResults.sort((a, b) => a.file.localeCompare(b.file));

  return buildScanResult(fileResults, config);
}
