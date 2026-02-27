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

  const fileResults: FileResult[] = [];
  let totalFindings = 0;

  for (const file of files) {
    const prompts = extractPrompts(file);
    if (prompts.length === 0) continue;

    const findings = analyzePrompt(prompts, file, config);
    if (findings.length === 0) continue;

    if (onFinding) {
      for (const f of findings) onFinding(f);
    }

    const fileScore = scoreFile(findings);
    fileResults.push({ file, findings, fileScore });

    totalFindings += findings.length;
    if (config.maxFindings && totalFindings >= config.maxFindings) break;
  }

  return buildScanResult(fileResults, config);
}
