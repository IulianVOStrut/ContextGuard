import type { AuditConfig, FileResult, ScanResult } from '../types.js';
import { discoverFiles } from './discover.js';
import { extractPrompts } from './extractor.js';
import { analyzePrompt, scoreFile, buildScanResult } from '../scoring/index.js';

export async function runScan(cwd: string, config: AuditConfig): Promise<ScanResult> {
  const files = await discoverFiles(cwd, config);

  const fileResults: FileResult[] = [];
  let totalFindings = 0;

  for (const file of files) {
    const prompts = extractPrompts(file);
    if (prompts.length === 0) continue;

    const findings = analyzePrompt(prompts, file);
    if (findings.length === 0) continue;

    const fileScore = scoreFile(findings);
    fileResults.push({ file, findings, fileScore });

    totalFindings += findings.length;
    if (config.maxFindings && totalFindings >= config.maxFindings) break;
  }

  return buildScanResult(fileResults, config);
}
