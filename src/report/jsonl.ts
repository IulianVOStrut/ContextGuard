import type { ScanResult } from '../types.js';

export function buildJsonlReport(result: ScanResult): string {
  return result.allFindings.map(f => JSON.stringify(f)).join('\n');
}
