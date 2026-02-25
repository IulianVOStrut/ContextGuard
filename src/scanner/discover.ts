import fg from 'fast-glob';
import type { AuditConfig } from '../types.js';

export async function discoverFiles(cwd: string, config: AuditConfig): Promise<string[]> {
  const files = await fg(config.include, {
    cwd,
    ignore: config.exclude,
    absolute: true,
    followSymbolicLinks: false,
    onlyFiles: true,
  });
  return files.sort();
}
