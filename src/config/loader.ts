import fs from 'fs';
import path from 'path';
import type { AuditConfig } from '../types.js';
import { DEFAULT_CONFIG } from './defaults.js';

interface RcFile {
  include?: string[];
  exclude?: string[];
  threshold?: number;
  formats?: string[];
  out?: string;
  maxFindings?: number;
  failOn?: string;
  verbose?: boolean;
}

export function loadConfig(configPath?: string, cwd: string = process.cwd()): AuditConfig {
  const rcPath = configPath
    ? path.resolve(configPath)
    : path.join(cwd, '.contexthoundrc.json');

  let rc: RcFile = {};
  if (fs.existsSync(rcPath)) {
    try {
      rc = JSON.parse(fs.readFileSync(rcPath, 'utf8')) as RcFile;
    } catch {
      console.warn(`Warning: Could not parse config file at ${rcPath}`);
    }
  }

  return {
    include: rc.include ?? DEFAULT_CONFIG.include,
    exclude: rc.exclude ?? DEFAULT_CONFIG.exclude,
    threshold: rc.threshold ?? DEFAULT_CONFIG.threshold,
    formats: (rc.formats as AuditConfig['formats']) ?? DEFAULT_CONFIG.formats,
    out: rc.out,
    maxFindings: rc.maxFindings,
    failOn: rc.failOn as AuditConfig['failOn'],
    verbose: rc.verbose ?? DEFAULT_CONFIG.verbose,
  };
}
