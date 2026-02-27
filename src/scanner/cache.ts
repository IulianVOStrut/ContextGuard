import fs from 'fs';
import path from 'path';
import type { Finding } from '../types.js';

const CACHE_VERSION = '1';
const CACHE_FILENAME = '.hound-cache.json';

interface CacheEntry {
  mtime: number;
  findings: Finding[];
}

export interface HoundCache {
  version: string;
  entries: Record<string, CacheEntry>;
}

export function loadCache(cwd: string): HoundCache {
  const cachePath = path.join(cwd, CACHE_FILENAME);
  if (!fs.existsSync(cachePath)) {
    return { version: CACHE_VERSION, entries: {} };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(cachePath, 'utf8')) as HoundCache;
    if (raw.version !== CACHE_VERSION) {
      return { version: CACHE_VERSION, entries: {} };
    }
    return raw;
  } catch {
    return { version: CACHE_VERSION, entries: {} };
  }
}

export function saveCache(cwd: string, cache: HoundCache): void {
  const cachePath = path.join(cwd, CACHE_FILENAME);
  try {
    fs.writeFileSync(cachePath, JSON.stringify(cache, null, 2), 'utf8');
  } catch {
    // Cache write failures are non-fatal
  }
}

export function getCachedFindings(cache: HoundCache, filePath: string): Finding[] | null {
  const entry = cache.entries[filePath];
  if (!entry) return null;
  try {
    const mtime = fs.statSync(filePath).mtimeMs;
    if (mtime === entry.mtime) return entry.findings;
  } catch {
    // File may have been deleted; treat as cache miss
  }
  return null;
}

export function setCacheEntry(cache: HoundCache, filePath: string, findings: Finding[]): void {
  try {
    const mtime = fs.statSync(filePath).mtimeMs;
    cache.entries[filePath] = { mtime, findings };
  } catch {
    // If stat fails, skip caching this file
  }
}
