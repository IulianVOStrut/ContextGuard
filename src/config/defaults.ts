import type { AuditConfig } from '../types.js';

export const DEFAULT_INCLUDE_GLOBS: string[] = [
  '**/*.prompt',
  '**/*.prompt.*',
  '**/*.md',
  '**/*.txt',
  '**/*.yaml',
  '**/*.yml',
  '**/*.json',
  '**/*.ts',
  '**/*.js',
];

export const DEFAULT_EXCLUDE_GLOBS: string[] = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.lock',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
];

export const DEFAULT_CONFIG: AuditConfig = {
  include: DEFAULT_INCLUDE_GLOBS,
  exclude: DEFAULT_EXCLUDE_GLOBS,
  threshold: 60,
  formats: ['console'],
  verbose: false,
};
