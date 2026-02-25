#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { loadConfig } from './config/loader.js';
import { runScan } from './scanner/pipeline.js';
import { printConsoleReport } from './report/console.js';
import { buildJsonReport } from './report/json.js';
import { buildSarifReport } from './report/sarif.js';
import type { AuditConfig, OutputFormat, FailOn } from './types.js';

const program = new Command();

program
  .name('prompt-audit')
  .description('ContextGuard: Scan LLM prompts for injection and security risks')
  .version('1.0.0');

program
  .command('scan', { isDefault: true })
  .description('Scan a repository for prompt-injection risks')
  .option('-c, --config <path>', 'Path to .promptauditrc.json config file')
  .option('-f, --format <formats>', 'Output formats: console,json,sarif (comma-separated)', 'console')
  .option('-o, --out <path>', 'Output path for json/sarif files')
  .option('-t, --threshold <n>', 'Risk score threshold (0-100). Fail if score >= threshold', '60')
  .option('--fail-on <level>', 'Fail on first finding of this severity: critical|high|medium')
  .option('--max-findings <n>', 'Stop after N findings')
  .option('-v, --verbose', 'Verbose output (show remediation and confidence)')
  .option('--dir <path>', 'Directory to scan (default: current working directory)')
  .action(async (opts: {
    config?: string;
    format: string;
    out?: string;
    threshold: string;
    failOn?: string;
    maxFindings?: string;
    verbose?: boolean;
    dir?: string;
  }) => {
    const cwd = opts.dir ? path.resolve(opts.dir) : process.cwd();

    // Load config file
    const fileConfig = loadConfig(opts.config, cwd);

    // CLI options override config file
    const formats = opts.format.split(',').map(f => f.trim()) as OutputFormat[];

    const config: AuditConfig = {
      ...fileConfig,
      formats,
      threshold: opts.threshold ? parseInt(opts.threshold, 10) : fileConfig.threshold,
      out: opts.out ?? fileConfig.out,
      failOn: (opts.failOn as FailOn) ?? fileConfig.failOn,
      maxFindings: opts.maxFindings ? parseInt(opts.maxFindings, 10) : fileConfig.maxFindings,
      verbose: opts.verbose ?? fileConfig.verbose,
    };

    if (config.verbose) {
      console.log(`Scanning: ${cwd}`);
      console.log(`Threshold: ${config.threshold}`);
      console.log(`Formats: ${config.formats.join(', ')}`);
    }

    let result;
    try {
      result = await runScan(cwd, config);
    } catch (err) {
      console.error('Error during scan:', err);
      process.exit(2);
    }

    // Console report always prints
    printConsoleReport(result, config.verbose);

    // JSON report
    if (formats.includes('json')) {
      const json = buildJsonReport(result);
      const outPath = config.out ? `${config.out}.json` : path.join(cwd, 'prompt-audit-results.json');
      fs.writeFileSync(outPath, json, 'utf8');
      console.log(`JSON report written to: ${outPath}`);
    }

    // SARIF report
    if (formats.includes('sarif')) {
      const sarif = buildSarifReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.sarif') ? config.out : `${config.out}.sarif`)
        : path.join(cwd, 'results.sarif');
      fs.writeFileSync(outPath, sarif, 'utf8');
      console.log(`SARIF report written to: ${outPath}`);
    }

    process.exit(result.passed ? 0 : 1);
  });

program.parse(process.argv);
