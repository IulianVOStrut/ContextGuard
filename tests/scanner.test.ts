import path from 'path';
import { runScan } from '../src/scanner/pipeline';
import { DEFAULT_CONFIG } from '../src/config/defaults';

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

describe('Scanner pipeline', () => {
  it('finds findings in the risky fixture directory', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      include: ['*.ts', '*.txt'],
      exclude: [],
    };
    const result = await runScan(FIXTURES_DIR, config);
    expect(result.allFindings.length).toBeGreaterThan(0);
    expect(result.repoScore).toBeGreaterThan(0);
  });

  it('returns lower score for safe prompt', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      include: ['safe-prompt.txt'],
      exclude: [],
    };
    const risky = {
      ...DEFAULT_CONFIG,
      include: ['risky-prompt.txt'],
      exclude: [],
    };
    const safeResult = await runScan(FIXTURES_DIR, config);
    const riskyResult = await runScan(FIXTURES_DIR, risky);

    // Safe prompt may have some findings but should score lower than risky
    expect(safeResult.repoScore).toBeLessThanOrEqual(riskyResult.repoScore);
  });

  it('passes when no files match globs', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      include: ['**/*.nonexistent'],
      exclude: [],
    };
    const result = await runScan(FIXTURES_DIR, config);
    expect(result.allFindings).toHaveLength(0);
    expect(result.repoScore).toBe(0);
    expect(result.passed).toBe(true);
  });
});
