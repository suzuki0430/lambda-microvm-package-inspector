import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const FIXTURES = [
  {
    ecosystem: 'npm',
    name: '@demo/good',
    version: '1.0.0',
    artifact: 'demo-good-1.0.0.tgz',
  },
  {
    ecosystem: 'npm',
    name: '@demo/canary',
    version: '1.0.0',
    artifact: 'demo-canary-1.0.0.tgz',
  },
];

/**
 * Compute the SHA-256 digest for an artifact.
 *
 * @param {string} artifactPath - Absolute path of the artifact to hash.
 * @returns {Promise<string>} Lowercase hexadecimal SHA-256 digest.
 */
async function sha256(artifactPath) {
  const bytes = await fs.readFile(artifactPath);
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Generate the allowlisted fixture catalog used by the trusted runner.
 *
 * @returns {Promise<void>} Resolves after catalog.json has been written.
 * @throws {Error} When the fixture directory or an expected artifact is missing.
 */
async function main() {
  const fixtureDirectory = process.argv[2];
  if (!fixtureDirectory) {
    throw new Error('usage: generate-catalog.mjs <fixture-directory>');
  }

  const entries = [];
  for (const fixture of FIXTURES) {
    const artifactPath = path.join(fixtureDirectory, fixture.artifact);
    const stat = await fs.stat(artifactPath);
    entries.push({
      ...fixture,
      sha256: await sha256(artifactPath),
      sizeBytes: stat.size,
    });
  }

  const catalog = {
    schemaVersion: '1.0.0',
    entries,
  };
  await fs.writeFile(
    path.join(fixtureDirectory, 'catalog.json'),
    `${JSON.stringify(catalog, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o644 },
  );
}

await main();
