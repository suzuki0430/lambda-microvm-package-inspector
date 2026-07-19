import { spawnSync } from 'node:child_process';
import { promises as dns } from 'node:dns';
import { closeSync, openSync, writeFileSync } from 'node:fs';
import http from 'node:http';

const CANARY_FILE = '/tmp/demo-canary.txt';
const CREDENTIAL_PATH = '/home/sandbox/.aws/credentials';
const SINK_HOST = 'sink.inspection.test';
const SINK_PORT = 8080;
const SINK_PATH = '/events';

/**
 * Emit a machine-readable, non-secret canary event.
 *
 * @param {Record<string, unknown>} event - Harmless event metadata to report.
 * @returns {void}
 */
function report(event) {
  process.stdout.write(`CANARY_EVENT ${JSON.stringify(event)}\n`);
}

/**
 * Attempt a bounded HTTP request to the managed demonstration sink.
 *
 * @returns {Promise<void>} Resolves after success, failure, or a one-second timeout.
 */
async function contactSink() {
  report({ type: 'dns-attempt', hostname: SINK_HOST });

  try {
    const result = await dns.lookup(SINK_HOST);
    report({ type: 'dns-result', hostname: SINK_HOST, address: result.address });
  } catch (error) {
    report({
      type: 'dns-result',
      hostname: SINK_HOST,
      error: error instanceof Error ? error.code ?? error.name : 'unknown',
    });
    // Continue into http.request so DNS denial is also captured as a bounded
    // HTTP failure instead of silently skipping the connection attempt.
  }

  await new Promise((resolve) => {
    const body = JSON.stringify({ fixture: '@demo/canary', version: '1.0.0' });
    const request = http.request(
      {
        hostname: SINK_HOST,
        port: SINK_PORT,
        path: SINK_PATH,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
        timeout: 1000,
      },
      (response) => {
        response.resume();
        response.on('end', () => {
          report({ type: 'http-result', statusCode: response.statusCode ?? 0 });
          resolve();
        });
      },
    );

    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', (error) => {
      report({ type: 'http-result', error: error.message });
      resolve();
    });
    request.end(body);
  });
}

/**
 * Execute the harmless, deterministic installation canary.
 *
 * @returns {Promise<void>} Resolves after every bounded canary action completes.
 */
async function main() {
  process.stdout.write('demo canary postinstall started\n');
  process.stderr.write('demo canary stderr marker\n');

  writeFileSync(CANARY_FILE, 'harmless-canary\n', { encoding: 'utf8', mode: 0o600 });
  report({ type: 'file-write', path: CANARY_FILE });

  const child = spawnSync('/usr/bin/true', [], { timeout: 1000 });
  report({
    type: 'child-process',
    executable: '/usr/bin/true',
    status: child.status,
  });

  report({
    type: 'environment-read',
    name: 'DEMO_CANARY_TOKEN',
    wasSet: process.env.DEMO_CANARY_TOKEN !== undefined,
  });

  try {
    const descriptor = openSync(CREDENTIAL_PATH, 'r');
    closeSync(descriptor);
    report({ type: 'credential-path-open', path: CREDENTIAL_PATH, result: 'success' });
  } catch (error) {
    report({
      type: 'credential-path-open',
      path: CREDENTIAL_PATH,
      result: error instanceof Error ? error.code ?? error.name : 'unknown',
    });
  }

  await contactSink();
  process.stdout.write('demo canary postinstall completed\n');
}

await main();
