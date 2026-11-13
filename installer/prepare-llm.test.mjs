import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), 'prepare-llm.ps1');
function verify(root) {
  return spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', script, '-VerifyOnly', '-AssetRoot', root,
  ], { encoding: 'utf8' });
}

test('packaging preflight rejects missing model and runtime', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'aegis-llm-test-'));
  try {
    const result = verify(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /missing bundled/i);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('packaging preflight rejects a truncated model', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'aegis-llm-test-'));
  try {
    mkdirSync(path.join(root, 'runtime'));
    writeFileSync(path.join(root, 'model.gguf'), 'not a model');
    writeFileSync(path.join(root, 'runtime', 'llama-server.exe'), 'not a runtime');
    const result = verify(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /size differs|checksum differs/i);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('packaging preflight accepts complete pinned assets when available', () => {
  const root = process.env.AEGIS_TEST_LLM_ASSET_ROOT;
  if (!root) return;
  const result = verify(root);
  assert.equal(result.status, 0, result.stderr + result.stdout);
});
