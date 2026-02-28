const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createSignature,
  appendSignature,
  verifySignature,
  getConfig,
} = require('../src/utils/subSignature');

function buildEnv(overrides = {}) {
  return {
    SESSION_SECRET: 'session-secret',
    SUB_LINK_SIGN_MODE: 'off',
    SUB_LINK_SIGN_SECRET: '',
    SUB_LINK_SIGN_PARAM: 'sig',
    ...overrides,
  };
}

test('createSignature is deterministic for same token and scope', () => {
  const env = buildEnv({ SUB_LINK_SIGN_MODE: 'enforce', SUB_LINK_SIGN_SECRET: 'abc123' });
  const s1 = createSignature('token-a', 'sub', env);
  const s2 = createSignature('token-a', 'sub', env);
  assert.equal(s1, s2);
  assert.equal(s1.length, 64);
});

test('appendSignature appends configured query param when mode enabled', () => {
  const env = buildEnv({ SUB_LINK_SIGN_MODE: 'enforce', SUB_LINK_SIGN_SECRET: 'abc123', SUB_LINK_SIGN_PARAM: 'sk' });
  const signed = appendSignature('https://panel.example/sub/t1', 't1', 'sub', env);
  assert.match(signed, /[?&]sk=[a-f0-9]{64}/);
});

test('verifySignature enforce mode rejects invalid and accepts valid signature', () => {
  const env = buildEnv({ SUB_LINK_SIGN_MODE: 'enforce', SUB_LINK_SIGN_SECRET: 'abc123' });
  const sig = createSignature('token-b', 'sub', env);
  const ok = verifySignature('token-b', sig, 'sub', env);
  assert.equal(ok.ok, true);

  const bad = verifySignature('token-b', 'deadbeef', 'sub', env);
  assert.equal(bad.ok, false);
  assert.equal(bad.status, 403);
});

test('verifySignature observe mode allows invalid signature with log hint', () => {
  const env = buildEnv({ SUB_LINK_SIGN_MODE: 'observe', SUB_LINK_SIGN_SECRET: 'abc123' });
  const r = verifySignature('token-c', 'deadbeef', 'sub', env);
  assert.equal(r.ok, true);
  assert.equal(r.shouldLog, true);
});

test('getConfig sanitizes invalid query param name', () => {
  const env = buildEnv({ SUB_LINK_SIGN_PARAM: 'bad-param!' });
  const cfg = getConfig(env);
  assert.equal(cfg.paramName, 'sig');
});
