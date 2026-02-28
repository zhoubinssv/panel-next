const crypto = require('crypto');
const { safeTokenEqual } = require('./securityTokens');

const DEFAULT_MODE = 'off';
const DEFAULT_PARAM = 'sig';
const ALLOWED_MODES = new Set(['off', 'observe', 'enforce']);

function normalizeMode(rawMode) {
  const mode = String(rawMode || DEFAULT_MODE).trim().toLowerCase();
  return ALLOWED_MODES.has(mode) ? mode : DEFAULT_MODE;
}

function normalizeParamName(rawName) {
  const s = String(rawName || DEFAULT_PARAM).trim();
  return /^[a-zA-Z0-9_]{1,32}$/.test(s) ? s : DEFAULT_PARAM;
}

function getConfig(env = process.env) {
  return {
    mode: normalizeMode(env.SUB_LINK_SIGN_MODE),
    secret: String(env.SUB_LINK_SIGN_SECRET || env.SESSION_SECRET || ''),
    paramName: normalizeParamName(env.SUB_LINK_SIGN_PARAM),
  };
}

function createSignature(token, scope = 'sub', env = process.env) {
  const { secret } = getConfig(env);
  if (!secret) return '';
  return crypto
    .createHmac('sha256', secret)
    .update(`${scope}:${String(token || '')}`)
    .digest('hex');
}

function appendSignature(rawUrl, token, scope = 'sub', env = process.env) {
  const cfg = getConfig(env);
  if (cfg.mode === 'off') return rawUrl;
  const sig = createSignature(token, scope, env);
  if (!sig) return rawUrl;

  const isAbsolute = /^https?:\/\//i.test(String(rawUrl || ''));
  const base = isAbsolute ? undefined : 'http://local-sign';
  const u = new URL(rawUrl, base);
  u.searchParams.set(cfg.paramName, sig);
  return isAbsolute ? u.toString() : `${u.pathname}${u.search}${u.hash}`;
}

function verifySignature(token, inputSig, scope = 'sub', env = process.env) {
  const cfg = getConfig(env);
  if (cfg.mode === 'off') return { ok: true, reason: 'signature_off' };

  if (!cfg.secret) {
    if (cfg.mode === 'enforce') {
      return { ok: false, status: 500, message: '订阅签名配置错误', reason: 'signature_secret_missing' };
    }
    return { ok: true, reason: 'signature_secret_missing_observe', shouldLog: true };
  }

  const expected = createSignature(token, scope, env);
  const ok = safeTokenEqual(String(inputSig || ''), expected);
  if (ok) return { ok: true, reason: 'signature_ok' };

  if (cfg.mode === 'enforce') {
    return { ok: false, status: 403, message: '订阅签名无效', reason: 'signature_invalid' };
  }
  return { ok: true, reason: 'signature_invalid_observe', shouldLog: true };
}

module.exports = {
  createSignature,
  appendSignature,
  verifySignature,
  getConfig,
};
