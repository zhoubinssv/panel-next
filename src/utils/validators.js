const net = require('net');
const HOST_RE = /^[a-zA-Z0-9._-]{1,253}$/;

function parseIntId(raw) {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function isValidHost(host) {
  if (typeof host !== 'string') return false;
  const value = host.trim();
  if (!value) return false;

  // 兼容 IPv4 / IPv6
  if (net.isIP(value)) return true;

  // 兼容域名/主机名
  return HOST_RE.test(value);
}

module.exports = {
  parseIntId,
  isValidHost,
};
