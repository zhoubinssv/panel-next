const test = require('node:test');
const assert = require('node:assert/strict');
const { getClientIp, normalizeIp, parseIpAllowlist, isIpAllowed } = require('../src/utils/clientIp');

test('normalizeIp strips IPv4-mapped IPv6 prefix', () => {
  assert.equal(normalizeIp('::ffff:203.0.113.7'), '203.0.113.7');
});

test('parseIpAllowlist parses comma separated list', () => {
  const list = parseIpAllowlist(' 127.0.0.1, ::ffff:10.0.0.2 , 2001:db8::1 ');
  assert.deepEqual(list, ['127.0.0.1', '10.0.0.2', '2001:db8::1']);
});

test('isIpAllowed handles empty and explicit allowlist', () => {
  assert.equal(isIpAllowed('203.0.113.8', []), true);
  assert.equal(isIpAllowed('203.0.113.8', ['203.0.113.8']), true);
  assert.equal(isIpAllowed('203.0.113.8', ['198.51.100.9']), false);
});

test('getClientIp returns req.ip for express request', () => {
  const req = { ip: '198.51.100.7', headers: { 'x-forwarded-for': '203.0.113.9' } };
  assert.equal(getClientIp(req), '198.51.100.7');
});

test('getClientIp trusts forwarded headers only from local/private proxy hop', () => {
  const req = {
    connection: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': '203.0.113.9, 10.0.0.2' },
  };
  assert.equal(getClientIp(req), '203.0.113.9');
});

test('getClientIp ignores spoofed forwarded headers on public direct connection', () => {
  const req = {
    connection: { remoteAddress: '198.51.100.20' },
    headers: { 'x-forwarded-for': '203.0.113.9' },
  };
  assert.equal(getClientIp(req), '198.51.100.20');
});
