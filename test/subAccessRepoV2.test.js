const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');

const subAccessRepo = require('../src/services/repos/subAccessRepo');

test('sub access v2 aggregates success/deny stats from event stream', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vless-sub-event-'));
  const dbPath = path.join(dir, 'panel.db');
  const db = new Database(dbPath);

  t.after(async () => {
    try { db.close(); } catch (_) {}
    await fsp.rm(dir, { recursive: true, force: true });
  });

  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL
    );
    CREATE TABLE sub_access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      ua TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE sub_access_event (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      token_prefix TEXT DEFAULT '',
      route TEXT DEFAULT 'sub',
      result TEXT NOT NULL DEFAULT 'allow',
      reason TEXT DEFAULT 'ok',
      ip TEXT DEFAULT '',
      ua TEXT DEFAULT '',
      client_type TEXT DEFAULT '',
      http_status INTEGER DEFAULT 200,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  db.prepare(`INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'bob')`).run();

  subAccessRepo.init({ getDb: () => db });

  subAccessRepo.logSubAccessEvent({
    userId: 1,
    tokenPrefix: 'tok-a',
    route: 'sub',
    result: 'allow',
    reason: 'ok',
    ip: '1.1.1.1',
    ua: 'clash',
    clientType: 'clash',
    httpStatus: 200,
  });
  subAccessRepo.logSubAccessEvent({
    userId: 1,
    tokenPrefix: 'tok-a',
    route: 'sub',
    result: 'deny',
    reason: 'unknown_ua',
    ip: '1.1.1.2',
    ua: 'Mozilla/5.0',
    clientType: 'v2ray',
    httpStatus: 403,
  });
  subAccessRepo.logSubAccessEvent({
    userId: 1,
    tokenPrefix: 'tok-a',
    route: 'sub',
    result: 'deny',
    reason: 'unknown_ua',
    ip: '1.1.1.3',
    ua: 'curl/8.0',
    clientType: 'v2ray',
    httpStatus: 403,
  });
  subAccessRepo.logSubAccessEvent({
    userId: 1,
    tokenPrefix: 'tok-a',
    route: 'sub6',
    result: 'allow',
    reason: 'ok_cache',
    ip: '1.1.1.1',
    ua: 'clash',
    clientType: 'clash',
    httpStatus: 200,
  });
  subAccessRepo.logSubAccessEvent({
    userId: 2,
    tokenPrefix: 'tok-b',
    route: 'sub',
    result: 'allow',
    reason: 'ok',
    ip: '2.2.2.2',
    ua: 'clash',
    clientType: 'clash',
    httpStatus: 200,
  });

  const overview = subAccessRepo.getSubEventOverview(24);
  assert.equal(overview.total_requests, 5);
  assert.equal(overview.allow_requests, 3);
  assert.equal(overview.deny_requests, 2);
  assert.equal(overview.user_count, 2);
  assert.equal(overview.denied_user_count, 1);
  assert.equal(overview.deny_reasons[0].reason, 'unknown_ua');
  assert.equal(overview.deny_reasons[0].count, 2);

  const stats = subAccessRepo.getSubAccessStatsV2(24, 20, 0, false, 'request');
  assert.equal(stats.total, 2);
  const alice = stats.data.find((r) => r.user_id === 1);
  assert.ok(alice);
  assert.equal(alice.request_count, 4);
  assert.equal(alice.ok_count, 2);
  assert.equal(alice.deny_count, 2);
  assert.equal(alice.ip_count, 3);
  assert.equal(alice.top_deny_reason, 'unknown_ua');

  const detail = subAccessRepo.getSubAccessUserDetailV2(1, 24);
  assert.equal(detail.summary.request_count, 4);
  assert.equal(detail.summary.ok_count, 2);
  assert.equal(detail.summary.deny_count, 2);
  assert.equal(detail.reasons[0].reason, 'unknown_ua');
  assert.equal(detail.reasons[0].count, 2);
  assert.ok(detail.routes.some((r) => r.route === 'sub6'));
  assert.ok(detail.timeline.length >= 1);
});
