const express = require('express');
const db = require('../services/database');
const { buildVlessLink, buildSsLink, generateV2raySubForUser, generateClashSubForUser, generateSingboxSubForUser, generateV2raySsSub, generateClashSsSub, generateSingboxSsSub, detectClient } = require('../utils/vless');
const { formatBytes } = require('../services/traffic');
const { requireAuth } = require('../middleware/auth');
const { subLimiter } = require('../middleware/rateLimit');
const QRCode = require('qrcode');
const { notify } = require('../services/notify');
const { getOnlineCache } = require('../services/health');
const { escapeHtml } = require('../utils/escapeHtml');
const { getClientIp } = require('../utils/clientIp');
const { appendSignature, verifySignature, getConfig: getSubSignConfig } = require('../utils/subSignature');
const { dateKeyInTimeZone, toSqlUtc, formatDateTimeInTimeZone } = require('../utils/time');
const { createSubGuard } = require('../services/subGuard');

// 模块级缓存（替代 global 变量）
const _abuseCache = new Map();



const router = express.Router();

// ========== 订阅接口内存缓存 ==========
const _subCache = new Map(); // token -> { data, headers, ts }
const SUB_CACHE_TTL = 60000; // 60秒缓存
const SUB_CACHE_MAX_ENTRIES = 2000;
const ABUSE_CACHE_TTL_MS = 3600000;
const ABUSE_CACHE_MAX_ENTRIES = 5000;

const DEFAULT_SUB_UA_ALLOWLIST = [
  'clash',
  'clash-meta',
  'mihomo',
  'stash',
  'sing-box',
  'singbox',
  'sfa',
  'sfi',
  'v2rayn',
  'v2rayng',
  'shadowrocket',
  'quantumult',
  'surfboard',
  'nekoray',
];
const subGuard = createSubGuard({
  mode: process.env.SUB_CLIENT_FILTER_MODE || 'off',
  uaAllowlist: process.env.SUB_UA_ALLOWLIST || '',
  defaultAllowlist: DEFAULT_SUB_UA_ALLOWLIST,
  tokenWindowMs: process.env.SUB_TOKEN_WINDOW_MS || '60000',
  tokenMaxReq: process.env.SUB_TOKEN_MAX_REQ || '20',
  tokenBanMs: process.env.SUB_TOKEN_BAN_MS || '900000',
  behaviorWindowMs: process.env.SUB_BEHAVIOR_WINDOW_MS || '120000',
  behaviorMaxIps: process.env.SUB_BEHAVIOR_MAX_IPS || '6',
  behaviorMaxUas: process.env.SUB_BEHAVIOR_MAX_UAS || '4',
});
const subSignConfig = getSubSignConfig();

function invalidateSubCache(token) {
  if (token) _subCache.delete(token);
  else _subCache.clear();
}

function setSubCache(cacheKey, value) {
  if (!_subCache.has(cacheKey) && _subCache.size >= SUB_CACHE_MAX_ENTRIES) {
    let oldestKey = null;
    let oldestTs = Infinity;
    for (const [key, entry] of _subCache) {
      const ts = Number(entry?.ts || 0);
      if (ts < oldestTs) {
        oldestTs = ts;
        oldestKey = key;
      }
    }
    if (oldestKey) _subCache.delete(oldestKey);
  }
  _subCache.set(cacheKey, value);
}

function cleanupAbuseCache(now = Date.now()) {
  for (const [k, ts] of _abuseCache) {
    if (now - ts > ABUSE_CACHE_TTL_MS) _abuseCache.delete(k);
  }
  if (_abuseCache.size <= ABUSE_CACHE_MAX_ENTRIES) return;
  const sorted = [..._abuseCache.entries()].sort((a, b) => a[1] - b[1]);
  const removeCount = _abuseCache.size - ABUSE_CACHE_MAX_ENTRIES;
  for (let i = 0; i < removeCount; i++) {
    _abuseCache.delete(sorted[i][0]);
  }
}

function getUserNodeUuidMap(userId, nodes) {
  const map = new Map();
  const existing = db.getUserAllNodeUuids(userId);
  for (const row of existing) {
    if (row && row.node_id != null && row.uuid) {
      map.set(Number(row.node_id), row.uuid);
    }
  }
  // 极端情况下补齐缺失映射（并写库）
  for (const n of nodes) {
    if (!map.has(Number(n.id))) {
      const row = db.getUserNodeUuid(userId, n.id);
      if (row?.uuid) map.set(Number(n.id), row.uuid);
    }
  }
  return map;
}

function applySubGuards(token, ua, clientIP) {
  const result = subGuard.apply(token, ua, clientIP);
  if (result.reason === 'unknown_ua_observe' && result.shouldLogUnknownUa) {
      db.addAuditLog(null, 'sub_unknown_ua', `未知客户端 UA: ${String(ua || '').slice(0, 180)} token:${token.slice(0, 8)} ip:${clientIP}`, clientIP);
  }
  return result;
}

function buildSubUrl(req, token, scope = 'sub') {
  const path = scope === 'sub6' ? `/sub6/${token}` : `/sub/${token}`;
  const base = `${req.protocol}://${req.get('host')}${path}`;
  return appendSignature(base, token, scope);
}

function readSubSignatureFromQuery(req) {
  const raw = req.query?.[subSignConfig.paramName];
  if (Array.isArray(raw)) return String(raw[0] || '');
  return String(raw || '');
}

function resolveSubUserIdByToken(token) {
  const user = db.getUserBySubToken(token);
  return user?.id || null;
}

function logSubAccessEventSafe(input = {}) {
  try {
    db.logSubAccessEvent({
      userId: input.userId || null,
      tokenPrefix: String(input.token || '').slice(0, 8),
      route: input.route || 'sub',
      result: input.result || 'allow',
      reason: input.reason || 'ok',
      ip: input.ip || '',
      ua: input.ua || '',
      clientType: input.clientType || '',
      httpStatus: input.httpStatus || 200,
    });
  } catch (_) {}
}

// 首页 - 节点列表（每个用户看到自己的 UUID）
function getNowShanghaiParts(date = new Date()) {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  });
  const p = Object.fromEntries(fmt.formatToParts(date).filter(x => x.type !== 'literal').map(x => [x.type, x.value]));
  return {
    year: parseInt(p.year), month: parseInt(p.month), day: parseInt(p.day),
    hour: parseInt(p.hour), minute: parseInt(p.minute), second: parseInt(p.second)
  };
}

function shanghaiToUtcMs(year, month, day, hour = 0, minute = 0, second = 0) {
  // 上海固定 UTC+8
  return Date.UTC(year, month - 1, day, hour - 8, minute, second);
}

function nextUuidResetAtMs(now = new Date()) {
  const n = getNowShanghaiParts(now);
  const today3 = shanghaiToUtcMs(n.year, n.month, n.day, 3, 0, 0);
  if (now.getTime() < today3) return today3;
  const t = new Date(shanghaiToUtcMs(n.year, n.month, n.day, 12, 0, 0));
  t.setUTCDate(t.getUTCDate() + 1);
  const y = getNowShanghaiParts(t);
  return shanghaiToUtcMs(y.year, y.month, y.day, 3, 0, 0);
}

function nextTokenResetAtMs(user, now = new Date()) {
  // 根据用户等级计算下次订阅重置时间
  const level = user.trust_level || 0;

  // Lv4 不重置
  if (level >= 4) return -1;

  // Lv3：月初重置
  if (level >= 3) {
    const n = getNowShanghaiParts(now);
    // 下个月1号 03:00
    let nextMonth = n.month + 1;
    let nextYear = n.year;
    if (nextMonth > 12) { nextMonth = 1; nextYear++; }
    return shanghaiToUtcMs(nextYear, nextMonth, 1, 3, 0, 0);
  }

  // Lv0-1: 7天, Lv2: 15天
  const interval = level >= 2 ? 15 : 7;
  const last = user.last_token_reset || '2000-01-01';
  const [y,m,d] = String(last).split('-').map(v => parseInt(v));
  if (!y || !m || !d) return nextUuidResetAtMs(now);
  const last3 = shanghaiToUtcMs(y, m, d, 3, 0, 0);
  let next = new Date(last3);
  next.setUTCDate(next.getUTCDate() + interval);
  // 如果算出来的时间已过期，往前推到下一个周期
  while (next.getTime() < now.getTime()) {
    next.setUTCDate(next.getUTCDate() + interval);
  }
  return next.getTime();
}

router.get('/', requireAuth, (req, res) => {
  const isVip = db.isInWhitelist(req.user.nodeloc_id);
  const user = req.user;

  // 0级用户显示升级提示
  if (!isVip && user.trust_level < 1) {
    return res.render('upgrade', { user });
  }

  const nodes = db.getAllNodes(true).filter(n => isVip || req.user.trust_level >= (n.min_level || 0));

  const traffic = db.getUserTraffic(user.id);
  const globalTraffic = db.getGlobalTraffic();
  const uuidMap = getUserNodeUuidMap(user.id, nodes);

  const userNodes = nodes.map(n => {
    const userUuid = uuidMap.get(Number(n.id)) || '';
    return { ...n, link: n.protocol === 'ss' ? buildSsLink(n, userUuid) : buildVlessLink(n, userUuid) };
  });

  // 查询节点 AI 操作标签
  const nodeAiTags = {};
  try {
    const d = db.getDb();
    const deployNodes = d.prepare("SELECT DISTINCT detail FROM audit_log WHERE action = 'deploy'").all();
    deployNodes.forEach(r => {
      // detail 格式通常含节点名
      const match = (r.detail || '').match(/节点.*?[:：]\s*(.+)/);
      if (match) nodeAiTags[match[1]] = nodeAiTags[match[1]] || [];
    });
    const sevenDaysAgo = toSqlUtc(new Date(Date.now() - 7 * 86400000));
    const swapNodes = d.prepare(`
      SELECT DISTINCT detail FROM audit_log
      WHERE action IN ('auto_swap_ip','swap_ip','ip_rotated') AND created_at > ?
    `).all(sevenDaysAgo);
    // 标记所有节点
    nodes.forEach(n => {
      const tags = [];
      const swapMatch = swapNodes.some(r => (r.detail || '').includes(n.name) || (r.detail || '').includes(n.host));
      if (swapMatch) tags.push('ai_swap');
      if (tags.length) nodeAiTags[n.id] = tags;
    });
  } catch (_) {}

  res.render('panel', {
    user, userNodes, traffic, globalTraffic, formatBytes,
    trafficLimit: user.traffic_limit || 0,
    nodeAiTags,
    subUrl: buildSubUrl(req, user.sub_token, 'sub'),
    subUrl6: buildSubUrl(req, user.sub_token, 'sub6'),
    nextUuidResetAt: nextUuidResetAtMs(),
    nextSubResetAt: nextTokenResetAtMs(user),
    announcement: db.getSetting('announcement') || '',
    expiresAt: user.expires_at || null,
  });
});

// ========== 蜜桃酱 AI 运维状态 API ==========
router.get('/api/peach-status', requireAuth, (req, res) => {
  try {
    const d = db.getDb();
    const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');

    const todayStats = d.prepare(`
      SELECT
        COUNT(*) FILTER (WHERE action LIKE '%patrol%' OR action = 'health_check') as patrols,
        COUNT(*) FILTER (WHERE action IN ('auto_swap_ip','swap_ip','ip_rotated')) as swaps,
        COUNT(*) FILTER (WHERE action IN ('auto_repair','node_recovered')) as fixes
      FROM audit_log WHERE date(created_at) = ?
    `).get(today) || { patrols: 0, swaps: 0, fixes: 0 };

    const totalStats = d.prepare(`
      SELECT
        COUNT(*) FILTER (WHERE action LIKE '%patrol%' OR action = 'health_check') as patrols,
        COUNT(*) FILTER (WHERE action IN ('auto_swap_ip','swap_ip','ip_rotated')) as swaps,
        COUNT(*) FILTER (WHERE action IN ('auto_repair','node_recovered')) as fixes
      FROM audit_log
    `).get() || { patrols: 0, swaps: 0, fixes: 0 };

    const lastPatrol = db.getSetting('ops_last_patrol') || '';
    const nodes = db.getAllNodes(true);
    const onlineCount = nodes.filter(n => n.agent_last_report && (Date.now() - new Date(n.agent_last_report).getTime()) < 120000).length;
    const totalActive = nodes.length;

    // 最早审计记录算运行天数
    const firstLog = d.prepare("SELECT created_at FROM audit_log ORDER BY created_at ASC LIMIT 1").get();
    const uptimeDays = firstLog ? Math.max(1, Math.ceil((Date.now() - new Date(firstLog.created_at).getTime()) / 86400000)) : 1;

    const recentEvents = d.prepare(`
      SELECT action, detail, created_at FROM audit_log
      WHERE action IN ('health_check','auto_swap_ip','swap_ip','ip_rotated','node_recovered','auto_repair','deploy','node_blocked','node_xray_down')
      ORDER BY created_at DESC LIMIT 5
    `).all();

    res.json({
      online: true,
      lastPatrol,
      lastPatrolDisplay: formatDateTimeInTimeZone(lastPatrol, 'Asia/Shanghai'),
      todayPatrols: todayStats.patrols,
      todaySwaps: todayStats.swaps,
      todayFixes: todayStats.fixes,
      totalPatrols: totalStats.patrols,
      totalSwaps: totalStats.swaps,
      totalFixes: totalStats.fixes,
      uptimeDays,
      nodeAvailability: totalActive > 0 ? Math.round(onlineCount / totalActive * 100) : 100,
      nodesOnline: onlineCount,
      nodesTotal: totalActive,
      recentEvents: recentEvents.map(e => ({
        action: escapeHtml(e.action),
        detail: escapeHtml((e.detail || '').slice(0, 80)),
        time: formatDateTimeInTimeZone(e.created_at, 'Asia/Shanghai')
      }))
    });
  } catch (err) {
    res.json({ online: false, error: err.message });
  }
});

// 当前登录用户订阅二维码（便于手机扫码）
router.get('/sub-qr', requireAuth, async (req, res) => {
  try {
    const subUrl = buildSubUrl(req, req.user.sub_token, 'sub');
    const png = await QRCode.toBuffer(subUrl, {
      width: 300,
      margin: 1,
      errorCorrectionLevel: 'M'
    });
    res.set({
      'Content-Type': 'image/png',
      'Cache-Control': 'no-store'
    });
    res.send(png);
  } catch (e) {
    console.error('[二维码] 生成失败:', e.message);
    res.status(500).send('二维码生成失败');
  }
});

// IPv6 订阅二维码
router.get('/sub6-qr', requireAuth, async (req, res) => {
  try {
    const subUrl6 = buildSubUrl(req, req.user.sub_token, 'sub6');
    const png = await QRCode.toBuffer(subUrl6, {
      width: 300,
      margin: 1,
      errorCorrectionLevel: 'M'
    });
    res.set({
      'Content-Type': 'image/png',
      'Cache-Control': 'no-store'
    });
    res.send(png);
  } catch (e) {
    console.error('[二维码] IPv6生成失败:', e.message);
    res.status(500).send('二维码生成失败');
  }
});

// 订阅接口（每个用户返回自己的 UUID）
router.get('/sub/:token', subLimiter, (req, res) => {
  const token = req.params.token;
  const ua = req.headers['user-agent'] || '';
  const clientIP = getClientIp(req);
  const forceType = req.query.type;
  const clientType = forceType || detectClient(ua);
  const eventBase = { token, route: 'sub', ip: clientIP, ua, clientType };
  const sig = readSubSignatureFromQuery(req);
  const sigGuard = verifySignature(token, sig, 'sub');
  if (!sigGuard.ok) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: sigGuard.reason || 'signature_invalid',
      httpStatus: sigGuard.status || 403,
    });
    return res.status(sigGuard.status).type('text').send(sigGuard.message);
  }
  if (sigGuard.shouldLog) {
    db.addAuditLog(null, 'sub_sig_observe', `签名异常已放行 token:${token.slice(0, 8)} ip:${clientIP}`, clientIP);
  }

  // 拒绝空 UA 请求（防止订阅聚合/转换工具拉取）
  if (!ua.trim()) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: 'empty_ua',
      httpStatus: 403,
    });
    return res.status(403).type('text').send('User-Agent is required');
  }
  const cacheKey = `${token}:${clientType}`;

  // 记录拉取 IP（始终执行，不受缓存影响）
  const guard = applySubGuards(token, ua, clientIP);
  if (!guard.ok) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: guard.reason || 'guard_blocked',
      httpStatus: guard.status || 429,
    });
    return res.status(guard.status).type('text').send(guard.message);
  }

  let allowReason = 'ok';
  if (sigGuard.reason && sigGuard.reason !== 'signature_ok' && sigGuard.reason !== 'signature_off') {
    allowReason = sigGuard.reason;
  }
  if (guard.reason && guard.reason !== 'ok') {
    allowReason = guard.reason;
  }

  // 检查缓存
  const cached = _subCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < SUB_CACHE_TTL) {
    // 异步记录访问日志
    const user = db.getUserBySubToken(token);
    if (user) {
      db.logSubAccess(user.id, clientIP, ua);
    }
    logSubAccessEventSafe({
      ...eventBase,
      userId: user?.id || null,
      result: 'allow',
      reason: allowReason === 'ok' ? 'ok_cache' : `${allowReason}_cache`,
      httpStatus: 200,
    });
    res.set(cached.headers);
    return res.send(cached.body);
  }

  const user = db.getUserBySubToken(token);
  if (!user) {
    logSubAccessEventSafe({
      ...eventBase,
      result: 'deny',
      reason: 'invalid_token',
      httpStatus: 403,
    });
    return res.status(403).send('无效的订阅链接');
  }
  if (user.trust_level < 1 && !db.isInWhitelist(user.nodeloc_id)) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'deny',
      reason: 'level_not_allowed',
      httpStatus: 403,
    });
    return res.status(403).send('账号等级不足，请在 NodeLoc 论坛升级到1级后使用');
  }

  db.logSubAccess(user.id, clientIP, ua);

  // 滥用检测：24h 内 ≥20 个不同 IP 触发通知（同一用户1小时内只通知一次）
  const ips = db.getSubAccessIPs(user.id, 24);
  if (ips.length >= 20) {
    
    const now = Date.now();
    const last = _abuseCache.get(user.id) || 0;
    if (now - last > 3600000) {
      _abuseCache.set(user.id, now);
      cleanupAbuseCache(now);
      
      notify.abuse(user.username, ips.length);
    }
  }

  const isVip = db.isInWhitelist(user.nodeloc_id);
  const nodes = db.getAllNodes(true).filter(n => (isVip || user.trust_level >= (n.min_level || 0)) && n.protocol !== 'ss');
  const uuidMap = getUserNodeUuidMap(user.id, nodes);

  // 获取用户在每个节点的 UUID
  const userNodes = nodes.map(n => {
    const uuid = uuidMap.get(Number(n.id));
    return { ...n, uuid: uuid || '' };
  });

  // 获取用户流量用于 Subscription-Userinfo
  const traffic = db.getUserTraffic(user.id);
  const trafficLimit = user.traffic_limit || 0;
  const totalBytes = trafficLimit > 0 ? trafficLimit : 1125899906842624; // 默认 1PB
  const exceeded = trafficLimit > 0 && (traffic.total_up + traffic.total_down) >= trafficLimit;

  db.addAuditLog(user.id, 'sub_fetch', `订阅拉取 [${clientType}] IP: ${clientIP}`, clientIP);

  // 流量超额则返回空节点列表
  const finalNodes = exceeded ? [] : userNodes;
  const subInfo = `upload=${traffic.total_up}; download=${traffic.total_down}; total=${totalBytes}; expire=0`;
  const finalAllowReason = allowReason === 'ok'
    ? (exceeded ? 'ok_exceeded' : 'ok')
    : `${allowReason}${exceeded ? '_exceeded' : ''}`;

  const panelName = encodeURIComponent('小姨子的诱惑');

  if (clientType === 'clash') {
    const headers = {
      'Content-Type': 'text/yaml; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Profile-Update-Interval': '6',
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateClashSubForUser(finalNodes);
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    return res.send(body);
  }

  if (clientType === 'singbox') {
    const headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateSingboxSubForUser(finalNodes);
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    return res.send(body);
  }

  {
    const headers = {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateV2raySubForUser(finalNodes, { upload: traffic.total_up, download: traffic.total_down, total: totalBytes });
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    res.send(body);
  }
});

// ========== IPv6 Shadowsocks 订阅接口 ==========
router.get('/sub6/:token', subLimiter, (req, res) => {
  const token = req.params.token;
  const ua = req.headers['user-agent'] || '';
  const clientIP = getClientIp(req);
  const forceType = req.query.type;
  const clientType = forceType || detectClient(ua);
  const eventBase = { token, route: 'sub6', ip: clientIP, ua, clientType };
  const sig = readSubSignatureFromQuery(req);
  const sigGuard = verifySignature(token, sig, 'sub6');
  if (!sigGuard.ok) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: sigGuard.reason || 'signature_invalid',
      httpStatus: sigGuard.status || 403,
    });
    return res.status(sigGuard.status).type('text').send(sigGuard.message);
  }
  if (sigGuard.shouldLog) {
    db.addAuditLog(null, 'sub6_sig_observe', `签名异常已放行 token:${token.slice(0, 8)} ip:${clientIP}`, clientIP);
  }

  // 拒绝空 UA 请求
  if (!ua.trim()) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: 'empty_ua',
      httpStatus: 403,
    });
    return res.status(403).type('text').send('User-Agent is required');
  }

  const cacheKey = `v6:${token}:${clientType}`;
  const guard = applySubGuards(token, ua, clientIP);
  if (!guard.ok) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: resolveSubUserIdByToken(token),
      result: 'deny',
      reason: guard.reason || 'guard_blocked',
      httpStatus: guard.status || 429,
    });
    return res.status(guard.status).type('text').send(guard.message);
  }

  let allowReason = 'ok';
  if (sigGuard.reason && sigGuard.reason !== 'signature_ok' && sigGuard.reason !== 'signature_off') {
    allowReason = sigGuard.reason;
  }
  if (guard.reason && guard.reason !== 'ok') {
    allowReason = guard.reason;
  }

  const cached = _subCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < SUB_CACHE_TTL) {
    const user = db.getUserBySubToken(token);
    if (user) db.logSubAccess(user.id, clientIP, ua);
    logSubAccessEventSafe({
      ...eventBase,
      userId: user?.id || null,
      result: 'allow',
      reason: allowReason === 'ok' ? 'ok_cache' : `${allowReason}_cache`,
      httpStatus: 200,
    });
    res.set(cached.headers);
    return res.send(cached.body);
  }

  const user = db.getUserBySubToken(token);
  if (!user) {
    logSubAccessEventSafe({
      ...eventBase,
      result: 'deny',
      reason: 'invalid_token',
      httpStatus: 403,
    });
    return res.status(403).send('无效的订阅链接');
  }
  if (user.trust_level < 1 && !db.isInWhitelist(user.nodeloc_id)) {
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'deny',
      reason: 'level_not_allowed',
      httpStatus: 403,
    });
    return res.status(403).send('账号等级不足，请在 NodeLoc 论坛升级到1级后使用');
  }

  db.logSubAccess(user.id, clientIP, ua);

  const isVip = db.isInWhitelist(user.nodeloc_id);
  // 只取 IPv6 + SS 节点
  const rawNodes = db.getAllNodes(true).filter(n =>
    n.ip_version === 6 && n.protocol === 'ss' &&
    (isVip || user.trust_level >= (n.min_level || 0))
  );
  const uuidMap = getUserNodeUuidMap(user.id, rawNodes);

  // 为每个 SS 节点注入用户独立密码（复用 user_node_uuid 的 uuid 作为 SS 密码）
  const nodes = rawNodes.map(n => {
    const userPassword = uuidMap.get(Number(n.id)) || '';
    return { ...n, userPassword };
  });

  const traffic = db.getUserTraffic(user.id);
  const trafficLimit = user.traffic_limit || 0;
  const totalBytes = trafficLimit > 0 ? trafficLimit : 1125899906842624;
  const exceeded = trafficLimit > 0 && (traffic.total_up + traffic.total_down) >= trafficLimit;

  db.addAuditLog(user.id, 'sub6_fetch', `IPv6订阅拉取 [${clientType}] IP: ${clientIP}`, clientIP);

  const finalNodes = exceeded ? [] : nodes;
  const subInfo = `upload=${traffic.total_up}; download=${traffic.total_down}; total=${totalBytes}; expire=0`;
  const finalAllowReason = allowReason === 'ok'
    ? (exceeded ? 'ok_exceeded' : 'ok')
    : `${allowReason}${exceeded ? '_exceeded' : ''}`;
  const panelName = encodeURIComponent('小姨子的诱惑-IPv6');

  if (clientType === 'clash') {
    const headers = {
      'Content-Type': 'text/yaml; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Profile-Update-Interval': '6',
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateClashSsSub(finalNodes);
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    return res.send(body);
  }

  if (clientType === 'singbox') {
    const headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateSingboxSsSub(finalNodes);
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    return res.send(body);
  }

  {
    const headers = {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${panelName}`,
      'Subscription-Userinfo': subInfo,
      'Cache-Control': 'no-cache'
    };
    const body = generateV2raySsSub(finalNodes, { upload: traffic.total_up, download: traffic.total_down, total: totalBytes });
    setSubCache(cacheKey, { headers, body, ts: Date.now() });
    logSubAccessEventSafe({
      ...eventBase,
      userId: user.id,
      result: 'allow',
      reason: finalAllowReason,
      httpStatus: 200,
    });
    res.set(headers);
    res.send(body);
  }
});

// 在线用户数（从巡检缓存读取）
router.get('/online-count', requireAuth, (req, res) => {
  const cache = getOnlineCache();
  const summary = cache.summary || { online: 0, nodes: 0 };
  res.json(summary);
});

// 实时统计 API（前端轮询用）
router.get('/api/stats', requireAuth, (req, res) => {
  const cache = getOnlineCache();
  const summary = cache.summary || { online: 0, nodes: 0 };
  const traffic = db.getUserTraffic(req.user.id);
  const user = db.getUserById(req.user.id);
  const trafficLimit = user ? (user.traffic_limit || 0) : 0;
  const totalUsed = (traffic.total_up || 0) + (traffic.total_down || 0);
  const remaining = trafficLimit > 0 ? Math.max(0, trafficLimit - totalUsed) : -1; // -1 = unlimited
  const globalTraffic = db.getGlobalTraffic();
  res.json({
    online: summary.online || 0,
    totalUsed,
    remaining,
    trafficLimit,
    globalUp: globalTraffic.total_up || 0,
    globalDown: globalTraffic.total_down || 0,
  });
});

// Sprint 6: 用户流量使用明细 API
router.get('/api/traffic-detail', requireAuth, (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 90);
  const detail = db.getUserTrafficDaily(req.user.id, days);
  const trend = db.getUserTrafficDailyAgg(req.user.id, days);
  res.json({ ok: true, detail, trend });
});

module.exports = router;
