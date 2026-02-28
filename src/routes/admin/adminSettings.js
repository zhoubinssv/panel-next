const express = require('express');
const db = require('../../services/database');
const { notify } = require('../../services/notify');
const { syncAllNodesConfig } = require('../../services/deploy');
const { escapeHtml } = require('../../utils/escapeHtml');
const { dateKeyInTimeZone, formatDateTimeInTimeZone, parseDateInput } = require('../../utils/time');
const { parseIntId } = require('../../utils/validators');

const router = express.Router();

// 日志
router.get('/logs', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const type = req.query.type || 'all';
  const limit = 50;
  const offset = (page - 1) * limit;
  const data = db.getAuditLogs(limit, offset, type);
  // 服务端转义 detail/action 防注入
  if (data.rows) {
    data.rows = data.rows.map(r => ({
      ...r,
      action: escapeHtml(r.action),
      detail: escapeHtml(r.detail),
      username: escapeHtml(r.username),
      created_at_display: formatDateTimeInTimeZone(r.created_at, 'Asia/Shanghai'),
    }));
  }
  const pages = Math.max(1, Math.ceil((data.total || 0) / limit));
  res.json({ ...data, page, limit, pages });
});

router.post('/logs/clear', (req, res) => {
  db.clearAuditLogs();
  db.addAuditLog(req.user.id, 'logs_clear', '清空日志', req.clientIp || req.ip);
  res.json({ ok: true });
});

// 通知
router.post('/notify/config', (req, res) => {
  const { token, chatId } = req.body;
  if (token) db.setSetting('tg_bot_token', token);
  if (chatId) db.setSetting('tg_chat_id', chatId);
  res.json({ ok: true });
});

router.post('/notify/test', async (req, res) => {
  try {
    const { send } = require('../../services/notify');
    await send('🔔 测试通知 - 来自小姨子の后台');
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

router.post('/notify/event', (req, res) => {
  const { key, enabled } = req.body;
  if (key && key.startsWith('tg_on_')) {
    db.setSetting(key, enabled ? 'true' : 'false');
  }
  res.json({ ok: true });
});

// 公告 & 限制
router.post('/announcement', (req, res) => {
  db.setSetting('announcement', req.body.text || '');
  res.json({ ok: true });
});

router.post('/max-users', (req, res) => {
  db.setSetting('max_users', String(parseInt(req.body.max) || 0));
  res.json({ ok: true });
});

// 订阅访问
router.get('/sub-access/:userId', (req, res) => {
  const userId = parseIntId(req.params.userId);
  if (!userId) return res.status(400).json({ error: '参数错误' });
  const hours = parseInt(req.query.hours) || 24;
  const rows = db.getSubAccessIPs(userId, hours).map((r) => ({
    ...r,
    last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
  }));
  res.json(rows);
});

// 订阅统计
router.get('/sub-stats', (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  const page = parseInt(req.query.page) || 1;
  const sortRaw = String(req.query.sort || 'request');
  const onlyHigh = req.query.high === '1';
  const limit = 20;
  const offset = (page - 1) * limit;
  const sortMap = {
    count: 'request',
    request: 'request',
    success: 'success',
    deny: 'deny',
    ip: 'ip',
    ua: 'ua',
    last: 'last',
    ok_rate: 'ok_rate',
  };
  const sort = sortMap[sortRaw] || 'request';

  const data = db.getSubAccessStatsV2(hours, limit, offset, onlyHigh, sort);
  const hasV2Data = (data.total || 0) > 0;
  if (hasV2Data && Array.isArray(data.data)) {
    data.data = data.data.map((r) => ({
      ...r,
      last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
      source: 'event',
    }));
  }

  if (hasV2Data) {
    const pages = Math.max(1, Math.ceil((data.total || 0) / limit));
    return res.json({ ...data, page, limit, pages, source: 'event' });
  }

  // 兼容旧数据：若新事件表暂无数据，回退到 sub_access_log 统计
  const legacySort = sortRaw === 'ip' ? 'ip' : (sortRaw === 'last' ? 'last' : 'count');
  const legacy = db.getSubAccessStats(hours, limit, offset, onlyHigh, legacySort);
  if (Array.isArray(legacy.data)) {
    legacy.data = legacy.data.map((r) => ({
      ...r,
      request_count: r.pull_count || 0,
      ok_count: r.pull_count || 0,
      deny_count: 0,
      ok_rate: r.pull_count > 0 ? 100 : 0,
      deny_rate: 0,
      deny_ratio: 0,
      ua_count: 0,
      top_deny_reason: '',
      source: 'legacy',
      last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
    }));
  }
  const pages = Math.max(1, Math.ceil((legacy.total || 0) / limit));
  const legacyTotalRequests = (legacy.data || []).reduce((s, x) => s + Number(x.request_count || 0), 0);
  return res.json({
    ...legacy,
    page,
    limit,
    pages,
    source: 'legacy',
    overview: {
      total_requests: legacyTotalRequests,
      allow_requests: legacyTotalRequests,
      deny_requests: 0,
      allow_rate: legacyTotalRequests > 0 ? 100 : 0,
      deny_rate: 0,
      user_count: Number(legacy.total || 0),
      denied_user_count: 0,
      deny_reasons: [],
    },
  });
});

router.get('/sub-stats/:userId/detail', (req, res) => {
  const userId = parseIntId(req.params.userId);
  if (!userId) return res.status(400).json({ error: '参数错误' });
  const hours = parseInt(req.query.hours) || 24;
  const detail = db.getSubAccessUserDetailV2(userId, hours);
  const hasV2Data = Number(detail?.summary?.request_count || 0) > 0;
  if (hasV2Data) {
    return res.json({
      ...detail,
      source: 'event',
      summary: {
        ...detail.summary,
        last_access_display: formatDateTimeInTimeZone(detail.summary?.last_access, 'Asia/Shanghai'),
      },
      ips: (detail.ips || []).map((r) => ({
        ...r,
        last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
      })),
      reasons: (detail.reasons || []).map((r) => ({
        ...r,
        last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
      })),
      timeline: (detail.timeline || []).map((r) => ({
        ...r,
        time_display: formatDateTimeInTimeZone(r.time, 'Asia/Shanghai'),
      })),
    });
  }

  // 兼容旧数据
  const legacy = db.getSubAccessUserDetail(userId, hours);
  const legacyReqCount = (legacy.ips || []).reduce((sum, r) => sum + Number(r.count || 0), 0);
  const legacyLastAccess = legacy.timeline?.[0]?.time || legacy.ips?.[0]?.last_access || null;
  return res.json({
    source: 'legacy',
    summary: {
      request_count: legacyReqCount,
      ok_count: legacyReqCount,
      deny_count: 0,
      ok_rate: legacyReqCount > 0 ? 100 : 0,
      deny_rate: 0,
      ip_count: (legacy.ips || []).length,
      ua_count: (legacy.uas || []).length,
      risk_level: 'low',
      last_access: legacyLastAccess,
      last_access_display: formatDateTimeInTimeZone(legacyLastAccess, 'Asia/Shanghai'),
    },
    ips: (legacy.ips || []).map((r) => ({
      ...r,
      ok_count: r.count || 0,
      deny_count: 0,
      last_access_display: formatDateTimeInTimeZone(r.last_access, 'Asia/Shanghai'),
    })),
    uas: (legacy.uas || []).map((r) => ({
      ...r,
      ok_count: r.count || 0,
      deny_count: 0,
    })),
    reasons: [],
    routes: [],
    timeline: (legacy.timeline || []).map((r) => ({
      ...r,
      route: String(r.ua || '').toLowerCase().includes('clash') ? 'sub' : 'sub',
      result: 'allow',
      reason: 'legacy_ok',
      http_status: 200,
      client_type: '',
      time_display: formatDateTimeInTimeZone(r.time, 'Asia/Shanghai'),
    })),
  });
});

// AI 运营日记
router.get('/diary', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const data = db.getDiaryEntries(limit, offset);
  const stats = db.getDiaryStats();
  const pages = Math.max(1, Math.ceil((data.total || 0) / limit));
  const rows = (data.rows || []).map((entry) => {
    const dt = formatDateTimeInTimeZone(entry.created_at, 'Asia/Shanghai');
    const [date = '', time = ''] = dt.split(' ');
    const weekday = entry.created_at
      ? new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', weekday: 'short' }).format(parseDateInput(entry.created_at))
      : '';
    return {
      ...entry,
      created_at_display: dt,
      created_date_display: date,
      created_time_display: time,
      created_weekday_display: weekday,
    };
  });
  res.json({
    ...data,
    rows,
    page,
    limit,
    pages,
    stats: {
      ...stats,
      firstEntryDisplay: formatDateTimeInTimeZone(stats.firstEntry, 'Asia/Shanghai'),
    },
  });
});

// AI 运维配置
router.get('/ops-config', (req, res) => {
  const keys = ['ops_target_nodes', 'ops_patrol_interval', 'ops_max_daily_swaps', 'ops_max_daily_creates',
    'ops_auto_swap_ip', 'ops_auto_repair', 'ops_auto_scale', 'ops_panel_guard'];
  const cfg = {};
  for (const k of keys) cfg[k] = db.getSetting(k) || '';
  res.json(cfg);
});

router.post('/ops-config', (req, res) => {
  const allowed = ['ops_target_nodes', 'ops_patrol_interval', 'ops_max_daily_swaps', 'ops_max_daily_creates',
    'ops_auto_swap_ip', 'ops_auto_repair', 'ops_auto_scale', 'ops_panel_guard'];
  for (const [k, v] of Object.entries(req.body)) {
    if (allowed.includes(k)) db.setSetting(k, String(v));
  }
  db.addAuditLog(req.user.id, 'ops_config', '更新 AI 运维配置', req.clientIp || req.ip);
  res.json({ ok: true });
});

// 运维仪表盘 API
router.get('/ops-dashboard', (req, res) => {
  const d = db.getDb();
  const nodes = db.getAllNodes();
  const total = nodes.length;
  const online = nodes.filter(n => n.is_active === 1 && n.fail_count === 0).length;
  const blocked = nodes.filter(n => n.fail_count >= 3).length;
  const offline = total - online;

  const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');
  const lastPatrol = db.getSetting('ops_last_patrol') || '';

  const todayStats = d.prepare(`
    SELECT
      COUNT(*) FILTER (WHERE action LIKE '%patrol%' OR action = 'health_check') as patrols,
      COUNT(*) FILTER (WHERE action IN ('auto_swap_ip', 'swap_ip', 'ip_rotated')) as swaps,
      COUNT(*) FILTER (WHERE action IN ('auto_repair', 'node_recovered')) as fixes
    FROM audit_log WHERE date(created_at) = ?
  `).get(today) || { patrols: 0, swaps: 0, fixes: 0 };

  res.json({
    total,
    online,
    offline,
    blocked,
    lastPatrol,
    lastPatrolDisplay: formatDateTimeInTimeZone(lastPatrol, 'Asia/Shanghai'),
    todayStats,
  });
});

router.get('/ops-events', (req, res) => {
  const d = db.getDb();
  const limit = parseInt(req.query.limit) || 30;
  // 合并 audit_log 运维事件 + ops_diagnosis 诊断记录
  const auditEvents = d.prepare(`
    SELECT id, action, detail, created_at, 'audit' as source FROM audit_log
    WHERE action IN ('node_blocked','auto_swap_ip','auto_swap_ip_start','auto_swap_ip_ok','auto_swap_ip_fail',
      'swap_ip','ip_rotated','node_recovered','deploy','health_check','auto_repair','ops_config',
      'node_create','node_delete','patrol','instance_create','instance_terminate','xray_restart',
      'node_xray_down','node_auto_remove_manual','traffic_exceed')
    ORDER BY created_at DESC LIMIT ?
  `).all(limit);
  const diagEvents = d.prepare(`
    SELECT d.id, d.status, d.diag_info, d.ai_analysis, d.created_at, d.resolved_at,
           n.name as node_name, 'diagnosis' as source
    FROM ops_diagnosis d LEFT JOIN nodes n ON d.node_id = n.id
    ORDER BY d.created_at DESC LIMIT ?
  `).all(limit);
  // 合并并按时间排序
  const merged = [
    ...auditEvents.map(e => ({ ...e, action: escapeHtml(e.action), detail: escapeHtml(e.detail), type: 'event' })),
    ...diagEvents.map(e => ({
      id: 'diag-' + e.id,
      action: 'diagnosis_' + e.status,
      detail: escapeHtml(`${e.node_name || '未知节点'}: ${e.diag_info || ''}${e.ai_analysis ? ' → ' + e.ai_analysis : ''}`),
      created_at: e.created_at,
      created_at_display: formatDateTimeInTimeZone(e.created_at, 'Asia/Shanghai'),
      source: 'diagnosis',
      type: 'diagnosis'
    }))
  ].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, limit)
    .map(e => ({ ...e, created_at_display: e.created_at_display || formatDateTimeInTimeZone(e.created_at, 'Asia/Shanghai') }));
  res.json(merged);
});

router.get('/ops-diagnoses', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  res.json(db.getAllDiagnoses(limit));
});

module.exports = router;
