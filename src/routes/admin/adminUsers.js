const express = require('express');
const db = require('../../services/database');
const { emitSyncAll } = require('../../services/configEvents');
const { dateKeyInTimeZone, dateKeyDaysAgo, formatDateTimeInTimeZone } = require('../../utils/time');
const { parseIntId } = require('../../utils/validators');

const router = express.Router();
function wantsJson(req) {
  const accept = req.headers.accept || '';
  const contentType = req.headers['content-type'] || '';
  return req.xhr || accept.includes('application/json') || contentType.includes('application/json');
}

router.post('/users/:id/toggle-block', async (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: '参数错误' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ ok: false, error: '用户不存在' });
  const nextBlocked = !user.is_blocked;
  const actionText = nextBlocked ? '封禁' : '解封';
  if (user) {
    db.blockUser(user.id, nextBlocked);
    db.addAuditLog(req.user.id, 'user_block', `${actionText} 用户: ${user.username}`, req.clientIp || req.ip);
    emitSyncAll();
  }
  if (wantsJson(req)) {
    return res.json({ ok: true, message: `${actionText}成功`, blocked: nextBlocked });
  }
  res.redirect('/admin#users');
});

router.post('/users/:id/reset-token', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: '参数错误' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ ok: false, error: '用户不存在' });
  db.resetSubToken(user.id);
  db.addAuditLog(req.user.id, 'token_reset', `重置订阅: ${user.username}`, req.clientIp || req.ip);
  if (wantsJson(req)) return res.json({ ok: true, message: '订阅令牌已重置' });
  res.redirect('/admin#users');
});

router.post('/users/:id/traffic-limit', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const limitGB = parseFloat(req.body.limit) || 0;
  const limitBytes = Math.round(limitGB * 1073741824);
  db.setUserTrafficLimit(user.id, limitBytes);
  db.addAuditLog(req.user.id, 'traffic_limit', `设置 ${user.username} 流量限额: ${limitGB > 0 ? limitGB + ' GB' : '无限'}`, req.clientIp || req.ip);
  res.json({ ok: true });
});

router.post('/default-traffic-limit', (req, res) => {
  const limitGB = parseFloat(req.body.limit) || 0;
  const limitBytes = Math.round(limitGB * 1073741824);
  db.setSetting('default_traffic_limit', String(limitBytes));
  db.addAuditLog(req.user.id, 'default_traffic_limit', `设置默认流量限额: ${limitGB > 0 ? limitGB + ' GB' : '无限'}`, req.clientIp || req.ip);
  res.json({ ok: true });
});

router.post('/default-traffic-limit/apply', (req, res) => {
  const limitBytes = parseInt(db.getSetting('default_traffic_limit')) || 0;
  const r = db.getDb().prepare('UPDATE users SET traffic_limit = ?').run(limitBytes);
  db.addAuditLog(req.user.id, 'default_traffic_limit_apply', `批量应用默认流量限额到全部用户: ${r.changes} 个`, req.clientIp || req.ip);
  res.json({ ok: true, updated: r.changes });
});

router.get('/users', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const search = (req.query.search || '').trim();
  const sortBy = req.query.sortBy || 'total_traffic';
  const sortDir = req.query.sortDir || 'DESC';
  const limit = 20;
  const offset = (page - 1) * limit;
  const data = db.getAllUsersPaged(limit, offset, search, sortBy, sortDir);
  res.json({ ...data, page });
});

// Sprint 6: 设置用户到期时间
router.post('/users/:id/set-expiry', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const { expires_at } = req.body;
  db.setUserExpiry(user.id, expires_at || null);
  db.addAuditLog(req.user.id, 'set_expiry', `设置 ${user.username} 到期时间: ${expires_at || '永不过期'}`, req.clientIp || req.ip);
  res.json({ ok: true });
});

module.exports = router;

// 用户综合详情（流量排行点击查看）
router.get('/users/:id/detail', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: '用户不存在' });

  // 基本信息
  const info = {
    id: user.id, username: user.username, name: user.name,
    trust_level: user.trust_level, is_admin: user.is_admin,
    is_blocked: user.is_blocked, is_frozen: user.is_frozen,
    last_login: user.last_login, created_at: user.created_at,
    expires_at: user.expires_at, traffic_limit: user.traffic_limit,
    nodeloc_id: user.nodeloc_id, sub_token: user.sub_token,
    last_login_display: formatDateTimeInTimeZone(user.last_login, 'Asia/Shanghai'),
    created_at_display: formatDateTimeInTimeZone(user.created_at, 'Asia/Shanghai'),
    expires_at_display: formatDateTimeInTimeZone(user.expires_at, 'Asia/Shanghai'),
  };

  // 流量统计
  const d = db.getDb();
  const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');
  const todayTraffic = d.prepare('SELECT COALESCE(SUM(uplink),0) as up, COALESCE(SUM(downlink),0) as down FROM traffic_daily WHERE user_id = ? AND date = ?').get(id, today);
  const totalTraffic = d.prepare(`
    SELECT COALESCE(total_up,0) as up, COALESCE(total_down,0) as down
    FROM traffic_user_total
    WHERE user_id = ?
  `).get(id) || { up: 0, down: 0 };

  // 订阅拉取记录（最近24h）
  const subAccessRaw = db.getSubAccessUserDetail(id, 24);
  const subAccess = {
    ips: (subAccessRaw.ips || []).map((ip) => ({
      ...ip,
      last_access_display: formatDateTimeInTimeZone(ip.last_access, 'Asia/Shanghai'),
    })),
    uas: subAccessRaw.uas || [],
    timeline: (subAccessRaw.timeline || []).map((t) => ({
      ...t,
      time_display: formatDateTimeInTimeZone(t.time, 'Asia/Shanghai'),
    })),
  };

  // 最近7天流量趋势
  const weekAgo = dateKeyDaysAgo(6, 'Asia/Shanghai');
  const dailyTraffic = d.prepare('SELECT date, COALESCE(SUM(uplink),0) as up, COALESCE(SUM(downlink),0) as down FROM traffic_daily WHERE user_id = ? AND date >= ? GROUP BY date ORDER BY date').all(id, weekAgo);

  res.json({ info, todayTraffic, totalTraffic, subAccess, dailyTraffic });
});
