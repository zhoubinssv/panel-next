let _getDb;

function init(deps) {
  _getDb = deps.getDb;
}

function toPosInt(value, fallback, min = 1, max = null) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  let out = n;
  if (out < min) out = min;
  if (max != null && out > max) out = max;
  return out;
}

function toSafeText(value, maxLen = 255) {
  return String(value == null ? '' : value).slice(0, maxLen);
}

function buildRiskLevel(row) {
  const req = Number(row.request_count || 0);
  const deny = Number(row.deny_count || 0);
  const ip = Number(row.ip_count || 0);
  const ua = Number(row.ua_count || 0);
  const denyRate = req > 0 ? deny / req : 0;

  if (deny >= 40 || denyRate >= 0.5 || ip >= 10 || ua >= 8 || req >= 200) return 'high';
  if (deny >= 10 || denyRate >= 0.2 || ip >= 5 || ua >= 4 || req >= 80) return 'mid';
  return 'low';
}

function logSubAccess(userId, ip, ua) {
  // 仅记录访问；历史清理由 app.js 的定时任务统一处理，避免高频订阅路径触发 DELETE
  _getDb().prepare("INSERT INTO sub_access_log (user_id, ip, ua, created_at) VALUES (?, ?, ?, datetime('now'))").run(userId, ip, ua || '');
}

function logSubAccessEvent(input = {}) {
  const result = String(input.result || 'allow').toLowerCase() === 'deny' ? 'deny' : 'allow';
  const userId = Number.isFinite(Number(input.userId)) ? Number(input.userId) : null;
  const tokenPrefix = toSafeText(input.tokenPrefix || '', 16);
  const route = toSafeText(input.route || 'sub', 16);
  const reason = toSafeText(input.reason || 'ok', 64);
  const ip = toSafeText(input.ip || '', 64);
  const ua = toSafeText(input.ua || '', 300);
  const clientType = toSafeText(input.clientType || '', 32);
  const statusRaw = parseInt(input.httpStatus, 10);
  const httpStatus = Number.isFinite(statusRaw) ? statusRaw : (result === 'allow' ? 200 : 403);

  _getDb().prepare(`
    INSERT INTO sub_access_event (
      user_id, token_prefix, route, result, reason, ip, ua, client_type, http_status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(userId, tokenPrefix, route, result, reason, ip, ua, clientType, httpStatus);
}

function getSubAccessIPs(userId, hours = 24) {
  return _getDb().prepare(`
    SELECT ip, COUNT(*) as count, MAX(created_at) as last_access
    FROM sub_access_log
    WHERE user_id = ? AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY ip ORDER BY count DESC
  `).all(userId, hours);
}

function getSubAbuseUsers(hours = 24, minIPs = 3) {
  return _getDb().prepare(`
    SELECT user_id, COUNT(DISTINCT ip) as ip_count, GROUP_CONCAT(DISTINCT ip) as ips
    FROM sub_access_log
    WHERE created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY user_id HAVING ip_count >= ?
    ORDER BY ip_count DESC
  `).all(hours, minIPs);
}

function getSubAccessStats(hours = 24, limit = 50, offset = 0, onlyHigh = false, sort = 'count') {
  const orderMap = { count: 'pull_count DESC', ip: 'ip_count DESC', last: 'last_access DESC' };
  const orderBy = orderMap[sort] || orderMap.count;

  const baseWhere = `WHERE created_at > datetime('now', '-' || @hours || ' hours')`;
  const baseWhereWithAlias = `WHERE l.created_at > datetime('now', '-' || @hours || ' hours')`;
  const havingClause = onlyHigh ? 'HAVING COUNT(*) > 100 OR COUNT(DISTINCT ip) > 8' : '';
  const havingClauseWithAlias = onlyHigh ? 'HAVING COUNT(*) > 100 OR COUNT(DISTINCT l.ip) > 8' : '';

  const countRow = _getDb().prepare(`
    SELECT COUNT(*) as total FROM (
      SELECT user_id FROM sub_access_log ${baseWhere}
      GROUP BY user_id ${havingClause}
    )
  `).get({ hours });

  const rows = _getDb().prepare(`
    SELECT
      l.user_id,
      COALESCE(u.username, '未知') as username,
      COUNT(*) as pull_count,
      COUNT(DISTINCT l.ip) as ip_count,
      MAX(l.created_at) as last_access,
      ROUND((@hours * 3600.0) / MAX(COUNT(*), 1), 1) as avg_interval_sec
    FROM sub_access_log l
    LEFT JOIN users u ON u.id = l.user_id
    ${baseWhereWithAlias}
    GROUP BY l.user_id ${havingClauseWithAlias}
    ORDER BY ${orderBy}
    LIMIT @limit OFFSET @offset
  `).all({ hours, limit, offset });

  const data = rows.map((r) => {
    const risk = (r.pull_count > 100 || r.ip_count > 8) ? 'high'
      : (r.pull_count >= 30 || r.ip_count >= 4) ? 'mid' : 'low';
    return { ...r, risk_level: risk };
  });

  return { total: countRow.total, data };
}

function getSubEventOverview(hours = 24) {
  const safeHours = toPosInt(hours, 24, 1, 24 * 365);
  const base = _getDb().prepare(`
    SELECT
      COUNT(*) as total_requests,
      SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) as allow_requests,
      SUM(CASE WHEN result = 'deny' THEN 1 ELSE 0 END) as deny_requests,
      COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id ELSE NULL END) as user_count,
      COUNT(DISTINCT CASE WHEN result = 'deny' AND user_id IS NOT NULL THEN user_id ELSE NULL END) as denied_user_count
    FROM sub_access_event
    WHERE created_at > datetime('now', '-' || ? || ' hours')
  `).get(safeHours) || {
    total_requests: 0,
    allow_requests: 0,
    deny_requests: 0,
    user_count: 0,
    denied_user_count: 0,
  };

  const denyReasons = _getDb().prepare(`
    SELECT reason, COUNT(*) as count
    FROM sub_access_event
    WHERE created_at > datetime('now', '-' || ? || ' hours')
      AND result = 'deny'
    GROUP BY reason
    ORDER BY count DESC, MAX(created_at) DESC
    LIMIT 8
  `).all(safeHours);

  const total = Number(base.total_requests || 0);
  const allow = Number(base.allow_requests || 0);
  const deny = Number(base.deny_requests || 0);

  return {
    total_requests: total,
    allow_requests: allow,
    deny_requests: deny,
    allow_rate: total > 0 ? Math.round((allow * 1000) / total) / 10 : 0,
    deny_rate: total > 0 ? Math.round((deny * 1000) / total) / 10 : 0,
    user_count: Number(base.user_count || 0),
    denied_user_count: Number(base.denied_user_count || 0),
    deny_reasons: denyReasons,
  };
}

function getSubAccessStatsV2(hours = 24, limit = 20, offset = 0, onlyHigh = false, sort = 'request') {
  const safeHours = toPosInt(hours, 24, 1, 24 * 365);
  const safeLimit = toPosInt(limit, 20, 1, 200);
  const safeOffset = toPosInt(offset, 0, 0, 1000000);
  const orderMap = {
    request: 'request_count DESC',
    success: 'ok_count DESC',
    deny: 'deny_count DESC',
    ip: 'ip_count DESC',
    ua: 'ua_count DESC',
    last: 'last_access DESC',
    ok_rate: 'ok_rate DESC',
  };
  const orderBy = orderMap[sort] || orderMap.request;

  const baseWhere = `
    WHERE e.created_at > datetime('now', '-' || @hours || ' hours')
      AND e.user_id IS NOT NULL
  `;
  const havingClause = onlyHigh
    ? `
      HAVING COUNT(*) >= 150
         OR COUNT(DISTINCT e.ip) >= 8
         OR SUM(CASE WHEN e.result = 'deny' THEN 1 ELSE 0 END) >= 20
    `
    : '';

  const countRow = _getDb().prepare(`
    SELECT COUNT(*) as total FROM (
      SELECT e.user_id
      FROM sub_access_event e
      ${baseWhere}
      GROUP BY e.user_id
      ${havingClause}
    )
  `).get({ hours: safeHours }) || { total: 0 };

  const rows = _getDb().prepare(`
    SELECT
      e.user_id,
      COALESCE(u.username, '未知') as username,
      COUNT(*) as request_count,
      SUM(CASE WHEN e.result = 'allow' THEN 1 ELSE 0 END) as ok_count,
      SUM(CASE WHEN e.result = 'deny' THEN 1 ELSE 0 END) as deny_count,
      ROUND(100.0 * SUM(CASE WHEN e.result = 'allow' THEN 1 ELSE 0 END) / MAX(COUNT(*), 1), 1) as ok_rate,
      ROUND(100.0 * SUM(CASE WHEN e.result = 'deny' THEN 1 ELSE 0 END) / MAX(COUNT(*), 1), 1) as deny_rate,
      COUNT(DISTINCT e.ip) as ip_count,
      COUNT(DISTINCT NULLIF(e.ua, '')) as ua_count,
      MAX(e.created_at) as last_access,
      ROUND((@hours * 3600.0) / MAX(COUNT(*), 1), 1) as avg_interval_sec,
      (
        SELECT ee.reason
        FROM sub_access_event ee
        WHERE ee.user_id = e.user_id
          AND ee.created_at > datetime('now', '-' || @hours || ' hours')
          AND ee.result = 'deny'
        GROUP BY ee.reason
        ORDER BY COUNT(*) DESC, MAX(ee.created_at) DESC
        LIMIT 1
      ) as top_deny_reason
    FROM sub_access_event e
    LEFT JOIN users u ON u.id = e.user_id
    ${baseWhere}
    GROUP BY e.user_id
    ${havingClause}
    ORDER BY ${orderBy}
    LIMIT @limit OFFSET @offset
  `).all({
    hours: safeHours,
    limit: safeLimit,
    offset: safeOffset,
  });

  const data = rows.map((r) => {
    const requestCount = Number(r.request_count || 0);
    const denyCount = Number(r.deny_count || 0);
    return {
      ...r,
      deny_ratio: requestCount > 0 ? Math.round((denyCount * 10000) / requestCount) / 100 : 0,
      risk_level: buildRiskLevel(r),
    };
  });

  return {
    total: Number(countRow.total || 0),
    data,
    overview: getSubEventOverview(safeHours),
  };
}

function getSubAccessUserDetail(userId, hours = 24) {
  const ips = _getDb().prepare(`
    SELECT ip, COUNT(*) as count, MAX(created_at) as last_access
    FROM sub_access_log
    WHERE user_id = ? AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY ip ORDER BY count DESC
  `).all(userId, hours);

  const uas = _getDb().prepare(`
    SELECT ua, COUNT(*) as count
    FROM sub_access_log
    WHERE user_id = ? AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY ua ORDER BY count DESC LIMIT 10
  `).all(userId, hours);

  const timeline = _getDb().prepare(`
    SELECT created_at as time, ip, ua
    FROM sub_access_log
    WHERE user_id = ? AND created_at > datetime('now', '-' || ? || ' hours')
    ORDER BY created_at DESC LIMIT 20
  `).all(userId, hours);

  return { ips, uas, timeline };
}

function getSubAccessUserDetailV2(userId, hours = 24) {
  const safeUserId = toPosInt(userId, 0, 1);
  if (!safeUserId) return { summary: {}, ips: [], uas: [], reasons: [], routes: [], timeline: [] };
  const safeHours = toPosInt(hours, 24, 1, 24 * 365);

  const summary = _getDb().prepare(`
    SELECT
      COUNT(*) as request_count,
      SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) as ok_count,
      SUM(CASE WHEN result = 'deny' THEN 1 ELSE 0 END) as deny_count,
      COUNT(DISTINCT ip) as ip_count,
      COUNT(DISTINCT NULLIF(ua, '')) as ua_count,
      MAX(created_at) as last_access
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
  `).get(safeUserId, safeHours) || {
    request_count: 0,
    ok_count: 0,
    deny_count: 0,
    ip_count: 0,
    ua_count: 0,
    last_access: null,
  };

  const ips = _getDb().prepare(`
    SELECT
      ip,
      COUNT(*) as count,
      SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) as ok_count,
      SUM(CASE WHEN result = 'deny' THEN 1 ELSE 0 END) as deny_count,
      MAX(created_at) as last_access
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY ip
    ORDER BY count DESC, last_access DESC
    LIMIT 30
  `).all(safeUserId, safeHours);

  const uas = _getDb().prepare(`
    SELECT
      ua,
      COUNT(*) as count,
      SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) as ok_count,
      SUM(CASE WHEN result = 'deny' THEN 1 ELSE 0 END) as deny_count
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY ua
    ORDER BY count DESC
    LIMIT 15
  `).all(safeUserId, safeHours);

  const reasons = _getDb().prepare(`
    SELECT
      reason,
      COUNT(*) as count,
      MAX(created_at) as last_access
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
      AND result = 'deny'
    GROUP BY reason
    ORDER BY count DESC, last_access DESC
    LIMIT 15
  `).all(safeUserId, safeHours);

  const routes = _getDb().prepare(`
    SELECT
      route,
      COUNT(*) as count,
      SUM(CASE WHEN result = 'allow' THEN 1 ELSE 0 END) as ok_count,
      SUM(CASE WHEN result = 'deny' THEN 1 ELSE 0 END) as deny_count
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY route
    ORDER BY count DESC
  `).all(safeUserId, safeHours);

  const timeline = _getDb().prepare(`
    SELECT
      created_at as time,
      ip,
      ua,
      route,
      result,
      reason,
      http_status,
      client_type
    FROM sub_access_event
    WHERE user_id = ?
      AND created_at > datetime('now', '-' || ? || ' hours')
    ORDER BY created_at DESC
    LIMIT 50
  `).all(safeUserId, safeHours);

  const reqCount = Number(summary.request_count || 0);
  const denyCount = Number(summary.deny_count || 0);
  return {
    summary: {
      ...summary,
      ok_rate: reqCount > 0 ? Math.round((Number(summary.ok_count || 0) * 1000) / reqCount) / 10 : 0,
      deny_rate: reqCount > 0 ? Math.round((denyCount * 1000) / reqCount) / 10 : 0,
      risk_level: buildRiskLevel({
        request_count: reqCount,
        deny_count: denyCount,
        ip_count: Number(summary.ip_count || 0),
        ua_count: Number(summary.ua_count || 0),
      }),
    },
    ips,
    uas,
    reasons,
    routes,
    timeline,
  };
}

module.exports = {
  init,
  logSubAccess,
  logSubAccessEvent,
  getSubAccessIPs,
  getSubAbuseUsers,
  getSubAccessStats,
  getSubEventOverview,
  getSubAccessStatsV2,
  getSubAccessUserDetail,
  getSubAccessUserDetailV2,
};
