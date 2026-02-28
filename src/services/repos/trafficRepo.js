let _getDb, _getUserById;
const { dateKeyInTimeZone, dateKeyDaysAgo } = require('../../utils/time');

function init(deps) {
  _getDb = deps.getDb;
  _getUserById = deps.getUserById;
}

function recordTraffic(userId, nodeId, uplink, downlink) {
  _getDb().prepare('INSERT INTO traffic (user_id, node_id, uplink, downlink) VALUES (?, ?, ?, ?)').run(userId, nodeId, uplink, downlink);
  const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');
  _getDb().prepare(`
    INSERT INTO traffic_daily (user_id, node_id, date, uplink, downlink)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, node_id, date) DO UPDATE SET
      uplink = uplink + excluded.uplink,
      downlink = downlink + excluded.downlink
  `).run(userId, nodeId, today, uplink, downlink);
  _getDb().prepare(`
    INSERT INTO traffic_user_total (user_id, total_up, total_down, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      total_up = total_up + excluded.total_up,
      total_down = total_down + excluded.total_down,
      updated_at = datetime('now')
  `).run(userId, uplink, downlink);
  try {
    _getDb().prepare(`
      INSERT INTO traffic_site_total (id, total_up, total_down, updated_at)
      VALUES (1, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        total_up = total_up + excluded.total_up,
        total_down = total_down + excluded.total_down,
        updated_at = datetime('now')
    `).run(uplink, downlink);
  } catch (_) {}
}

function getUserTraffic(userId) {
  const total = _getDb().prepare(`
    SELECT COALESCE(total_up, 0) as total_up, COALESCE(total_down, 0) as total_down
    FROM traffic_user_total WHERE user_id = ?
  `).get(userId);
  if (total) return total;
  // 兼容：极少数老数据未回填时兜底
  return _getDb().prepare(`
    SELECT COALESCE(SUM(uplink), 0) as total_up, COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily WHERE user_id = ?
  `).get(userId);
}

function getAllUsersTraffic(date, limit = 20, offset = 0) {
  const where = date ? 'AND t.date = ?' : '';
  const params = date ? [date, limit, offset] : [limit, offset];
  const rows = _getDb().prepare(`
    SELECT u.id, u.username, u.name, u.avatar_url,
      COALESCE(SUM(t.uplink), 0) as total_up,
      COALESCE(SUM(t.downlink), 0) as total_down
    FROM users u
    LEFT JOIN traffic_daily t ON u.id = t.user_id ${where}
    GROUP BY u.id
    HAVING total_up + total_down > 0
    ORDER BY (total_up + total_down) DESC
    LIMIT ? OFFSET ?
  `).all(...params);
  const countParams = date ? [date] : [];
  const total = _getDb().prepare(`
    SELECT COUNT(*) as c FROM (
      SELECT u.id FROM users u
      LEFT JOIN traffic_daily t ON u.id = t.user_id ${where}
      GROUP BY u.id HAVING COALESCE(SUM(t.uplink),0) + COALESCE(SUM(t.downlink),0) > 0
    )
  `).get(...countParams).c;
  return { rows, total };
}

function getNodeTraffic(nodeId) {
  return _getDb().prepare(`
    SELECT COALESCE(SUM(uplink), 0) as total_up, COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily WHERE node_id = ?
  `).get(nodeId);
}

function getGlobalTraffic() {
  try {
    const total = _getDb().prepare(`
      SELECT COALESCE(total_up, 0) as total_up, COALESCE(total_down, 0) as total_down
      FROM traffic_site_total WHERE id = 1
    `).get();
    if (total) return total;
  } catch (_) {}
  // 兼容：历史库不存在 traffic_site_total 时兜底
  return _getDb().prepare(`
    SELECT COALESCE(SUM(uplink), 0) as total_up, COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily
  `).get();
}

function getTodayTraffic() {
  const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');
  return _getDb().prepare(`
    SELECT COALESCE(SUM(uplink), 0) as total_up, COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily WHERE date = ?
  `).get(today);
}

function _rangeDateCondition(range) {
  const today = dateKeyInTimeZone(new Date(), 'Asia/Shanghai');
  if (range === 'today') return { where: 'AND t.date = ?', params: [today] };
  if (range === '7d') {
    return { where: 'AND t.date >= ?', params: [dateKeyDaysAgo(6, 'Asia/Shanghai')] };
  }
  if (range === '30d') {
    return { where: 'AND t.date >= ?', params: [dateKeyDaysAgo(29, 'Asia/Shanghai')] };
  }
  if (range === 'all') return { where: '', params: [] };
  // 支持具体日期 YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(range)) return { where: 'AND t.date = ?', params: [range] };
  return { where: '', params: [] };
}

function getUsersTrafficByRange(range, limit = 20, offset = 0) {
  const { where, params } = _rangeDateCondition(range);
  const rows = _getDb().prepare(`
    SELECT u.id, u.username, u.name, u.avatar_url,
      COALESCE(SUM(t.uplink), 0) as total_up,
      COALESCE(SUM(t.downlink), 0) as total_down
    FROM users u
    LEFT JOIN traffic_daily t ON u.id = t.user_id ${where}
    GROUP BY u.id
    HAVING total_up + total_down > 0
    ORDER BY (total_up + total_down) DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);
  const total = _getDb().prepare(`
    SELECT COUNT(*) as c FROM (
      SELECT u.id FROM users u
      LEFT JOIN traffic_daily t ON u.id = t.user_id ${where}
      GROUP BY u.id HAVING COALESCE(SUM(t.uplink),0) + COALESCE(SUM(t.downlink),0) > 0
    )
  `).get(...params).c;
  return { rows, total };
}

function getNodesTrafficByRange(range) {
  const { where, params } = _rangeDateCondition(range);
  return _getDb().prepare(`
    SELECT n.id, n.name,
      COALESCE(SUM(t.uplink), 0) as total_up,
      COALESCE(SUM(t.downlink), 0) as total_down
    FROM nodes n
    LEFT JOIN traffic_daily t ON n.id = t.node_id ${where}
    GROUP BY n.id
    HAVING total_up + total_down > 0
    ORDER BY (total_up + total_down) DESC
  `).all(...params);
}

function getTrafficTrend(days = 30) {
  const startDate = dateKeyDaysAgo(days - 1, 'Asia/Shanghai');
  return _getDb().prepare(`
    SELECT date,
      COALESCE(SUM(uplink), 0) as total_up,
      COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily
    WHERE date >= ?
    GROUP BY date
    ORDER BY date ASC
  `).all(startDate);
}

// Sprint 6: 用户按天/按节点的流量明细
function getUserTrafficDaily(userId, days = 30) {
  const startDate = dateKeyDaysAgo(days - 1, 'Asia/Shanghai');
  return _getDb().prepare(`
    SELECT td.date, td.node_id, n.name as node_name,
      td.uplink, td.downlink
    FROM traffic_daily td
    LEFT JOIN nodes n ON n.id = td.node_id
    WHERE td.user_id = ? AND td.date >= ?
    ORDER BY td.date DESC, n.name
  `).all(userId, startDate);
}

function getUserTrafficDailyAgg(userId, days = 30) {
  const startDate = dateKeyDaysAgo(days - 1, 'Asia/Shanghai');
  return _getDb().prepare(`
    SELECT date,
      COALESCE(SUM(uplink), 0) as total_up,
      COALESCE(SUM(downlink), 0) as total_down
    FROM traffic_daily
    WHERE user_id = ? AND date >= ?
    GROUP BY date
    ORDER BY date ASC
  `).all(userId, startDate);
}

function cleanupTrafficHistory(rawRetentionDays = 30, dailyRetentionDays = 120) {
  const rawDays = Math.max(1, parseInt(rawRetentionDays) || 30);
  const dailyDays = Math.max(30, parseInt(dailyRetentionDays) || 120);
  const dailyCutoff = dateKeyDaysAgo(dailyDays - 1, 'Asia/Shanghai');

  const tx = _getDb().transaction(() => {
    const r1 = _getDb().prepare(`
      DELETE FROM traffic
      WHERE recorded_at < datetime('now', 'localtime', ?)
    `).run(`-${rawDays} days`);

    const r2 = _getDb().prepare(`
      DELETE FROM traffic_daily
      WHERE date < ?
    `).run(dailyCutoff);

    return {
      rawDeleted: r1.changes || 0,
      dailyDeleted: r2.changes || 0,
      rawDays,
      dailyDays,
      dailyCutoff,
    };
  });

  return tx();
}

module.exports = {
  init,
  recordTraffic, getUserTraffic, getAllUsersTraffic, getNodeTraffic,
  getGlobalTraffic, getTodayTraffic, getUsersTrafficByRange, getNodesTrafficByRange,
  getTrafficTrend, getUserTrafficDaily, getUserTrafficDailyAgg, cleanupTrafficHistory
};
