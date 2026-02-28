const { v4: uuidv4 } = require('uuid');
const { toSqlUtc } = require('../../utils/time');

let _getDb, _getSetting, _addAuditLog, _ensureUserHasAllNodeUuids, _removeFromRegisterWhitelist;

function init(deps) {
  _getDb = deps.getDb;
  _getSetting = deps.getSetting;
  _addAuditLog = deps.addAuditLog;
  _ensureUserHasAllNodeUuids = deps.ensureUserHasAllNodeUuids;
  _removeFromRegisterWhitelist = deps.removeFromRegisterWhitelist;
}

function findOrCreateUser(profile) {
  const existing = _getDb().prepare('SELECT * FROM users WHERE nodeloc_id = ?').get(profile.id);
  if (existing) {
    const wasFrozen = existing.is_frozen;
    _getDb().prepare(`
      UPDATE users SET username = ?, name = ?, avatar_url = ?, trust_level = ?, email = ?, is_frozen = 0, last_login = datetime('now')
      WHERE nodeloc_id = ?
    `).run(profile.username, profile.name, profile.avatar_url, profile.trust_level, profile.email, profile.id);
    const user = _getDb().prepare('SELECT * FROM users WHERE nodeloc_id = ?').get(profile.id);
    if (wasFrozen) {
      _ensureUserHasAllNodeUuids(user.id);
      user._wasFrozen = true;
    }
    return user;
  }

  const subToken = uuidv4();
  const userCount = _getDb().prepare('SELECT COUNT(*) as count FROM users').get().count;
  const isAdmin = userCount === 0 ? 1 : 0;
  const defaultLimit = parseInt(_getSetting('default_traffic_limit')) || 0;

  _getDb().prepare(`
    INSERT INTO users (nodeloc_id, username, name, avatar_url, trust_level, email, sub_token, is_admin, traffic_limit, last_login)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(profile.id, profile.username, profile.name, profile.avatar_url, profile.trust_level, profile.email, subToken, isAdmin, defaultLimit);

  const newUser = _getDb().prepare('SELECT * FROM users WHERE nodeloc_id = ?').get(profile.id);
  if (isAdmin) console.log(`👑 首位用户 ${profile.username} 已自动设为管理员`);

  _addAuditLog(null, 'user_register', `新用户注册: ${profile.username}${isAdmin ? ' (管理员)' : ''}`, 'system');

  try { const { notify } = require('../notify'); notify.userRegister(profile.username, profile); } catch {}

  _ensureUserHasAllNodeUuids(newUser.id);
  _removeFromRegisterWhitelist(profile.username);

  return newUser;
}

function getUserBySubToken(token) {
  return _getDb().prepare('SELECT * FROM users WHERE sub_token = ? AND is_blocked = 0 AND is_frozen = 0').get(token);
}

function getUserById(id) {
  return _getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getUserCount() {
  return _getDb().prepare('SELECT COUNT(*) as count FROM users').get().count;
}

function getAllUsers() {
  return _getDb().prepare(`
    SELECT u.*, COALESCE(tut.total_up, 0) + COALESCE(tut.total_down, 0) as total_traffic
    FROM users u
    LEFT JOIN traffic_user_total tut ON u.id = tut.user_id
    ORDER BY total_traffic DESC
  `).all();
}

function getAllUsersPaged(limit = 20, offset = 0, search = '', sortBy = 'total_traffic', sortDir = 'DESC') {
  const where = search ? "WHERE u.username LIKE '%' || @search || '%' OR u.name LIKE '%' || @search || '%'" : '';
  const allowedSorts = {
    id: 'u.id', username: 'u.username', trust_level: 'u.trust_level',
    total_traffic: 'total_traffic', expires_at: 'u.expires_at', last_login: 'u.last_login'
  };
  const orderCol = allowedSorts[sortBy] || 'total_traffic';
  const dir = sortDir === 'ASC' ? 'ASC' : 'DESC';
  const rows = _getDb().prepare(`
    SELECT u.*, COALESCE(tut.total_up, 0) + COALESCE(tut.total_down, 0) as total_traffic
    FROM users u
    LEFT JOIN traffic_user_total tut ON u.id = tut.user_id
    ${where}
    ORDER BY ${orderCol} ${dir}
    LIMIT @limit OFFSET @offset
  `).all({ limit, offset, search });
  const total = _getDb().prepare(`SELECT COUNT(*) as c FROM users u ${where}`).get({ search }).c;
  return { rows, total };
}

function blockUser(id, blocked) {
  _getDb().prepare('UPDATE users SET is_blocked = ? WHERE id = ?').run(blocked ? 1 : 0, id);
}

function setUserTrafficLimit(id, limitBytes) {
  _getDb().prepare('UPDATE users SET traffic_limit = ? WHERE id = ?').run(limitBytes, id);
}

function isTrafficExceeded(userId) {
  const user = getUserById(userId);
  if (!user || !user.traffic_limit) return false;
  const traffic = _getDb().prepare(
    'SELECT COALESCE(total_up, 0) + COALESCE(total_down, 0) as total FROM traffic_user_total WHERE user_id = ?'
  ).get(userId);
  return (traffic?.total || 0) >= user.traffic_limit;
}

function freezeUser(id) {
  _getDb().prepare('UPDATE users SET is_frozen = 1 WHERE id = ?').run(id);
  _getDb().prepare('DELETE FROM user_node_uuid WHERE user_id = ?').run(id);
}

function unfreezeUser(id) {
  _getDb().prepare('UPDATE users SET is_frozen = 0 WHERE id = ?').run(id);
  const u = _getDb().prepare('SELECT is_admin, trust_level FROM users WHERE id = ?').get(id);
  if (u) {
    _ensureUserHasAllNodeUuids(id);
  }
}

function autoFreezeInactiveUsers(days = 15) {
  const cutoff = toSqlUtc(new Date(Date.now() - days * 86400000));
  const users = _getDb().prepare(
    "SELECT id, username FROM users WHERE is_frozen = 0 AND is_blocked = 0 AND is_admin = 0 AND last_login < ?"
  ).all(cutoff);
  for (const u of users) {
    freezeUser(u.id);
  }
  return users;
}

function resetSubToken(userId) {
  const newToken = uuidv4();
  _getDb().prepare('UPDATE users SET sub_token = ? WHERE id = ?').run(newToken, userId);
  return newToken;
}

// Sprint 6: 用户到期时间
function setUserExpiry(userId, expiresAt) {
  _getDb().prepare('UPDATE users SET expires_at = ? WHERE id = ?').run(expiresAt || null, userId);
}

function autoFreezeExpiredUsers() {
  const now = toSqlUtc();
  const users = _getDb().prepare(
    "SELECT id, username FROM users WHERE is_frozen = 0 AND is_blocked = 0 AND expires_at IS NOT NULL AND expires_at < ?"
  ).all(now);
  for (const u of users) {
    freezeUser(u.id);
  }
  return users;
}

module.exports = {
  init,
  findOrCreateUser, getUserBySubToken, getUserById, getUserCount,
  getAllUsers, getAllUsersPaged, blockUser, setUserTrafficLimit,
  isTrafficExceeded, freezeUser, unfreezeUser, autoFreezeInactiveUsers, resetSubToken,
  setUserExpiry, autoFreezeExpiredUsers
};
