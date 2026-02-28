const { v4: uuidv4 } = require('uuid');

let _getDb, _getAllUsers, _getAllNodes;

function init(deps) {
  _getDb = deps.getDb;
  _getAllUsers = deps.getAllUsers;
  _getAllNodes = deps.getAllNodes;
}

function getUserNodeUuid(userId, nodeId) {
  let row = _getDb().prepare('SELECT * FROM user_node_uuid WHERE user_id = ? AND node_id = ?').get(userId, nodeId);
  if (!row) {
    const newUuid = uuidv4();
    _getDb().prepare('INSERT INTO user_node_uuid (user_id, node_id, uuid) VALUES (?, ?, ?)').run(userId, nodeId, newUuid);
    row = { user_id: userId, node_id: nodeId, uuid: newUuid };
  }
  return row;
}

function getUserAllNodeUuids(userId) {
  return _getDb().prepare('SELECT un.*, n.name as node_name, n.host, n.port FROM user_node_uuid un JOIN nodes n ON un.node_id = n.id WHERE un.user_id = ?').all(userId);
}

function getNodeAllUserUuids(nodeId) {
  return _getDb().prepare(`
    SELECT un.*, u.username FROM user_node_uuid un
    JOIN users u ON un.user_id = u.id
    JOIN nodes n ON un.node_id = n.id
    LEFT JOIN whitelist w ON u.nodeloc_id = w.nodeloc_id
    WHERE un.node_id = ? AND u.is_blocked = 0 AND u.is_frozen = 0
      AND (w.nodeloc_id IS NOT NULL OR u.trust_level >= n.min_level)
  `).all(nodeId);
}

function ensureAllUsersHaveUuid(nodeId) {
  const users = _getAllUsers().filter(u => !u.is_frozen && !u.is_blocked);
  const stmt = _getDb().prepare('INSERT OR IGNORE INTO user_node_uuid (user_id, node_id, uuid) VALUES (?, ?, ?)');
  const insertMany = _getDb().transaction((users) => {
    for (const user of users) {
      stmt.run(user.id, nodeId, uuidv4());
    }
  });
  insertMany(users);
}

function ensureUserHasAllNodeUuids(userId) {
  const u = _getDb().prepare('SELECT is_admin, trust_level, is_frozen, is_blocked FROM users WHERE id = ?').get(userId);
  if (!u || u.is_frozen || u.is_blocked) return;
  const nodes = _getAllNodes();
  const stmt = _getDb().prepare('INSERT OR IGNORE INTO user_node_uuid (user_id, node_id, uuid) VALUES (?, ?, ?)');
  const insertMany = _getDb().transaction((nodes) => {
    for (const node of nodes) {
      stmt.run(userId, node.id, uuidv4());
    }
  });
  insertMany(nodes);
}

function rotateAllUserNodeUuids() {
  const rows = _getDb().prepare('SELECT id FROM user_node_uuid').all();
  const stmt = _getDb().prepare('UPDATE user_node_uuid SET uuid = ? WHERE id = ?');
  const updateMany = _getDb().transaction((rows) => {
    for (const row of rows) {
      stmt.run(uuidv4(), row.id);
    }
  });
  updateMany(rows);
  return rows.length;
}

function rotateUserNodeUuidsByNodeIds(nodeIds = []) {
  if (!Array.isArray(nodeIds) || nodeIds.length === 0) return 0;
  const placeholders = nodeIds.map(() => '?').join(',');
  const rows = _getDb().prepare(`SELECT id FROM user_node_uuid WHERE node_id IN (${placeholders})`).all(...nodeIds);
  const stmt = _getDb().prepare('UPDATE user_node_uuid SET uuid = ? WHERE id = ?');
  const updateMany = _getDb().transaction((rows) => {
    for (const row of rows) {
      stmt.run(uuidv4(), row.id);
    }
  });
  updateMany(rows);
  return rows.length;
}

module.exports = {
  init,
  getUserNodeUuid, getUserAllNodeUuids, getNodeAllUserUuids,
  ensureAllUsersHaveUuid, ensureUserHasAllNodeUuids,
  rotateAllUserNodeUuids, rotateUserNodeUuidsByNodeIds
};
