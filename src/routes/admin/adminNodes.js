const express = require('express');
const db = require('../../services/database');
const deployService = require('../../services/deploy');
const agentWs = require('../../services/agent-ws');
const { emitSyncAll, emitSyncNode } = require('../../services/configEvents');
const { parseIntId, isValidHost } = require('../../utils/validators');

const router = express.Router();

// 统一部署入口
router.post('/nodes/deploy-smart', (req, res) => {
  const { host, ssh_port, ssh_user, ssh_password, ss_method, enable_vless, enable_ss,
          socks5_host, socks5_port, socks5_user, socks5_pass } = req.body;
  if (!host || !ssh_password) return res.redirect('/admin#nodes');

  const vless = enable_vless === 'on';
  const ss = enable_ss === 'on';
  if (!vless && !ss) return res.redirect('/admin#nodes');

  const sshInfo = {
    host, ssh_port: parseInt(ssh_port) || 22, ssh_user: ssh_user || 'root', ssh_password,
    ss_method: ss_method || 'aes-256-gcm',
    socks5_host: socks5_host || null, socks5_port: parseInt(socks5_port) || 1080,
    socks5_user: socks5_user || null, socks5_pass: socks5_pass || null,
    triggered_by: req.user.id
  };

  if (vless && ss) {
    db.addAuditLog(req.user.id, 'node_deploy_dual_start', `开始双协议部署: ${host}`, req.clientIp || req.ip);
    deployService.deployDualNode(sshInfo, db).catch(err => console.error('[双协议部署异常]', err));
  } else if (vless) {
    db.addAuditLog(req.user.id, 'node_deploy_start', `开始VLESS部署: ${host}`, req.clientIp || req.ip);
    deployService.deployNode(sshInfo, db).catch(err => console.error('[部署异常]', err));
  } else {
    db.addAuditLog(req.user.id, 'node_deploy_ss_start', `开始SS部署: ${host}`, req.clientIp || req.ip);
    deployService.deploySsNode(sshInfo, db).catch(err => console.error('[SS部署异常]', err));
  }

  res.redirect('/admin?msg=deploying#nodes');
});

router.post('/nodes/deploy-dual', (req, res) => {
  const { host, ssh_port, ssh_user, ssh_password, ss_method, socks5_host, socks5_port, socks5_user, socks5_pass } = req.body;
  if (!host || !ssh_password) return res.redirect('/admin#nodes');

  db.addAuditLog(req.user.id, 'node_deploy_dual_start', `开始双协议部署: ${host}`, req.clientIp || req.ip);

  deployService.deployDualNode({
    host, ssh_port: parseInt(ssh_port) || 22, ssh_user: ssh_user || 'root', ssh_password,
    ss_method: ss_method || 'aes-256-gcm',
    socks5_host: socks5_host || null, socks5_port: parseInt(socks5_port) || 1080,
    socks5_user: socks5_user || null, socks5_pass: socks5_pass || null,
    triggered_by: req.user.id
  }, db).catch(err => console.error('[双协议部署异常]', err));

  res.redirect('/admin?msg=deploying#nodes');
});

router.post('/nodes/deploy-ss', (req, res) => {
  const { host, ssh_port, ssh_user, ssh_password, ss_method, socks5_host, socks5_port, socks5_user, socks5_pass } = req.body;
  if (!host || !ssh_password) return res.redirect('/admin#nodes');

  const existing = db.getAllNodes().find(n => n.ssh_host === host.trim() || n.host === host.trim());
  if (existing) {
    db.addAuditLog(req.user.id, 'node_deploy_dup', `重复 IP: ${host} (已有节点: ${existing.name})`, req.clientIp || req.ip);
    return res.redirect('/admin?msg=dup#nodes');
  }

  db.addAuditLog(req.user.id, 'node_deploy_ss_start', `开始SS部署: ${host}`, req.clientIp || req.ip);

  deployService.deploySsNode({
    host, ssh_port: parseInt(ssh_port) || 22, ssh_user: ssh_user || 'root', ssh_password,
    ss_method: ss_method || 'aes-256-gcm',
    socks5_host: socks5_host || null, socks5_port: parseInt(socks5_port) || 1080,
    socks5_user: socks5_user || null, socks5_pass: socks5_pass || null,
    triggered_by: req.user.id
  }, db).catch(err => console.error('[SS部署异常]', err));

  res.redirect('/admin?msg=deploying#nodes');
});

router.post('/nodes/deploy', (req, res) => {
  const { host, ssh_port, ssh_user, ssh_password, socks5_host, socks5_port, socks5_user, socks5_pass } = req.body;
  if (!host || !ssh_password) return res.redirect('/admin#nodes');
  if (!isValidHost(host)) return res.redirect('/admin?msg=invalid_host#nodes');

  const existing = db.getAllNodes().find(n => n.host === host.trim());
  if (existing) {
    db.addAuditLog(req.user.id, 'node_deploy_dup', `重复 IP: ${host} (已有节点: ${existing.name})`, req.clientIp || req.ip);
    return res.redirect('/admin?msg=dup#nodes');
  }

  db.addAuditLog(req.user.id, 'node_deploy_start', `开始部署: ${host}${socks5_host ? ' (socks5→' + socks5_host + ')' : ''}`, req.clientIp || req.ip);

  deployService.deployNode({
    host, ssh_port: parseInt(ssh_port) || 22, ssh_user: ssh_user || 'root', ssh_password,
    socks5_host: socks5_host || null, socks5_port: parseInt(socks5_port) || 1080,
    socks5_user: socks5_user || null, socks5_pass: socks5_pass || null,
    triggered_by: req.user.id
  }, db).catch(err => console.error('[部署异常]', err));

  res.redirect('/admin?msg=deploying#nodes');
});

router.post('/nodes/:id/delete', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const node = db.getNodeById(id);
  if (!node) return res.redirect('/admin#nodes');

  const stopCmd = 'systemctl stop xray && systemctl disable xray && systemctl stop vless-agent && systemctl disable vless-agent';

  (async () => {
    try {
      if (agentWs.isAgentOnline(node.id)) {
        await agentWs.sendCommand(node.id, { type: 'exec', command: stopCmd });
      } else if (node.ssh_password || node.ssh_key_path) {
        const { NodeSSH } = require('node-ssh');
        const ssh = new NodeSSH();
        const connectOpts = {
          host: node.ssh_host || node.host, port: node.ssh_port || 22,
          username: node.ssh_user || 'root', readyTimeout: 10000
        };
        if (node.ssh_key_path) connectOpts.privateKeyPath = node.ssh_key_path;
        else connectOpts.password = node.ssh_password;
        await ssh.connect(connectOpts);
        await ssh.execCommand(stopCmd, { execOptions: { timeout: 15000 } });
        ssh.dispose();
      }
    } catch (err) {
      console.error(`[删除节点] 停止远端服务失败: ${err.message}`);
    }
    db.deleteNode(node.id);
    db.addAuditLog(req.user.id, 'node_delete', `删除节点: ${node.name}`, req.clientIp || req.ip);
  })();

  res.redirect('/admin#nodes');
});

router.post('/nodes/:id/update-host', (req, res) => {
  const { host } = req.body;
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  if (!host || !isValidHost(host)) return res.status(400).json({ error: 'host 格式非法' });
  const node = db.getNodeById(id);
  if (node && host?.trim()) {
    const oldHost = node.host;
    db.updateNode(node.id, { host: host.trim(), ssh_host: host.trim() });
    db.addAuditLog(req.user.id, 'node_update_ip', `${node.name} IP变更: ${oldHost} → ${host.trim()}`, req.clientIp || req.ip);
  }
  res.redirect('/admin#nodes');
});

router.post('/nodes/:id/update-level', async (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const node = db.getNodeById(id);
  const level = parseInt(req.body.level) || 0;
  if (node) {
    db.updateNode(node.id, { min_level: Math.max(0, Math.min(4, level)) });
    db.addAuditLog(req.user.id, 'node_update_level', `${node.name} 等级: Lv.${level}`, req.clientIp || req.ip);
    emitSyncNode(node);
  }
  res.json({ ok: true });
});

router.post('/health-check', async (req, res) => {
  try {
    const agents = agentWs.getConnectedAgents();
    const nodes = db.getAllNodes();
    const onlineNodeIds = new Set(agents.map(a => a.nodeId));
    const results = [];

    const pings = agents.map(async (a) => {
      const result = await agentWs.sendCommand(a.nodeId, { type: 'ping' });
      return { nodeId: a.nodeId, name: a.nodeName, online: result.success, agent: true, sshHost: (nodes.find(n=>n.id===a.nodeId)||{}).ssh_host || '' };
    });
    const pingResults = await Promise.all(pings);
    results.push(...pingResults);

    for (const n of nodes) {
      if (!onlineNodeIds.has(n.id)) {
        results.push({ nodeId: n.id, name: n.name, online: false, agent: false, sshHost: n.ssh_host || '' });
      }
    }

    db.addAuditLog(req.user.id, 'health_check', `Agent 健康检测: ${agents.length}/${nodes.length} 在线`, req.clientIp || req.ip);
    res.json({ ok: true, results });
  } catch (err) {
    console.error('[健康检测]', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

router.post('/rotate', (req, res) => {
  const rotateService = require('../../services/rotate');
  db.addAuditLog(req.user.id, 'manual_rotate', '手动轮换（后台执行中）', req.clientIp || req.ip);
  res.redirect('/admin#nodes');
  rotateService.rotateManual().catch(err => console.error('[手动轮换] 失败:', err));
});

router.post('/nodes/:id/restart-xray', async (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const node = db.getNodeById(id);
  if (!node) return res.status(404).json({ error: '节点不存在' });
  if (!agentWs.isAgentOnline(node.id)) {
    return res.json({ success: false, error: 'Agent 不在线' });
  }
  const result = await agentWs.sendCommand(node.id, { type: 'restart_xray' });
  db.addAuditLog(req.user.id, 'restart_xray', `重启 Xray: ${node.name}`, req.clientIp || req.ip);
  res.json(result);
});

// Sprint 6: 更新节点分组/标签
router.post('/nodes/:id/update-group', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const node = db.getNodeById(id);
  if (!node) return res.status(404).json({ error: '节点不存在' });
  const { group_name, tags } = req.body;
  db.updateNode(id, {
    group_name: (group_name || '').trim(),
    tags: (tags || '').trim()
  });
  db.addAuditLog(req.user.id, 'node_update_group', `${node.name} 分组: ${group_name || '无'}, 标签: ${tags || '无'}`, req.clientIp || req.ip);
  res.json({ ok: true });
});

// 更新节点 SS/IPv6 配置
router.post('/nodes/:id/update-ss', (req, res) => {
  const id = parseIntId(req.params.id);
  if (!id) return res.status(400).json({ error: '参数错误' });
  const node = db.getNodeById(id);
  if (!node) return res.status(404).json({ error: '节点不存在' });
  const { protocol, ip_version, ss_method, ss_password } = req.body;
  const updates = {};
  if (protocol) updates.protocol = protocol;
  if (ip_version !== undefined) updates.ip_version = parseInt(ip_version) || 4;
  if (ss_method) updates.ss_method = ss_method;
  if (ss_password !== undefined) updates.ss_password = ss_password;
  db.updateNode(id, updates);
  db.addAuditLog(req.user.id, 'node_update_ss', `${node.name} SS配置: protocol=${protocol}, ipv=${ip_version}`, req.clientIp || req.ip);
  res.json({ ok: true });
});

// 手动添加节点（SS/IPv6）
router.post('/nodes/manual', (req, res) => {
  const { name, host, port, protocol, ip_version, region, ss_method, ss_password } = req.body;
  if (!name || !host || !port) return res.status(400).json({ error: '缺少必填字段' });
  const p = parseInt(port);
  if (!p || p < 1 || p > 65535) return res.status(400).json({ error: '端口无效' });

  const proto = protocol === 'ss' ? 'ss' : 'vless';
  const ipv = parseInt(ip_version) === 6 ? 6 : 4;

  const { v4: uuidv4 } = require('uuid');
  const nodeData = {
    name: name.trim(),
    host: host.trim(),
    port: p,
    uuid: uuidv4(), // SS 不用但字段 NOT NULL
    protocol: proto,
    ip_version: ipv,
    region: (region || '').trim(),
    is_manual: 1,
  };

  const result = db.addNode(nodeData);
  const nodeId = result.lastInsertRowid;

  // SS 特有字段通过 updateNode 写入
  if (proto === 'ss') {
    db.updateNode(nodeId, {
      ss_method: ss_method || 'aes-256-gcm',
      ss_password: ss_password || '',
    });
  }
  // ip_version 也通过 updateNode 写入
  db.updateNode(nodeId, { ip_version: ipv });

  db.addAuditLog(req.user.id, 'node_add_manual', `手动添加节点: ${name} (${proto}/IPv${ipv})`, req.clientIp || req.ip);
  res.json({ ok: true, id: nodeId });
});

module.exports = router;
