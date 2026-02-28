const { NodeSSH } = require('node-ssh');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { randomPort } = require('../utils/vless');
const { BEAUTIFUL_NAMES } = require('../utils/names');
const { notify } = require('./notify');

// 地区 emoji 映射
const REGION_EMOJI = {
  'singapore': '🇸🇬', 'tokyo': '🇯🇵', 'japan': '🇯🇵', 'osaka': '🇯🇵', 'chiyoda': '🇯🇵',
  'seoul': '🇰🇷', 'korea': '🇰🇷', 'hong kong': '🇭🇰', 'hongkong': '🇭🇰',
  'taiwan': '🇹🇼', 'mumbai': '🇮🇳', 'india': '🇮🇳',
  'sydney': '🇦🇺', 'australia': '🇦🇺',
  'london': '🇬🇧', 'uk': '🇬🇧', 'united kingdom': '🇬🇧',
  'frankfurt': '🇩🇪', 'germany': '🇩🇪',
  'paris': '🇫🇷', 'france': '🇫🇷',
  'amsterdam': '🇳🇱', 'netherlands': '🇳🇱',
  'virginia': '🇺🇸', 'ohio': '🇺🇸', 'oregon': '🇺🇸', 'california': '🇺🇸', 'portland': '🇺🇸', 'minkler': '🇺🇸', 'ashburn': '🇺🇸', 'san jose': '🇺🇸',
  'us': '🇺🇸', 'united states': '🇺🇸', 'america': '🇺🇸',
  'canada': '🇨🇦', 'brazil': '🇧🇷', 'são paulo': '🇧🇷',
};

const CITY_CN = {
  'singapore': '新加坡', 'tokyo': '东京', 'osaka': '大阪', 'chiyoda': '千代田', 'chiyoda city': '千代田',
  'seoul': '首尔', 'hong kong': '香港', 'hongkong': '香港',
  'taipei': '台北', 'mumbai': '孟买', 'sydney': '悉尼',
  'london': '伦敦', 'frankfurt': '法兰克福', 'paris': '巴黎',
  'amsterdam': '阿姆斯特丹', 'virginia': '弗吉尼亚', 'ohio': '俄亥俄',
  'oregon': '俄勒冈', 'california': '加利福尼亚', 'portland': '波特兰', 'minkler': '明克勒', 'ashburn': '阿什本', 'san jose': '圣何塞', 'são paulo': '圣保罗',
  'toronto': '多伦多', 'jakarta': '雅加达', 'bangkok': '曼谷',
  'dubai': '迪拜', 'stockholm': '斯德哥尔摩', 'dublin': '都柏林',
  'milan': '米兰', 'zurich': '苏黎世', 'warsaw': '华沙',
  'cape town': '开普敦', 'bahrain': '巴林',
};

function getRegionEmoji(city, country) {
  const key = `${city || ''} ${country || ''}`.toLowerCase();
  for (const [k, v] of Object.entries(REGION_EMOJI)) {
    if (key.includes(k)) return v;
  }
  return '🌐';
}

function getCityCN(city) {
  const key = (city || '').toLowerCase();
  for (const [k, v] of Object.entries(CITY_CN)) {
    if (key.includes(k)) return v;
  }
  return city || '未知';
}

async function detectRegion(ip) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city&lang=en`);
    const data = await res.json();
    if (data.status === 'success') {
      return {
        city: data.city, region: data.regionName, country: data.country,
        cityCN: getCityCN(data.city),
        emoji: getRegionEmoji(data.city, data.country)
      };
    }
  } catch (e) {
    console.error(`[地区检测] ${ip} 失败:`, e.message);
  }
  return { city: 'Unknown', region: '', country: '', cityCN: '未知', emoji: '🌐' };
}

function generateNodeName(geo, existingNodes, hasSocks5 = false) {
  const city = geo.cityCN;
  // 命名规则：普通=小国旗；家宽落地=小国旗+小房子
  const prefix = hasSocks5 ? `${geo.emoji}🏠` : geo.emoji;
  const usedNames = new Set(existingNodes.map(n => {
    const match = n.name.match(/-(.{4})$/);
    return match ? match[1] : '';
  }));
  const available = BEAUTIFUL_NAMES.filter(n => !usedNames.has(n));
  const name = available.length > 0
    ? available[Math.floor(Math.random() * available.length)]
    : BEAUTIFUL_NAMES[Math.floor(Math.random() * BEAUTIFUL_NAMES.length)];
  return `${prefix} ${city}-${name}`;
}

// 统一生成 xray client email（仅用于识别/统计，避免暴露真实信息）
function makeEmail(userId, protocol = '') {
  const safe = String(userId ?? '0').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || '0';
  // 协议后缀用于 Agent 统计按协议拆分：
  // vless -> u-<id>-v@p, ss -> u-<id>-s@p
  const suffix = protocol === 'ss' ? '-s' : (protocol === 'vless' ? '-v' : '');
  return `u-${safe}${suffix}@p`;
}

function buildOutboundsBySocks(socks5Host, socks5Port, socks5User, socks5Pass) {
  if (socks5Host) {
    const socks5Server = { address: socks5Host, port: parseInt(socks5Port, 10) || 1080 };
    if (socks5User) socks5Server.users = [{ user: socks5User, pass: socks5Pass || '' }];
    return [
      { protocol: 'socks', tag: 'socks5-out', settings: { servers: [socks5Server] } },
      { protocol: 'freedom', tag: 'direct' }
    ];
  }
  return [
    { protocol: 'freedom', tag: 'direct' },
    { protocol: 'blackhole', tag: 'blocked' }
  ];
}

// ========== 生成 xray 多用户配置 ==========

// 生成完整 xray 配置（多用户 + stats + API + Reality）
function buildXrayConfig(port, clients, outbounds, realityOpts) {
  const streamSettings = { network: 'tcp', security: 'reality' };
  if (realityOpts) {
    // Reality 模式下 clients 需要 flow
    clients = clients.map(c => ({ ...c, flow: 'xtls-rprx-vision' }));
    streamSettings.realitySettings = {
      show: false,
      dest: `${realityOpts.sni}:443`,
      xver: 0,
      serverNames: [realityOpts.sni],
      privateKey: realityOpts.privateKey,
      shortIds: [realityOpts.shortId]
    };
  }
  return {
    log: { loglevel: 'warning' },
    stats: {},
    api: { tag: 'api', services: ['StatsService'] },
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    inbounds: [
      {
        port,
        protocol: 'vless',
        tag: 'vless-in',
        settings: { clients, decryption: 'none' },
        streamSettings
      },
      {
        listen: '127.0.0.1', port: 10085,
        protocol: 'dokodemo-door', tag: 'api-in',
        settings: { address: '127.0.0.1' }
      }
    ],
    outbounds,
    routing: {
      rules: [
        { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' },
        ...(outbounds[0]?.tag === 'socks5-out'
          ? [{ type: 'field', outboundTag: 'socks5-out', network: 'tcp,udp' }]
          : [])
      ]
    }
  };
}

// ========== SFTP 安全写文件 ==========

// 通过 SFTP 写文件，避免 heredoc 注入风险
async function sftpWriteFile(ssh, remotePath, content) {
  const sftp = await ssh.requestSFTP();
  return new Promise((resolve, reject) => {
    const stream = sftp.createWriteStream(remotePath, { mode: 0o644 });
    stream.on('error', reject);
    stream.on('close', resolve);
    stream.end(Buffer.from(content, 'utf8'));
  });
}

// ========== SSH 推送配置 ==========

// 将配置推送到节点并重启 xray（优先通过 Agent，SSH 后备）
async function pushConfigToNode(node, config) {
  const configJson = typeof config === 'string' ? config : JSON.stringify(config, null, 2);

  // 优先通过 Agent 推送
  const agentWs = require('./agent-ws'); // 延迟加载避免循环依赖
  if (agentWs.isAgentOnline(node.id)) {
    try {
      const result = await agentWs.sendCommand(node.id, {
        type: 'update_config',
        config: config,
      });
      if (result.success) {
        return true;
      }
      console.log(`[推送配置] ${node.name} Agent 推送失败: ${result.error}，回退 SSH`);
    } catch (e) {
      console.log(`[推送配置] ${node.name} Agent 异常: ${e.message}，回退 SSH`);
    }
  }

  // SSH 后备
  const ssh = new NodeSSH();
  try {
    const connectOpts = {
      host: node.ssh_host || node.host,
      port: node.ssh_port || 22,
      username: node.ssh_user || 'root',
    };
    if (node.ssh_key_path) connectOpts.privateKeyPath = node.ssh_key_path;
    else if (node.ssh_password) connectOpts.password = node.ssh_password;

    await ssh.connect(connectOpts);

    const configPath = node.xray_config_path || '/usr/local/etc/xray/config.json';

    await sftpWriteFile(ssh, configPath, configJson);
    const result = await ssh.execCommand('systemctl restart xray && sleep 1 && systemctl is-active --quiet xray && echo OK || echo FAIL');

    const ok = result.stdout.trim() === 'OK';
    return ok;
  } catch (err) {
    console.error(`[推送配置] ${node.name} SSH 失败: ${err.message}`);
    return false;
  } finally {
    ssh.dispose();
  }
}

// 同步某个节点的配置（用于新用户注册、轮换等场景）
async function syncNodeConfig(node, db) {
  const userUuids = db.getNodeAllUserUuids(node.id);
  if (userUuids.length === 0) return false;

  // SS 节点：使用 SS 多用户配置
  if (node.protocol === 'ss') {
    const clients = userUuids.map(u => ({
      password: u.uuid, email: makeEmail(u.user_id, 'ss')
    }));
    const ssOutbounds = buildOutboundsBySocks(node.socks5_host, node.socks5_port, node.socks5_user, node.socks5_pass);
    const config = buildSsXrayConfig(node.port, clients, node.ss_method || 'aes-256-gcm', ssOutbounds);

    // 如果有同机 VLESS 伙伴节点，生成双协议配置
    const peerNode = findPeerNode(node, db);
    if (peerNode) {
      const vlessUuids = db.getNodeAllUserUuids(peerNode.id);
      if (vlessUuids.length > 0) {
        const vlessClients = vlessUuids.map(u => ({
          id: u.uuid, level: 0, email: makeEmail(u.user_id, 'vless')
        }));
        const outbounds = buildOutboundsBySocks(peerNode.socks5_host, peerNode.socks5_port, peerNode.socks5_user, peerNode.socks5_pass);
        const realityOpts = peerNode.reality_private_key ? { privateKey: peerNode.reality_private_key, sni: peerNode.sni || 'www.microsoft.com', shortId: peerNode.reality_short_id } : null;
        const dualConfig = buildDualXrayConfig(peerNode.port, node.port, vlessClients, clients, node.ss_method || 'aes-256-gcm', outbounds, realityOpts);
        return await pushConfigToNode(node, dualConfig);
      }
    }
    return await pushConfigToNode(node, config);
  }

  // VLESS 节点
  const clients = userUuids.map(u => ({
    id: u.uuid, level: 0, email: makeEmail(u.user_id, 'vless')
  }));

  let outbounds;
  if (node.socks5_host) {
    const socks5Server = { address: node.socks5_host, port: node.socks5_port || 1080 };
    if (node.socks5_user) socks5Server.users = [{ user: node.socks5_user, pass: node.socks5_pass || '' }];
    outbounds = [
      { protocol: 'socks', tag: 'socks5-out', settings: { servers: [socks5Server] } },
      { protocol: 'freedom', tag: 'direct' }
    ];
  } else {
    outbounds = [
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'blackhole', tag: 'blocked' }
    ];
  }

  const realityOpts = node.reality_private_key ? { privateKey: node.reality_private_key, sni: node.sni || 'www.microsoft.com', shortId: node.reality_short_id } : null;

  // 如果有同机 SS 伙伴节点，生成双协议配置
  const peerNode = findPeerNode(node, db);
  if (peerNode) {
    const ssUuids = db.getNodeAllUserUuids(peerNode.id);
    if (ssUuids.length > 0) {
      const ssClients = ssUuids.map(u => ({
        password: u.uuid, email: makeEmail(u.user_id, 'ss')
      }));
      const dualConfig = buildDualXrayConfig(node.port, peerNode.port, clients, ssClients, peerNode.ss_method || 'aes-256-gcm', outbounds, realityOpts);
      return await pushConfigToNode(node, dualConfig);
    }
  }

  const config = buildXrayConfig(node.port, clients, outbounds, realityOpts);
  return await pushConfigToNode(node, config);
}

// 查找同机伙伴节点（同 ssh_host 的另一个协议节点）
function findPeerNode(node, db) {
  const sshHost = node.ssh_host || node.host;
  const allNodes = db.getAllNodes(true);
  return allNodes.find(n =>
    n.id !== node.id &&
    (n.ssh_host || n.host) === sshHost &&
    n.protocol !== node.protocol
  ) || null;
}

// 同步所有活跃节点的配置
// 去抖版本：短时间多次调用只执行最后一次
let _syncDebounceTimer = null;
let _syncDebounceResolvers = [];

function syncAllNodesConfigDebounced(db) {
  return new Promise((resolve, reject) => {
    _syncDebounceResolvers.push({ resolve, reject });
    if (_syncDebounceTimer) clearTimeout(_syncDebounceTimer);
    _syncDebounceTimer = setTimeout(async () => {
      _syncDebounceTimer = null;
      const resolvers = _syncDebounceResolvers;
      _syncDebounceResolvers = [];
      try {
        const result = await _syncAllNodesConfigImpl(db);
        resolvers.forEach(r => r.resolve(result));
      } catch (err) {
        resolvers.forEach(r => r.reject(err));
      }
    }, 3000);
  });
}

async function _syncAllNodesConfigImpl(db) {
  const nodes = db.getAllNodes(true);
  let success = 0, failed = 0;
  const CONCURRENCY = 5;
  for (let i = 0; i < nodes.length; i += CONCURRENCY) {
    const batch = nodes.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(n => syncNodeConfig(n, db).catch(() => false)));
    for (const ok of results) { if (ok) success++; else failed++; }
  }
  console.log(`[配置同步] 完成 成功:${success} 失败:${failed}`);
  if (failed > 0) {
    const db2 = require('./database'); // 延迟加载避免循环依赖
    db2.addAuditLog(null, 'config_sync', `配置同步完成 成功:${success} 失败:${failed}`, 'system');
  }
  return { success, failed };
}

// ========== 部署函数 ==========

async function deployNode(sshInfo, db) {
  const uuid = uuidv4();
  const port = randomPort();

  const geo = await detectRegion(sshInfo.host);

  let displayGeo = geo;
  let isHomeNetwork = false;
  if (sshInfo.socks5_host) {
    isHomeNetwork = true;
    const socks5Geo = await detectRegion(sshInfo.socks5_host);
    // 家宽是内网 IP 时，地区查询会失败（Unknown），回退到节点公网地区
    if (socks5Geo.city && socks5Geo.city !== 'Unknown' && socks5Geo.cityCN !== '未知') {
      displayGeo = socks5Geo;
    }
  }

  const existingNodes = db.getAllNodes();
  const name = generateNodeName(displayGeo, existingNodes, isHomeNetwork);
  const region = `${displayGeo.emoji} ${displayGeo.cityCN}`;

  const nodeData = {
    name, host: sshInfo.host, port, uuid,
    ssh_host: sshInfo.host,
    ssh_port: sshInfo.ssh_port || 22,
    ssh_user: sshInfo.ssh_user || 'root',
    ssh_password: sshInfo.ssh_password,
    ssh_key_path: sshInfo.ssh_key_path,
    socks5_host: sshInfo.socks5_host || null,
    socks5_port: parseInt(sshInfo.socks5_port) || 1080,
    socks5_user: sshInfo.socks5_user || null,
    socks5_pass: sshInfo.socks5_pass || null,
    region,
    remark: '⏳ 部署中...',
    is_active: 0
  };
  const result = db.addNode(nodeData);
  const nodeId = result.lastInsertRowid;

  // 为所有现有用户在新节点生成 UUID
  db.ensureAllUsersHaveUuid(nodeId);

  const ssh = new NodeSSH();
  try {
    const connectOpts = {
      host: sshInfo.host,
      port: sshInfo.ssh_port || 22,
      username: sshInfo.ssh_user || 'root',
    };
    if (sshInfo.ssh_key_path) connectOpts.privateKeyPath = sshInfo.ssh_key_path;
    else if (sshInfo.ssh_password) connectOpts.password = sshInfo.ssh_password;

    console.log(`[部署] ${name} (${sshInfo.host}) 开始...`);
    await ssh.connect(connectOpts);

    // 先安装 xray
    const installScript = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'install-xray.sh'), 'utf8').trim();

    const installResult = await ssh.execCommand(installScript, { execOptions: { timeout: 180000 } });
    if (!installResult.stdout.includes('INSTALL_OK')) {
      throw new Error('xray 安装失败: ' + (installResult.stderr || installResult.stdout).substring(0, 200));
    }

    // 生成 Reality 密钥对
    const keyResult = await ssh.execCommand('xray x25519');
    const output = keyResult.stdout + '\n' + keyResult.stderr;
    // 兼容新旧版本: 旧版 "Private key:" / "Public key:", 新版 "PrivateKey:" / "Password:"
    const privMatch = output.match(/Private\s*[Kk]ey:\s*(\S+)/);
    const pubMatch = output.match(/Public\s*[Kk]ey:\s*(\S+)/) || output.match(/Password:\s*(\S+)/);
    if (!privMatch || !pubMatch) throw new Error('Reality 密钥生成失败: ' + output.substring(0, 200));
    const realityPrivateKey = privMatch[1];
    const realityPublicKey = pubMatch[1];
    const realityShortId = crypto.randomBytes(4).toString('hex');
    const sni = 'www.microsoft.com';

    db.updateNode(nodeId, { reality_private_key: realityPrivateKey, reality_public_key: realityPublicKey, reality_short_id: realityShortId, sni });

    // 生成多用户配置
    const userUuids = db.getNodeAllUserUuids(nodeId);
    const clients = userUuids.length > 0
      ? userUuids.map(u => ({ id: u.uuid, level: 0, email: makeEmail(u.user_id, 'vless') }))
      : [{ id: uuid, level: 0, email: 'default@panel' }];

    let outbounds;
    if (sshInfo.socks5_host) {
      let socks5Settings = { address: sshInfo.socks5_host, port: parseInt(sshInfo.socks5_port) || 1080 };
      if (sshInfo.socks5_user) {
        socks5Settings.users = [{ user: sshInfo.socks5_user, pass: sshInfo.socks5_pass || '' }];
      }
      outbounds = [
        { protocol: 'socks', tag: 'socks5-out', settings: { servers: [socks5Settings] } },
        { protocol: 'freedom', tag: 'direct' }
      ];
    } else {
      outbounds = [
        { protocol: 'freedom', tag: 'direct' },
        { protocol: 'blackhole', tag: 'blocked' }
      ];
    }

    const config = buildXrayConfig(port, clients, outbounds, { privateKey: realityPrivateKey, sni, shortId: realityShortId });
    const configJson = JSON.stringify(config, null, 2);
    const configPath = '/usr/local/etc/xray/config.json';

    await ssh.execCommand('mkdir -p /usr/local/etc/xray');
    await sftpWriteFile(ssh, configPath, configJson);
    const startResult = await ssh.execCommand('systemctl enable xray && systemctl restart xray && sleep 2 && systemctl is-active --quiet xray && echo DEPLOY_OK || echo DEPLOY_FAIL');

    if (startResult.stdout.includes('DEPLOY_OK')) {
      db.updateNode(nodeId, { is_active: 1, remark: sshInfo.socks5_host ? '🏠 家宽落地' : '' });
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy', `部署成功: ${name} (${sshInfo.host}:${port}) [${clients.length}用户]`, 'system');
      console.log(`[部署成功] ${name} (${sshInfo.host}:${port}) ${clients.length}个用户`);

      // TG 通知
      try { notify.deploy(name, true, `IP: ${sshInfo.host}:${port} | ${clients.length}个用户`); } catch {}

      // 自动安装 Agent
      try {
        await installAgentOnNode(ssh, nodeId, db);
      } catch (agentErr) {
        console.error(`[Agent安装] ${name} 失败: ${agentErr.message}`);
      }
    } else {
      const errMsg = (startResult.stderr || startResult.stdout).substring(0, 200);
      db.updateNode(nodeId, { remark: `❌ 部署失败: ${errMsg}` });
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_fail', `部署失败: ${name} - ${errMsg}`, 'system');
      console.error(`[部署失败] ${name}: ${errMsg}`);
      try { notify.deploy(name, false, errMsg); } catch {}
    }
  } catch (err) {
    db.updateNode(nodeId, { remark: `❌ ${err.message}` });
    db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_fail', `部署异常: ${name} - ${err.message}`, 'system');
    console.error(`[部署异常] ${name}: ${err.message}`);
    try { notify.deploy(name, false, err.message); } catch {}
  } finally {
    ssh.dispose();
  }
}

/**
 * 通过已有 SSH 连接在节点上安装 Agent
 */
async function installAgentOnNode(ssh, nodeId, db) {
  // 获取节点独立 token
  const node = db.getNodeById(nodeId);
  const agentToken = node?.agent_token;
  if (!agentToken) {
    console.log('[Agent安装] 节点无 agent_token，跳过');
    return;
  }
  const serverUrl = process.env.AGENT_WS_URL || 'wss://vip.vip.sd/ws/agent';

  console.log(`[Agent安装] 节点#${nodeId} 开始安装...`);

  // 安装 Node.js（如果没有）
  const nodeCheck = await ssh.execCommand('command -v node && node -v || echo "NO_NODE"', { execOptions: { timeout: 10000 } });
  if (nodeCheck.stdout.includes('NO_NODE')) {
    console.log(`[Agent安装] 节点#${nodeId} 安装 Node.js...`);
    const installNode = await ssh.execCommand(
      'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs',
      { execOptions: { timeout: 180000 } }
    );
    if (installNode.code !== 0 && installNode.code !== null) {
      throw new Error('Node.js 安装失败: ' + (installNode.stderr || '').substring(0, 200));
    }
  }

  // 读取 agent.js 内容并通过 SSH 写入节点
  const agentJsPath = path.join(__dirname, '..', '..', 'node-agent', 'agent.js');
  const agentCode = fs.readFileSync(agentJsPath, 'utf8');

  // 写入 agent.js
  await ssh.execCommand('mkdir -p /opt/vless-agent');
  await sftpWriteFile(ssh, '/opt/vless-agent/agent.js', agentCode);
  await ssh.execCommand('chmod 755 /opt/vless-agent/agent.js');

  // 写入配置（根据协议决定是否开启 IPv6 检测）
  const needCheckIPv6 = node.protocol === 'ss' || !!findPeerNode(node, db);
  const configJson = JSON.stringify({ server: serverUrl, token: agentToken, nodeId, checkIPv6: needCheckIPv6 }, null, 2);
  await ssh.execCommand('mkdir -p /etc/vless-agent');
  await sftpWriteFile(ssh, '/etc/vless-agent/config.json', configJson);
  await ssh.execCommand('chmod 600 /etc/vless-agent/config.json');

  // 创建 systemd service 并启动
  const nodeBin = (await ssh.execCommand('which node')).stdout.trim() || '/usr/bin/node';
  const serviceTemplate = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'vless-agent.service'), 'utf8');
  const serviceContent = serviceTemplate.replace('{{NODE_BIN}}', nodeBin).trim();

  await sftpWriteFile(ssh, '/etc/systemd/system/vless-agent.service', serviceContent);
  await ssh.execCommand('systemctl daemon-reload && systemctl enable vless-agent && systemctl restart vless-agent');

  console.log(`[Agent安装] 节点#${nodeId} Agent 安装完成`);
}

// ========== IPv6 SS 自动部署 ==========

// 生成 SS 多用户 xray 配置（带 stats）
function buildSsXrayConfig(port, clients, ssMethod, outbounds = null) {
  const finalOutbounds = Array.isArray(outbounds) && outbounds.length > 0
    ? outbounds
    : [
      { tag: 'direct', protocol: 'freedom' },
      { tag: 'block', protocol: 'blackhole' }
    ];
  return {
    log: { loglevel: 'warning' },
    stats: {},
    api: { tag: 'api', services: ['StatsService'] },
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    inbounds: [
      {
        port, listen: '::', protocol: 'shadowsocks', tag: 'ss-in',
        settings: {
          clients: clients.map(c => ({
            password: c.password, email: c.email, method: ssMethod, level: 0
          })),
          network: 'tcp,udp'
        }
      },
      {
        listen: '127.0.0.1', port: 10085,
        protocol: 'dokodemo-door', tag: 'api-in',
        settings: { address: '127.0.0.1' }
      }
    ],
    outbounds: finalOutbounds,
    routing: {
      rules: [
        { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' },
        ...(finalOutbounds[0]?.tag === 'socks5-out'
          ? [{ type: 'field', outboundTag: 'socks5-out', network: 'tcp,udp' }]
          : [])
      ]
    }
  };
}

// 生成双协议 xray 配置（VLESS IPv4 + SS IPv6）
function buildDualXrayConfig(vlessPort, ssPort, vlessClients, ssClients, ssMethod, outbounds, realityOpts) {
  const vlessStreamSettings = { network: 'tcp', security: 'reality' };
  const vlessClientsWithFlow = vlessClients.map(c => ({ ...c, flow: 'xtls-rprx-vision' }));
  if (realityOpts) {
    vlessStreamSettings.realitySettings = {
      show: false,
      dest: `${realityOpts.sni}:443`,
      xver: 0,
      serverNames: [realityOpts.sni],
      privateKey: realityOpts.privateKey,
      shortIds: [realityOpts.shortId]
    };
  }
  return {
    log: { loglevel: 'warning' },
    stats: {},
    api: { tag: 'api', services: ['StatsService'] },
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    inbounds: [
      {
        port: vlessPort, listen: '0.0.0.0', protocol: 'vless', tag: 'vless-in',
        settings: { clients: vlessClientsWithFlow, decryption: 'none' },
        streamSettings: vlessStreamSettings
      },
      {
        port: ssPort, listen: '::', protocol: 'shadowsocks', tag: 'ss-in',
        settings: {
          clients: ssClients.map(c => ({
            password: c.password, email: c.email, method: ssMethod, level: 0
          })),
          network: 'tcp,udp'
        }
      },
      {
        listen: '127.0.0.1', port: 10085,
        protocol: 'dokodemo-door', tag: 'api-in',
        settings: { address: '127.0.0.1' }
      }
    ],
    outbounds,
    routing: {
      rules: [
        { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' },
        ...(outbounds[0]?.tag === 'socks5-out'
          ? [{ type: 'field', outboundTag: 'socks5-out', network: 'tcp,udp' }]
          : [])
      ]
    }
  };
}

async function deploySsNode(sshInfo, db) {
  // 确保数据库已初始化
  if (typeof db.getDb === 'function') db.getDb();

  const port = randomPort();
  const ssPassword = crypto.randomBytes(16).toString('base64');
  const ssMethod = sshInfo.ss_method || 'aes-256-gcm';

  const geo = await detectRegion(sshInfo.host);
  let displayGeo = geo;
  const hasSocks5 = !!sshInfo.socks5_host;
  if (hasSocks5) {
    const socks5Geo = await detectRegion(sshInfo.socks5_host);
    if (socks5Geo.city && socks5Geo.city !== 'Unknown' && socks5Geo.cityCN !== '未知') {
      displayGeo = socks5Geo;
    }
  }
  const existingNodes = db.getAllNodes();
  const name = generateNodeName(displayGeo, existingNodes, hasSocks5);
  const region = `${displayGeo.emoji} ${displayGeo.cityCN}`;

  const nodeData = {
    name, host: sshInfo.host, port, uuid: '00000000-0000-0000-0000-000000000000',
    protocol: 'ss', ip_version: 6, ss_method: ssMethod, ss_password: ssPassword,
    ssh_host: sshInfo.host,
    ssh_port: sshInfo.ssh_port || 22,
    ssh_user: sshInfo.ssh_user || 'root',
    ssh_password: sshInfo.ssh_password,
    socks5_host: sshInfo.socks5_host || null,
    socks5_port: parseInt(sshInfo.socks5_port, 10) || 1080,
    socks5_user: sshInfo.socks5_user || null,
    socks5_pass: sshInfo.socks5_pass || null,
    region, remark: '⏳ 部署中...', is_active: 0
  };
  const result = db.addNode(nodeData);
  const nodeId = result.lastInsertRowid;

  const ssh = new NodeSSH();
  try {
    const connectOpts = {
      host: sshInfo.host,
      port: sshInfo.ssh_port || 22,
      username: sshInfo.ssh_user || 'root',
    };
    if (sshInfo.ssh_key_path) connectOpts.privateKeyPath = sshInfo.ssh_key_path;
    else if (sshInfo.ssh_password) connectOpts.password = sshInfo.ssh_password;

    console.log(`[SS部署] ${name} (${sshInfo.host}) 开始...`);
    await ssh.connect(connectOpts);

    // 检测 IPv6 地址
    const ipv6Result = await ssh.execCommand("ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' | cut -d/ -f1");
    const ipv6Addr = (ipv6Result.stdout || '').trim();
    if (!ipv6Addr) {
      throw new Error('服务器没有 IPv6 地址');
    }
    console.log(`[SS部署] 检测到 IPv6: ${ipv6Addr}`);

    // 更新节点 host 为 IPv6 地址
    db.updateNode(nodeId, { host: ipv6Addr });

    // 安装 xray
    const installScript = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'install-xray.sh'), 'utf8').trim();
    const installResult = await ssh.execCommand(installScript, { execOptions: { timeout: 180000 } });
    if (!installResult.stdout.includes('INSTALL_OK')) {
      throw new Error('xray 安装失败: ' + (installResult.stderr || installResult.stdout).substring(0, 200));
    }

    // 为所有现有用户在新节点生成 UUID（用作 SS 密码）
    db.ensureAllUsersHaveUuid(nodeId);

    // 生成多用户 SS 配置（带 stats）
    const userUuids = db.getNodeAllUserUuids(nodeId);
    const clients = userUuids.length > 0
      ? userUuids.map(u => ({ password: u.uuid, email: makeEmail(u.user_id, 'ss') }))
      : [{ password: ssPassword, email: 'default@panel' }];

    const outbounds = buildOutboundsBySocks(sshInfo.socks5_host, sshInfo.socks5_port, sshInfo.socks5_user, sshInfo.socks5_pass);
    const config = buildSsXrayConfig(port, clients, ssMethod, outbounds);
    const configJson = JSON.stringify(config, null, 2);
    await ssh.execCommand('mkdir -p /usr/local/etc/xray');
    await sftpWriteFile(ssh, '/usr/local/etc/xray/config.json', configJson);

    // 开放防火墙端口
    await ssh.execCommand(`
      iptables -C INPUT -p tcp --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
      iptables -C INPUT -p udp --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${port} -j ACCEPT
      ip6tables -C INPUT -p tcp --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport ${port} -j ACCEPT
      ip6tables -C INPUT -p udp --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport ${port} -j ACCEPT
      command -v netfilter-persistent &>/dev/null && netfilter-persistent save || true
    `);

    // 启动 xray
    const startResult = await ssh.execCommand('systemctl enable xray && systemctl restart xray && sleep 2 && systemctl is-active --quiet xray && echo DEPLOY_OK || echo DEPLOY_FAIL');

    if (startResult.stdout.includes('DEPLOY_OK')) {
      db.updateNode(nodeId, { is_active: 1, remark: sshInfo.socks5_host ? '🏠 家宽落地' : '' });
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_ss', `SS部署成功: ${name} (IPv6: ${ipv6Addr}:${port})`, 'system');
      console.log(`[SS部署成功] ${name} (${ipv6Addr}:${port})`);
      try { notify.deploy(name, true, `IPv6 SS | ${ipv6Addr}:${port}`); } catch {}

      // 安装 Agent
      try { await installAgentOnNode(ssh, nodeId, db); } catch (e) {
        console.error(`[Agent安装] ${name} 失败: ${e.message}`);
      }
    } else {
      const errMsg = (startResult.stderr || startResult.stdout).substring(0, 200);
      db.updateNode(nodeId, { remark: `❌ 部署失败: ${errMsg}` });
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_ss_fail', `SS部署失败: ${name} - ${errMsg}`, 'system');
      console.error(`[SS部署失败] ${name}: ${errMsg}`);
      try { notify.deploy(name, false, errMsg); } catch {}
    }
  } catch (err) {
    db.updateNode(nodeId, { remark: `❌ ${err.message}` });
    db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_ss_fail', `SS部署异常: ${name} - ${err.message}`, 'system');
    console.error(`[SS部署异常] ${name}: ${err.message}`);
    try { notify.deploy(name, false, err.message); } catch {}
  } finally {
    ssh.dispose();
  }
}

// ========== 双协议部署（VLESS IPv4 + SS IPv6 同机）==========

async function deployDualNode(sshInfo, db) {
  if (typeof db.getDb === 'function') db.getDb();

  const vlessPort = randomPort();
  const ssPort = randomPort(10000, 60000);
  const uuid = uuidv4();
  const ssPassword = crypto.randomBytes(16).toString('base64');
  const ssMethod = sshInfo.ss_method || 'aes-256-gcm';

  const geo = await detectRegion(sshInfo.host);
  let displayGeo = geo;
  let isHomeNetwork = false;
  if (sshInfo.socks5_host) {
    isHomeNetwork = true;
    const socks5Geo = await detectRegion(sshInfo.socks5_host);
    if (socks5Geo.city && socks5Geo.city !== 'Unknown' && socks5Geo.cityCN !== '未知') displayGeo = socks5Geo;
  }

  const existingNodes = db.getAllNodes();
  const vlessName = generateNodeName(displayGeo, existingNodes, isHomeNetwork);
  // SS 节点名添加 IPv6 标记
  const ssName = vlessName.replace(/-([^-]+)$/, '-$1') + '⁶';
  const region = `${displayGeo.emoji} ${displayGeo.cityCN}`;

  // 先添加 VLESS 节点
  const vlessResult = db.addNode({
    name: vlessName, host: sshInfo.host, port: vlessPort, uuid,
    protocol: 'vless', ip_version: 4,
    ssh_host: sshInfo.host, ssh_port: sshInfo.ssh_port || 22,
    ssh_user: sshInfo.ssh_user || 'root', ssh_password: sshInfo.ssh_password,
    ssh_key_path: sshInfo.ssh_key_path,
    socks5_host: sshInfo.socks5_host || null, socks5_port: parseInt(sshInfo.socks5_port) || 1080,
    socks5_user: sshInfo.socks5_user || null, socks5_pass: sshInfo.socks5_pass || null,
    region, remark: '⏳ 部署中...', is_active: 0
  });
  const vlessNodeId = vlessResult.lastInsertRowid;

  // 添加 SS 节点（host 后面会更新为 IPv6）
  const ssResult = db.addNode({
    name: ssName, host: sshInfo.host, port: ssPort,
    uuid: '00000000-0000-0000-0000-000000000000',
    protocol: 'ss', ip_version: 6, ss_method: ssMethod, ss_password: ssPassword,
    ssh_host: sshInfo.host, ssh_port: sshInfo.ssh_port || 22,
    ssh_user: sshInfo.ssh_user || 'root', ssh_password: sshInfo.ssh_password,
    socks5_host: sshInfo.socks5_host || null, socks5_port: parseInt(sshInfo.socks5_port, 10) || 1080,
    socks5_user: sshInfo.socks5_user || null, socks5_pass: sshInfo.socks5_pass || null,
    region, remark: '⏳ 部署中...', is_active: 0
  });
  const ssNodeId = ssResult.lastInsertRowid;

  // 为所有用户生成 UUID
  db.ensureAllUsersHaveUuid(vlessNodeId);
  db.ensureAllUsersHaveUuid(ssNodeId);

  const ssh = new NodeSSH();
  try {
    const connectOpts = {
      host: sshInfo.host, port: sshInfo.ssh_port || 22,
      username: sshInfo.ssh_user || 'root',
    };
    if (sshInfo.ssh_key_path) connectOpts.privateKeyPath = sshInfo.ssh_key_path;
    else if (sshInfo.ssh_password) connectOpts.password = sshInfo.ssh_password;

    console.log(`[双协议部署] ${vlessName} + ${ssName} (${sshInfo.host}) 开始...`);
    await ssh.connect(connectOpts);

    // 检测 IPv6 地址
    const ipv6Result = await ssh.execCommand("ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' | cut -d/ -f1");
    const ipv6Addr = (ipv6Result.stdout || '').trim();
    if (!ipv6Addr) {
      throw new Error('服务器没有 IPv6 地址，无法进行双协议部署');
    }
    console.log(`[双协议部署] 检测到 IPv6: ${ipv6Addr}`);
    db.updateNode(ssNodeId, { host: ipv6Addr });

    // 安装 xray
    const installScript = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'install-xray.sh'), 'utf8').trim();
    const installResult = await ssh.execCommand(installScript, { execOptions: { timeout: 180000 } });
    if (!installResult.stdout.includes('INSTALL_OK')) {
      throw new Error('xray 安装失败: ' + (installResult.stderr || installResult.stdout).substring(0, 200));
    }

    // 生成 Reality 密钥
    const keyResult = await ssh.execCommand('xray x25519');
    const output = keyResult.stdout + '\n' + keyResult.stderr;
    const privMatch = output.match(/Private\s*[Kk]ey:\s*(\S+)/);
    const pubMatch = output.match(/Public\s*[Kk]ey:\s*(\S+)/) || output.match(/Password:\s*(\S+)/);
    if (!privMatch || !pubMatch) throw new Error('Reality 密钥生成失败');
    const realityPrivateKey = privMatch[1];
    const realityPublicKey = pubMatch[1];
    const realityShortId = crypto.randomBytes(4).toString('hex');
    const sni = 'www.microsoft.com';

    db.updateNode(vlessNodeId, { reality_private_key: realityPrivateKey, reality_public_key: realityPublicKey, reality_short_id: realityShortId, sni });

    // 构建双协议配置
    const vlessUuids = db.getNodeAllUserUuids(vlessNodeId);
    const vlessClients = vlessUuids.length > 0
      ? vlessUuids.map(u => ({ id: u.uuid, level: 0, email: makeEmail(u.user_id, 'vless') }))
      : [{ id: uuid, level: 0, email: 'default@panel' }];

    const ssUuids = db.getNodeAllUserUuids(ssNodeId);
    const ssClients = ssUuids.length > 0
      ? ssUuids.map(u => ({ password: u.uuid, email: makeEmail(u.user_id, 'ss') }))
      : [{ password: ssPassword, email: 'default@panel' }];

    const outbounds = buildOutboundsBySocks(sshInfo.socks5_host, sshInfo.socks5_port, sshInfo.socks5_user, sshInfo.socks5_pass);

    const config = buildDualXrayConfig(vlessPort, ssPort, vlessClients, ssClients, ssMethod, outbounds, { privateKey: realityPrivateKey, sni, shortId: realityShortId });
    const configJson = JSON.stringify(config, null, 2);

    await ssh.execCommand('mkdir -p /usr/local/etc/xray');
    await sftpWriteFile(ssh, '/usr/local/etc/xray/config.json', configJson);

    // 开放两个端口
    await ssh.execCommand(`
      for P in ${vlessPort} ${ssPort}; do
        iptables -C INPUT -p tcp --dport $P -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $P -j ACCEPT
        iptables -C INPUT -p udp --dport $P -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport $P -j ACCEPT
        ip6tables -C INPUT -p tcp --dport $P -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport $P -j ACCEPT
        ip6tables -C INPUT -p udp --dport $P -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport $P -j ACCEPT
      done
      command -v netfilter-persistent &>/dev/null && netfilter-persistent save || true
    `);

    // 启动 xray
    const startResult = await ssh.execCommand('systemctl enable xray && systemctl restart xray && sleep 2 && systemctl is-active --quiet xray && echo DEPLOY_OK || echo DEPLOY_FAIL');

    if (startResult.stdout.includes('DEPLOY_OK')) {
      db.updateNode(vlessNodeId, { is_active: 1, remark: sshInfo.socks5_host ? '🏠 家宽落地' : '' });
      db.updateNode(ssNodeId, { is_active: 1, remark: sshInfo.socks5_host ? '🏠 家宽落地' : '' });
      const msg = `双协议部署成功: ${vlessName} (VLESS ${sshInfo.host}:${vlessPort}) + ${ssName} (SS IPv6 ${ipv6Addr}:${ssPort})`;
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_dual', msg, 'system');
      console.log(`[双协议部署成功] ${msg}`);
      try { notify.deploy(vlessName, true, `双协议 | VLESS:${vlessPort} SS-IPv6:${ssPort}`); } catch {}

      // 安装 Agent（用 VLESS 节点 ID）
      try { await installAgentOnNode(ssh, vlessNodeId, db); } catch (e) {
        console.error(`[Agent安装] ${vlessName} 失败: ${e.message}`);
      }
    } else {
      const errMsg = (startResult.stderr || startResult.stdout).substring(0, 200);
      db.updateNode(vlessNodeId, { remark: `❌ 部署失败: ${errMsg}` });
      db.updateNode(ssNodeId, { remark: `❌ 部署失败: ${errMsg}` });
      db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_dual_fail', `双协议部署失败: ${errMsg}`, 'system');
      console.error(`[双协议部署失败] ${errMsg}`);
      try { notify.deploy(vlessName, false, errMsg); } catch {}
    }
  } catch (err) {
    db.updateNode(vlessNodeId, { remark: `❌ ${err.message}` });
    db.updateNode(ssNodeId, { remark: `❌ ${err.message}` });
    db.addAuditLog(sshInfo.triggered_by || null, 'node_deploy_dual_fail', `双协议部署异常: ${err.message}`, 'system');
    console.error(`[双协议部署异常] ${err.message}`);
    try { notify.deploy(vlessName, false, err.message); } catch {}
  } finally {
    ssh.dispose();
  }
}

// syncAllNodesConfig 对外暴露去抖版本
const syncAllNodesConfig = syncAllNodesConfigDebounced;
module.exports = { deployNode, deploySsNode, deployDualNode, detectRegion, generateNodeName, syncNodeConfig, syncAllNodesConfig, pushConfigToNode };
