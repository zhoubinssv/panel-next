#!/usr/bin/env node
'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const net = require('net');
const fs = require('fs');
const os = require('os');
const { execFile, exec, spawn } = require('child_process');
const path = require('path');
const crypto = require('crypto');

// ─── 配置 ───
const CONFIG_PATH = '/etc/vless-agent/config.json';
const XRAY_CONFIG_PATH = '/usr/local/etc/xray/config.json';
const AGENT_PATH = '/opt/vless-agent/agent.js';
const AGENT_VERSION = process.env.AGENT_VERSION || '1.2.0';

const CHINA_PROBE_TARGETS = [
  { host: '220.202.155.242', port: 80 },
  { host: '114.114.114.114', port: 53 },
  { host: '223.5.5.5', port: 53 },
];

// IPv6 连通性探测（ping Google DNS，检测 IPv6 网络是否正常）
const IPV6_PROBE_TARGET = { host: '2001:4860:4860::8888', port: 53 };

let config = loadConfig();
const REPORT_INTERVAL = config.reportInterval || 60_000;
const HEARTBEAT_INTERVAL = 30_000;
const SELF_HEAL_INTERVAL = config.selfHealInterval || 60_000;

// ─── TLS 配置 ───
const INSECURE_TLS = config.insecureTls === true || process.env.AGENT_INSECURE_TLS === 'true';
if (INSECURE_TLS) {
  log('WARN', '⚠️  TLS 证书校验已禁用 (insecureTls=true)，存在中间人攻击风险，仅限调试使用！');
}

// ─── exec 指令白名单 ───
const DEFAULT_EXEC_WHITELIST = [
  'systemctl restart xray',
  'systemctl stop xray',
  'systemctl start xray',
  'systemctl status xray',
  'systemctl is-active xray',
  'xray api',
  'df ',
  'free ',
  'uptime',
  'cat /usr/local/etc/xray/config.json',
  'ls ',
  'ps ',
  'top -bn1',
  'ip addr',
  'ip -6 addr',
  'ip route',
  'ping ',
  'curl ',
  'wget ',
];
const EXEC_WHITELIST = [
  ...DEFAULT_EXEC_WHITELIST,
  ...(config.execWhitelist || []),
  ...(process.env.AGENT_EXEC_WHITELIST ? process.env.AGENT_EXEC_WHITELIST.split(',') : []),
];
const EXEC_WHITELIST_ENABLED = config.execWhitelistEnabled !== false && process.env.AGENT_EXEC_WHITELIST_DISABLED !== 'true';
const AGENT_CAPABILITIES = {
  tlsStrict: !INSECURE_TLS,
  execWhitelist: EXEC_WHITELIST_ENABLED,
  selfHeal: true,
  selfUpdate: true,
};
const PANEL_HOST = (() => {
  try { return new URL(config.server).hostname.toLowerCase(); } catch { return null; }
})();
const SAFE_DOWNLOAD_HOSTS = new Set([PANEL_HOST, 'vip.vip.sd'].filter(Boolean));
const DANGEROUS_SHELL_PATTERN = /[|;&`<>]|\$\(|\r|\n/;

function extractCommandUrls(cmd) {
  return (cmd.match(/https?:\/\/[^\s"']+/g) || []);
}
const reconnectMetrics = {
  disconnectCount: 0,
  lastDisconnectAt: null,
  lastReconnectAt: null,
  consecutiveReconnects: 0,
};

let ws = null;
let reconnectDelay = 1000;
let heartbeatTimer = null;
let reportTimer = null;
let selfHealTimer = null;

// ─── 配置加载 ───
function loadConfig() {
  // 环境变量优先
  if (process.env.AGENT_SERVER && process.env.AGENT_TOKEN && process.env.AGENT_NODE_ID) {
    return {
      server: process.env.AGENT_SERVER,
      token: process.env.AGENT_TOKEN,
      nodeId: parseInt(process.env.AGENT_NODE_ID),
    };
  }
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) {
    console.error(`[配置] 无法读取 ${CONFIG_PATH}: ${e.message}`);
    process.exit(1);
  }
}

// ─── 工具函数 ───
function log(tag, msg) {
  console.log(`[${new Date().toISOString()}] [${tag}] ${msg}`);
}

function run(cmd, timeout = 15000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: (stdout || '').trim(), stderr: (stderr || '').trim(), code: err?.code });
    });
  });
}

function sendMsg(data) {
  if (ws?.readyState === 1) {
    try {
      ws.send(JSON.stringify({ ...data, nodeId: config.nodeId }));
    } catch (e) {
      log('WS', `发送失败: ${e.message}`);
    }
  }
}

// ─── TCP 探测中国可达性 ───
function tcpProbe(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (ok) => { if (!done) { done = true; socket.destroy(); resolve(ok); } };
    socket.setTimeout(timeout);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function checkChinaReachable() {
  try {
    const results = await Promise.all(
      CHINA_PROBE_TARGETS.map(t => tcpProbe(t.host, t.port))
    );
    const passCount = results.filter(Boolean).length;
    return passCount >= 2;
  } catch {
    return null;
  }
}

// 检测本机是否有全局 IPv6 地址
function hasGlobalIPv6() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv6' && !iface.internal && !iface.address.startsWith('fe80')) {
        return true;
      }
    }
  }
  return false;
}

// IPv6 连通性检测（仅配置开启 checkIPv6 且有全局 IPv6 地址时才检测）
async function checkIPv6Reachable() {
  if (!config.checkIPv6 || !hasGlobalIPv6()) return null;
  try {
    return await tcpProbe(IPV6_PROBE_TARGET.host, IPV6_PROBE_TARGET.port, 5000);
  } catch {
    return false;
  }
}

// ─── 系统信息采集 ───
function getSystemInfo() {
  const loadavg = os.loadavg();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  return {
    loadavg,
    memory: {
      total: totalMem,
      free: freeMem,
      used: totalMem - freeMem,
      usagePercent: +((1 - freeMem / totalMem) * 100).toFixed(1),
    },
    uptime: os.uptime(),
  };
}

async function getDiskUsage() {
  const { ok, stdout } = await run("df -B1 / | tail -1 | awk '{print $2,$3,$4,$5}'");
  if (!ok || !stdout) return null;
  const [total, used, avail, percent] = stdout.split(/\s+/);
  return { total: +total, used: +used, avail: +avail, usagePercent: parseFloat(percent) };
}

async function getXrayStatus() {
  const { stdout } = await run('systemctl is-active xray');
  return stdout === 'active';
}

async function getXrayTraffic() {
  const { ok, stdout } = await run(
    'xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>" -reset 2>/dev/null'
  );
  if (!ok || !stdout) return [];
  try {
    const data = JSON.parse(stdout);
    if (!data.stat) return [];
    const records = [];
    for (const stat of data.stat) {
      let userId = null;
      let direction = null;
      let proto = null;

      // 新协议区分格式：
      // VLESS: u-<id>-v@p
      // SS:    u-<id>-s@p
      let m = stat.name.match(/^user>>>u-(\d+)-(v|s)@p>>>traffic>>>(uplink|downlink)$/);
      if (m) {
        userId = parseInt(m[1], 10);
        proto = m[2] === 's' ? 'ss' : 'vless';
        direction = m[3];
      } else {
        // 兼容历史格式：
        // 旧: user-<id>@panel
        // 新(无协议后缀): u-<id>@p
        m = stat.name.match(/^user>>>(?:user-|u-)(\d+)(?:@panel|@p)>>>traffic>>>(uplink|downlink)$/);
        if (m) {
          userId = parseInt(m[1], 10);
          direction = m[2];
        }
      }

      if (userId) {
        const value = parseInt(stat.value, 10) || 0;
        if (value <= 0) continue;
        records.push({ userId, direction, value, proto });
      }
    }
    return records;
  } catch {
    return [];
  }
}

// ─── 定时上报 ───
async function report() {
  try {
    const [xrayActive, traffic, cnReachable, ipv6Reachable, disk] = await Promise.all([
      getXrayStatus(),
      getXrayTraffic(),
      checkChinaReachable(),
      checkIPv6Reachable(),
      getDiskUsage(),
    ]);
    const sys = getSystemInfo();
    sendMsg({
      type: 'report',
      ts: Date.now(),
      version: AGENT_VERSION,
      capabilities: AGENT_CAPABILITIES,
      reconnectMetrics,
      xrayAlive: xrayActive,
      trafficRecords: traffic,
      cnReachable,
      ipv6Reachable,
      loadAvg: sys.loadavg,
      memUsage: sys.memory,
      diskUsage: disk,
    });
  } catch (e) {
    log('上报', `失败: ${e.message}`);
  }
}

// ─── 自愈：xray 挂了自动重启 ───
async function selfHeal() {
  const active = await getXrayStatus();
  if (!active) {
    log('自愈', 'xray 未运行，尝试重启...');
    const { ok, stderr } = await run('systemctl restart xray');
    log('自愈', ok ? 'xray 重启成功' : `xray 重启失败: ${stderr}`);
  }
}

// ─── 指令处理 ───
async function handleCommand(msg) {
  const { type, id } = msg;
  const reply = (data) => sendMsg({ type: 'cmd_result', id, cmdType: type, ...data });

  switch (type) {
    case 'ping':
      sendMsg({ type: 'pong', ts: Date.now() });
      break;

    case 'restart_xray': {
      const { ok, stderr } = await run('systemctl restart xray');
      reply({ success: ok, error: ok ? undefined : stderr });
      break;
    }

    case 'update_config': {
      try {
        if (!msg.config) throw new Error('缺少 config 字段');
        const configStr = typeof msg.config === 'string' ? msg.config : JSON.stringify(msg.config, null, 2);
        fs.writeFileSync(XRAY_CONFIG_PATH, configStr, 'utf8');
        const { ok, stderr } = await run('systemctl restart xray');
        reply({ success: ok, error: ok ? undefined : stderr });
      } catch (e) {
        reply({ success: false, error: e.message });
      }
      break;
    }

    case 'exec': {
      if (!msg.command) { reply({ success: false, error: '缺少 command 字段' }); break; }
      const cmd = msg.command.trim();

      // 基础防护：拒绝危险 shell 元字符（防止管道、命令拼接、命令替换）
      if (DANGEROUS_SHELL_PATTERN.test(cmd)) {
        log('WARN', `⚠️  exec 指令含危险字符，已拒绝: ${cmd}`);
        reply({ success: false, error: '指令包含危险字符（|;&`<>,$(),换行）' });
        break;
      }

      // 白名单校验
      if (EXEC_WHITELIST_ENABLED) {
        const allowed = EXEC_WHITELIST.some(prefix => cmd.startsWith(prefix));
        if (!allowed) {
          log('WARN', `⚠️  exec 指令被白名单拒绝: ${cmd}`);
          reply({ success: false, error: `指令不在白名单中: ${cmd.slice(0, 80)}` });
          break;
        }
      }

      // curl/wget 仅允许下载面板域名，避免执行任意远程脚本
      if (cmd.startsWith('curl ') || cmd.startsWith('wget ')) {
        const urls = extractCommandUrls(cmd);
        if (urls.length > 0) {
          const forbidden = urls.find((u) => {
            try {
              const h = new URL(u).hostname.toLowerCase();
              return !SAFE_DOWNLOAD_HOSTS.has(h);
            } catch {
              return true;
            }
          });
          if (forbidden) {
            log('WARN', `⚠️  exec 下载域名不在白名单，已拒绝: ${forbidden}`);
            reply({ success: false, error: `下载域名不在白名单: ${forbidden}` });
            break;
          }
        }
      }

      const timeout = Math.min(msg.timeout || 30000, 120000);
      const result = await run(msg.command, timeout);
      reply({ success: result.ok, stdout: result.stdout, stderr: result.stderr, code: result.code });
      break;
    }

    case 'self_update': {
      try {
        const updateUrl = msg.url || `${config.server.replace(/\/ws\/agent$/, '').replace(/^wss:/, 'https:').replace(/^ws:/, 'http:')}/api/agent/download`;
        log('更新', `从 ${updateUrl} 下载新版 agent...`);
        const code = await httpGet(updateUrl);
        const tmpPath = AGENT_PATH + '.tmp';
        fs.writeFileSync(tmpPath, code, 'utf8');
        fs.renameSync(tmpPath, AGENT_PATH);
        fs.chmodSync(AGENT_PATH, 0o755);
        reply({ success: true, message: '更新完成，即将重启' });
        // 延迟退出，让 systemd 自动重启
        setTimeout(() => process.exit(0), 500);
      } catch (e) {
        reply({ success: false, error: e.message });
      }
      break;
    }

    default:
      log('指令', `未知指令: ${type}`);
      reply({ success: false, error: `未知指令: ${type}` });
  }
}

// ─── HTTP GET（用于 self_update） ───
function httpGet(urlStr) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.get(url, { headers: { Authorization: `Bearer ${config.token}` }, timeout: 30000, rejectUnauthorized: !INSECURE_TLS }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpGet(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('下载超时')); });
  });
}

// ─── WebSocket 连接 ───
function connect() {
  const wsUrl = `${config.server}?token=${encodeURIComponent(config.token)}&nodeId=${config.nodeId}`;
  log('WS', `连接 ${config.server} ...`);

  ws = createRawWs(wsUrl);
  if (!ws) {
    log('WS', '无法创建 WebSocket 连接');
    scheduleReconnect();
    return;
  }

  ws.on('open', () => {
    log('WS', '已连接，发送认证...');
    reconnectDelay = 1000;
    lastActivity = Date.now();
    if (reconnectMetrics.consecutiveReconnects > 0) {
      reconnectMetrics.lastReconnectAt = new Date().toISOString();
      reconnectMetrics.consecutiveReconnects = 0;
    }
    // 发送认证消息
    sendMsg({ type: 'auth', token: config.token, version: AGENT_VERSION, capabilities: AGENT_CAPABILITIES });
    // 立即上报一次
    setTimeout(report, 1000);
    // 心跳
    clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(() => {
      if (ws?.readyState === 1) ws.ping?.() || sendMsg({ type: 'heartbeat' });
    }, HEARTBEAT_INTERVAL);
  });

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(typeof raw === 'string' ? raw : raw.toString());
      if (msg.type === 'auth_ok') {
        log('WS', '认证成功');
        return;
      }
      handleCommand(msg).catch(e => log('指令', `处理异常: ${e.message}`));
    } catch (e) {
      log('WS', `消息解析失败: ${e.message}`);
    }
  });

  ws.on('close', (code, reason) => {
    log('WS', `断开 code=${code} reason=${reason || ''}`);
    reconnectMetrics.disconnectCount += 1;
    reconnectMetrics.consecutiveReconnects += 1;
    reconnectMetrics.lastDisconnectAt = new Date().toISOString();
    cleanup();
    scheduleReconnect();
  });

  ws.on('error', (err) => {
    log('WS', `错误: ${err.message}`);
  });
}

// 手动实现简易 WebSocket（用于没有内置 WebSocket 的 Node 版本）
function createRawWs(urlStr) {
  const EventEmitter = require('events');
  const url = new URL(urlStr);
  const isSecure = url.protocol === 'wss:';
  const mod = isSecure ? require('tls') : net;
  const port = url.port || (isSecure ? 443 : 80);
  const key = crypto.randomBytes(16).toString('base64');
  const pathStr = url.pathname + url.search;

  const emitter = new EventEmitter();
  emitter.readyState = 0; // CONNECTING

  const socket = mod.connect({ host: url.hostname, port, servername: url.hostname, rejectUnauthorized: !INSECURE_TLS }, () => {
    const headers = [
      `GET ${pathStr} HTTP/1.1`,
      `Host: ${url.hostname}`,
      `Upgrade: websocket`,
      `Connection: Upgrade`,
      `Sec-WebSocket-Key: ${key}`,
      `Sec-WebSocket-Version: 13`,
      '', ''
    ].join('\r\n');
    socket.write(headers);
  });

  let upgraded = false;
  let buffer = Buffer.alloc(0);
  let fragmented = null; // { opcode, chunks: Buffer[] }

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    if (!upgraded) {
      const idx = buffer.indexOf('\r\n\r\n');
      if (idx === -1) return;
      const headerStr = buffer.slice(0, idx).toString();
      if (!headerStr.includes('101')) {
        emitter.readyState = 3;
        emitter.emit('error', new Error('WebSocket 握手失败'));
        socket.destroy();
        return;
      }
      upgraded = true;
      emitter.readyState = 1;
      buffer = buffer.slice(idx + 4);
      emitter.emit('open');
    }

    // 解析 WebSocket 帧
    while (buffer.length >= 2) {
      const frame = parseWsFrame(buffer);
      if (!frame) break;
      buffer = buffer.slice(frame.totalLen);

      if (frame.opcode === 0x1 || frame.opcode === 0x2) {
        if (frame.fin) {
          emitter.emit('message', frame.payload);
        } else {
          fragmented = { opcode: frame.opcode, chunks: [frame.payload] };
        }
      } else if (frame.opcode === 0x0) {
        if (!fragmented) continue;
        fragmented.chunks.push(frame.payload);
        if (frame.fin) {
          emitter.emit('message', Buffer.concat(fragmented.chunks));
          fragmented = null;
        }
      } else if (frame.opcode === 0x8) {
        emitter.readyState = 3;
        const code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : 1000;
        emitter.emit('close', code, '');
        socket.destroy();
        return;
      } else if (frame.opcode === 0x9) {
        // PING → PONG
        sendWsFrame(socket, 0xA, frame.payload);
      }
    }
  });

  socket.on('error', (err) => {
    emitter.emit('error', err);
    // 不在这里设 readyState=3，留给 close 事件处理
    // socket error 后一定会触发 close
  });

  socket.on('close', () => {
    if (emitter.readyState !== 3) {
      emitter.readyState = 3;
      emitter.emit('close', 1006, '');
    }
  });

  // 兜底：如果 socket 被销毁但没触发 close（极端情况）
  socket.on('end', () => {
    if (emitter.readyState !== 3) {
      emitter.readyState = 3;
      emitter.emit('close', 1006, '');
    }
  });

  emitter.send = (data) => {
    if (emitter.readyState !== 1) return;
    const buf = Buffer.from(data, 'utf8');
    sendWsFrame(socket, 0x1, buf);
  };

  emitter.ping = () => {
    if (emitter.readyState !== 1) return;
    sendWsFrame(socket, 0x9, Buffer.alloc(0));
  };

  emitter.close = () => {
    if (emitter.readyState === 1) {
      sendWsFrame(socket, 0x8, Buffer.alloc(0));
    }
    socket.destroy();
    emitter.readyState = 3;
  };

  return emitter;
}

function parseWsFrame(buf) {
  if (buf.length < 2) return null;
  const fin = (buf[0] & 0x80) !== 0;
  const opcode = buf[0] & 0x0F;
  const masked = (buf[1] & 0x80) !== 0;
  let payloadLen = buf[1] & 0x7F;
  let offset = 2;

  if (payloadLen === 126) {
    if (buf.length < 4) return null;
    payloadLen = buf.readUInt16BE(2);
    offset = 4;
  } else if (payloadLen === 127) {
    if (buf.length < 10) return null;
    payloadLen = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }

  if (masked) offset += 4;
  if (buf.length < offset + payloadLen) return null;

  let payload = buf.slice(masked ? offset : offset, offset + payloadLen);
  if (masked) {
    const mask = buf.slice(offset - 4, offset);
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
  }

  return { fin, opcode, payload, totalLen: offset + payloadLen };
}

function sendWsFrame(socket, opcode, payload) {
  const mask = crypto.randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.alloc(6);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | payload.length;
    mask.copy(header, 2);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(8);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
    mask.copy(header, 4);
  } else {
    header = Buffer.alloc(14);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
    mask.copy(header, 10);
  }

  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];

  try { socket.write(Buffer.concat([header, masked])); } catch {}
}

function cleanup() {
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  ws = null;
}

function scheduleReconnect() {
  const delay = reconnectDelay + Math.random() * 1000;
  log('WS', `${(delay / 1000).toFixed(1)}s 后重连`);
  setTimeout(connect, delay);
  reconnectDelay = Math.min(reconnectDelay * 2, 60000);
}

// Watchdog: 如果长时间没有活跃连接，强制重连
let lastActivity = Date.now();
function watchdog() {
  if (ws?.readyState === 1) {
    lastActivity = Date.now();
    return;
  }
  const elapsed = Date.now() - lastActivity;
  if (elapsed > 120_000) {
    log('Watchdog', `${(elapsed / 1000).toFixed(0)}s 无活跃连接，强制重连`);
    lastActivity = Date.now();
    try { ws?.close?.(); } catch {}
    cleanup();
    reconnectDelay = 1000;
    connect();
  }
}

// ─── 启动 ───
function start() {
  log('启动', `nodeId=${config.nodeId} server=${config.server}`);
  connect();

  reportTimer = setInterval(report, REPORT_INTERVAL);
  selfHealTimer = setInterval(selfHeal, SELF_HEAL_INTERVAL);
  setInterval(watchdog, 30_000);

  // 优雅退出
  const shutdown = (sig) => {
    log('退出', `收到 ${sig}`);
    clearInterval(reportTimer);
    clearInterval(selfHealTimer);
    clearInterval(heartbeatTimer);
    ws?.close?.();
    setTimeout(() => process.exit(0), 500);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // 未捕获异常不崩溃
  process.on('uncaughtException', (e) => log('异常', e.stack || e.message));
  process.on('unhandledRejection', (e) => log('异常', `Promise: ${e?.stack || e}`));
}

start();
