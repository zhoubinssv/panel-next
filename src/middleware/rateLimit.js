const rateLimit = require('express-rate-limit');
const db = require('../services/database');
const { getClientIp } = require('../utils/clientIp');

function toPosInt(value, fallback, min = 1, max = null) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  let out = n;
  if (out < min) out = min;
  if (max != null && out > max) out = max;
  return out;
}

// 登录限流：每 IP 15 分钟最多 10 次
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '登录请求过于频繁，请 15 分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false
});

// AI 接口限流：每用户每分钟 10 次

const SUB_IP_WINDOW_MS = toPosInt(process.env.SUB_IP_WINDOW_MS, 60 * 1000, 1000, 60 * 60 * 1000);
const SUB_IP_MAX_REQ = toPosInt(process.env.SUB_IP_MAX_REQ, 5, 1, 1000);

function logSubRateLimited(req) {
  try {
    const token = String(req.params?.token || '');
    const user = token ? db.getUserBySubToken(token) : null;
    const route = String(req.path || '').includes('/sub6/') ? 'sub6' : 'sub';
    db.logSubAccessEvent({
      userId: user?.id || null,
      tokenPrefix: token.slice(0, 8),
      route,
      result: 'deny',
      reason: 'ip_rate_limited',
      ip: getClientIp(req),
      ua: req.headers?.['user-agent'] || '',
      clientType: '',
      httpStatus: 429,
    });
  } catch (_) {}
}

// 订阅拉取限流：每 IP 每分钟 N 次（默认 5）
const subLimiter = rateLimit({
  windowMs: SUB_IP_WINDOW_MS,
  max: SUB_IP_MAX_REQ,
  handler: (req, res, _next, options) => {
    logSubRateLimited(req);
    res.status(options.statusCode).type('text').send('Too many requests, please try again later.');
  },
  standardHeaders: true,
  legacyHeaders: false
});

// 管理 API 限流：每 IP 每分钟 300 次
const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { error: '请求过于频繁' },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = { authLimiter, subLimiter, adminLimiter };
