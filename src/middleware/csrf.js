const crypto = require('crypto');

// 生成 CSRF token 并存入 session
function generateToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

// 检查 Origin/Referer 是否匹配当前主机
function isOriginAllowed(req) {
  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const host = req.headers['host'];
  if (!host) return false;

  // 优先检查 Origin
  if (origin) {
    try {
      const url = new URL(origin);
      return url.host === host;
    } catch {
      return false;
    }
  }

  // 回退到 Referer
  if (referer) {
    try {
      const url = new URL(referer);
      return url.host === host;
    } catch {
      return false;
    }
  }

  // 都没有则拒绝
  return false;
}

// 验证 CSRF（POST/PUT/DELETE 请求）
function csrfProtection(req, res, next) {
  if (req.method !== 'POST' && req.method !== 'PUT' && req.method !== 'DELETE') return next();

  // JSON API：检查 Origin/Referer（浏览器跨站 fetch 会带 Origin）
  if (req.is('json')) {
    if (isOriginAllowed(req)) return next();
    // 反代/特殊浏览器场景兜底：允许 X-CSRF-Token
    const token = req.headers['x-csrf-token'];
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).json({ error: 'CSRF 校验失败：Origin 不匹配且 Token 无效' });
    }
    return next();
  }

  // 表单提交：检查 CSRF token
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'CSRF token 无效，请刷新页面重试' });
  }
  next();
}

// 模板中间件：自动注入 csrfToken 到 res.locals
function csrfLocals(req, res, next) {
  res.locals.csrfToken = generateToken(req);
  next();
}

module.exports = { csrfProtection, csrfLocals };
