const crypto = require('crypto');

const verifyAttempts = new Map();

function getEnv() {
  return {
    ACCESS_CODE: process.env.ACCESS_CODE || process.env.VITE_ACCESS_CODE || '',
    LOOKUP_KEY: process.env.LOOKUP_KEY || process.env.VITE_LOOKUP_KEY || '',
    SHEETS_WEBHOOK_URL: process.env.GOOGLE_SHEETS_WEBHOOK_URL || process.env.SHEETS_WEBHOOK_URL || '',
    ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN || '',
    COOKIE_SECURE: String(process.env.COOKIE_SECURE || 'true').toLowerCase() === 'true',
    TOKEN_SECRET:
      process.env.ACCESS_TOKEN_SECRET || process.env.SESSION_SECRET || process.env.ACCESS_CODE || 'development-secret',
    SESSION_TTL_MS: Number(process.env.SESSION_TTL_MS || 1000 * 60 * 5),
    VERIFY_LIMIT_WINDOW_MS: Number(process.env.VERIFY_LIMIT_WINDOW_MS || 60 * 1000),
    VERIFY_LIMIT_MAX: Number(process.env.VERIFY_LIMIT_MAX || 5),
  };
}

function setCommonHeaders(req, res) {
  const { ALLOWED_ORIGIN } = getEnv();
  const requestOrigin = req.headers.origin;

  if (ALLOWED_ORIGIN && requestOrigin === ALLOWED_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
}

function handleOptions(req, res) {
  setCommonHeaders(req, res);
  res.status(204).end();
}

function sendJson(req, res, status, payload) {
  setCommonHeaders(req, res);
  res.status(status).send(JSON.stringify(payload));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

function getCookieValue(req, cookieName) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = cookieHeader.split(';').map((cookie) => cookie.trim());

  for (const cookie of cookies) {
    const [name, value] = cookie.split('=');
    if (name === cookieName) {
      return value;
    }
  }

  return null;
}

function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

function createAccessToken() {
  const { SESSION_TTL_MS, TOKEN_SECRET } = getEnv();
  const payload = {
    exp: Date.now() + SESSION_TTL_MS,
    nonce: crypto.randomBytes(16).toString('hex'),
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest();
  return `${encodedPayload}.${base64UrlEncode(signature)}`;
}

function parseAccessToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }

  try {
    const { TOKEN_SECRET } = getEnv();
    const [encodedPayload, encodedSignature] = parts;
    const expectedSignature = crypto.createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest();
    const providedSignature = base64UrlDecode(encodedSignature);

    if (expectedSignature.length !== providedSignature.length || !crypto.timingSafeEqual(expectedSignature, providedSignature)) {
      return null;
    }

    const payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8'));
    if (!payload || typeof payload.exp !== 'number' || payload.exp <= Date.now()) {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

function getAccessCookieParts(token, maxAgeSeconds) {
  const { COOKIE_SECURE } = getEnv();
  const cookieParts = [`vehicle_lookup_session=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAgeSeconds}`];

  if (COOKIE_SECURE) {
    cookieParts.push('Secure');
  }

  return cookieParts;
}

function clearAccessCookieParts() {
  const { COOKIE_SECURE } = getEnv();
  const cookieParts = ['vehicle_lookup_session=', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];

  if (COOKIE_SECURE) {
    cookieParts.push('Secure');
  }

  return cookieParts;
}

function getClientKey(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown');
}

function isVerifyRateLimited(req) {
  const { VERIFY_LIMIT_WINDOW_MS, VERIFY_LIMIT_MAX } = getEnv();
  const clientKey = getClientKey(req);
  const now = Date.now();
  const entry = verifyAttempts.get(clientKey) || { windowStart: now, count: 0 };

  if (now - entry.windowStart > VERIFY_LIMIT_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }

  entry.count += 1;
  verifyAttempts.set(clientKey, entry);

  return entry.count > VERIFY_LIMIT_MAX;
}

function getIstTimestamp(date = new Date()) {
  return new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date).replace(',', '') + ' IST';
}

async function saveSearchToSheet({ query, result, status, responseStatus, phase }) {
  const { SHEETS_WEBHOOK_URL } = getEnv();
  if (!SHEETS_WEBHOOK_URL) {
    return;
  }

  const payload = {
    timestamp: getIstTimestamp(),
    phase,
    query,
    result: typeof result === 'string' ? result : JSON.stringify(result),
    status,
    responseStatus,
    source: 'vehicle-details',
  };

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const response = await fetch(SHEETS_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        return;
      }
    } catch (error) {
      // Best-effort logging only.
    }
  }
}

async function getJsonBody(req) {
  if (req.body && typeof req.body === 'object') {
    return req.body;
  }

  if (typeof req.body === 'string') {
    return JSON.parse(req.body);
  }

  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

module.exports = {
  clearAccessCookieParts,
  createAccessToken,
  getAccessCookieParts,
  getCookieValue,
  getEnv,
  getJsonBody,
  handleOptions,
  isVerifyRateLimited,
  parseAccessToken,
  saveSearchToSheet,
  sendJson,
  timingSafeEqual,
};