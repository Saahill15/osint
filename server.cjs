const http = require('http');
const crypto = require('crypto');

const ACCESS_CODE = process.env.ACCESS_CODE || process.env.VITE_ACCESS_CODE || '';
const LOOKUP_KEY = process.env.LOOKUP_KEY || process.env.VITE_LOOKUP_KEY || '';
const PORT = Number(process.env.PORT || 3015);
const SHEETS_WEBHOOK_URL = process.env.GOOGLE_SHEETS_WEBHOOK_URL || process.env.SHEETS_WEBHOOK_URL || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '').toLowerCase() === 'true';
const TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || process.env.SESSION_SECRET || ACCESS_CODE || 'development-secret';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 5);
const VERIFY_LIMIT_WINDOW_MS = Number(process.env.VERIFY_LIMIT_WINDOW_MS || 60 * 1000);
const VERIFY_LIMIT_MAX = Number(process.env.VERIFY_LIMIT_MAX || 5);

const verifyAttempts = new Map();

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

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
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

function isValidAccessToken(token) {
  return Boolean(parseAccessToken(token));
}

function getAccessCookieParts(token, maxAgeSeconds) {
  const cookieParts = [`vehicle_lookup_session=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAgeSeconds}`];

  if (COOKIE_SECURE) {
    cookieParts.push('Secure');
  }

  return cookieParts;
}

function clearAccessCookieParts() {
  const cookieParts = ['vehicle_lookup_session=', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];

  if (COOKIE_SECURE) {
    cookieParts.push('Secure');
  }

  return cookieParts;
}

function getClientKey(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown');
}

function isVerifyRateLimited(req) {
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

function sendAuthState(res, token) {
  const payload = parseAccessToken(token);

  if (!payload) {
    sendJson(res, 401, { authenticated: false });
    return;
  }

  sendJson(res, 200, {
    authenticated: true,
    expiresAt: payload.exp,
    remainingMs: Math.max(0, payload.exp - Date.now()),
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
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

      const text = await response.text().catch(() => '');
      console.warn(`Sheet logging failed with ${response.status}: ${text}`);
    } catch (error) {
      console.warn(`Sheet logging error on attempt ${attempt}: ${error.message}`);
    }
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    });
    res.end();
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');

  if (req.method === 'GET' && url.pathname === '/') {
    sendJson(res, 200, { ok: true, message: 'OSINT backend is running.' });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/session') {
    const sessionToken = getCookieValue(req, 'vehicle_lookup_session');
    sendAuthState(res, sessionToken);
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/verify') {
    try {
      if (isVerifyRateLimited(req)) {
        sendJson(res, 429, { ok: false, error: 'Too many attempts. Try again later.' });
        return;
      }

      const body = await readJsonBody(req);
      const provided = String(body.code || '').trim();

      if (!ACCESS_CODE) {
        sendJson(res, 500, { ok: false, error: 'Server access code is not configured.' });
        return;
      }

      const expectedBuffer = Buffer.from(ACCESS_CODE);
      const providedBuffer = Buffer.from(provided);
      const matches = timingSafeEqual(expectedBuffer, providedBuffer);

      if (!matches) {
        sendJson(res, 401, { ok: false, error: 'Incorrect access code.' });
        return;
      }

      const token = createAccessToken();
      const cookieParts = getAccessCookieParts(token, Math.max(1, Math.floor(SESSION_TTL_MS / 1000)));

      res.writeHead(200, {
        'Set-Cookie': cookieParts.join('; '),
        'Content-Type': 'application/json',
      });
      res.end(JSON.stringify({ ok: true, expiresAt: Date.now() + SESSION_TTL_MS, sessionTtlMs: SESSION_TTL_MS }));
      return;
    } catch (error) {
      sendJson(res, 400, { ok: false, error: 'Invalid request.' });
      return;
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    res.writeHead(200, {
      'Set-Cookie': clearAccessCookieParts().join('; '),
      'Content-Type': 'application/json',
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/lookup') {
    const sessionToken = getCookieValue(req, 'vehicle_lookup_session');

    if (!isValidAccessToken(sessionToken)) {
      sendJson(res, 401, { ok: false, error: 'Unauthorized.' });
      return;
    }

    const vehicle = url.searchParams.get('rc') || '';

    if (!vehicle) {
      sendJson(res, 400, { ok: false, error: 'Vehicle number is required.' });
      return;
    }

    if (!LOOKUP_KEY) {
      sendJson(res, 500, { ok: false, error: 'Lookup key is not configured.' });
      return;
    }

    try {
      const target = new URL('https://paid.originalapis.workers.dev/deep');
      target.searchParams.set('key', LOOKUP_KEY);
      target.searchParams.set('rc', vehicle);

      const response = await fetch(target.toString());
      const data = await response.json();
      const sanitizedResult = response.ok
        ? {
            ok: true,
            status: response.status,
            vehicleNumber: vehicle,
            summary: data?.result?.error || data?.result?.message || 'Lookup completed',
            result: data,
          }
        : {
            ok: false,
            status: response.status,
            vehicleNumber: vehicle,
            error: data?.error || data?.result?.error || 'Lookup returned an error',
            result: data,
          };
        saveSearchToSheet({
        phase: response.ok ? 'completed' : 'finished-with-error',
        query: vehicle,
        result: sanitizedResult,
        status: response.ok ? 'ok' : 'error',
        responseStatus: response.status,
      });
      sendJson(res, response.ok ? 200 : response.status, data);
    } catch (error) {
        saveSearchToSheet({
        phase: 'failed',
        query: vehicle,
        result: {
          ok: false,
          vehicleNumber: vehicle,
          error: error.message,
        },
        status: 'error',
        responseStatus: 502,
      });
      sendJson(res, 502, { ok: false, error: 'Lookup failed.' });
    }

    return;
  }

  sendJson(res, 404, { ok: false, error: 'Not found.' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Secure lookup server running on http://localhost:${PORT}`);
});
