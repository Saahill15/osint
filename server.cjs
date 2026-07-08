const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ACCESS_CODE = process.env.ACCESS_CODE || process.env.VITE_ACCESS_CODE || '';
const LOOKUP_KEY = process.env.LOOKUP_KEY || process.env.VITE_LOOKUP_KEY || '';
const PORT = Number(process.env.PORT || 3015);
const SHEETS_WEBHOOK_URL = process.env.GOOGLE_SHEETS_WEBHOOK_URL || process.env.SHEETS_WEBHOOK_URL || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || process.env.RENDER_EXTERNAL_URL || process.env.RENDER_URL || 'http://localhost:3000';
const DIST_DIR = path.join(__dirname, 'dist');
const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
};
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '').toLowerCase() === 'true';
const TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || process.env.SESSION_SECRET || ACCESS_CODE || 'development-secret';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 5);
const VERIFY_LIMIT_WINDOW_MS = Number(process.env.VERIFY_LIMIT_WINDOW_MS || 60 * 1000);
const VERIFY_LIMIT_MAX = Number(process.env.VERIFY_LIMIT_MAX || 5);
const VERIFY_LOCKOUT_MS = Number(process.env.VERIFY_LOCKOUT_MS || 1000 * 60 * 5);
const BRUTE_FORCE_MAX_ATTEMPTS = Number(process.env.BRUTE_FORCE_MAX_ATTEMPTS || VERIFY_LIMIT_MAX);
const BRUTE_FORCE_WINDOW_MS = Number(process.env.BRUTE_FORCE_WINDOW_MS || VERIFY_LIMIT_WINDOW_MS);
const BRUTE_FORCE_LOCKOUT_MS = Number(process.env.BRUTE_FORCE_LOCKOUT_MS || VERIFY_LOCKOUT_MS);

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

function getVerifyBucket(req) {
  const clientKey = getClientKey(req);
  const now = Date.now();
  const entry = verifyAttempts.get(clientKey) || { windowStart: now, count: 0, lockedUntil: 0 };

  if (now - entry.windowStart > BRUTE_FORCE_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }

  if (entry.lockedUntil && now < entry.lockedUntil) {
    return { ...entry, blocked: true };
  }

  if (entry.lockedUntil && now >= entry.lockedUntil) {
    entry.lockedUntil = 0;
  }

  return { ...entry, blocked: false };
}

function recordVerifyAttempt(req, wasSuccessful) {
  const clientKey = getClientKey(req);
  const now = Date.now();
  const entry = verifyAttempts.get(clientKey) || { windowStart: now, count: 0, lockedUntil: 0 };

  if (now - entry.windowStart > BRUTE_FORCE_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }

  if (entry.lockedUntil && now < entry.lockedUntil) {
    return;
  }

  if (wasSuccessful) {
    entry.count = 0;
    entry.lockedUntil = 0;
  } else {
    entry.count += 1;
    if (entry.count >= BRUTE_FORCE_MAX_ATTEMPTS) {
      entry.lockedUntil = now + BRUTE_FORCE_LOCKOUT_MS;
      entry.count = 0;
    }
  }

  verifyAttempts.set(clientKey, entry);
}

function isVerifyRateLimited(req) {
  const bucket = getVerifyBucket(req);
  if (bucket.blocked) {
    return true;
  }

  return bucket.count >= BRUTE_FORCE_MAX_ATTEMPTS;
}

function getLockoutMessage(req) {
  const bucket = getVerifyBucket(req);

  if (!bucket.blocked || !bucket.lockedUntil) {
    return null;
  }

  const remainingMs = Math.max(0, bucket.lockedUntil - Date.now());
  const remainingMinutes = Math.ceil(remainingMs / 60000);
  return `Too many failed attempts. Please wait ${remainingMinutes} minute${remainingMinutes === 1 ? '' : 's'} and try again.`;
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

function applySecurityHeaders(res, { isApi = false } = {}) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https://paid.originalapis.workers.dev");

  if (isApi) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}

function getAllowedOrigin(req) {
  const origin = req.headers.origin;
  const allowedOrigins = new Set([
    ALLOWED_ORIGIN,
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
  ]);

  if (!origin) {
    return ALLOWED_ORIGIN;
  }

  return allowedOrigins.has(origin) ? origin : null;
}

function applyCorsHeaders(req, res) {
  const allowedOrigin = getAllowedOrigin(req);

  if (allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function getContentType(filePath) {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
}

function sendFile(res, filePath, statusCode = 200) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Not found.' }));
      return;
    }

    res.writeHead(statusCode, { 'Content-Type': getContentType(filePath) });
    res.end(data);
  });
}

function serveStatic(req, res, url) {
  if (req.method !== 'GET' || url.pathname.startsWith('/api')) {
    return false;
  }

  const pathname = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
  const relativePath = pathname.replace(/^\/+/, '') || 'index.html';
  const requestedFile = path.resolve(DIST_DIR, relativePath);
  const indexFile = path.resolve(DIST_DIR, 'index.html');

  if (!requestedFile.startsWith(DIST_DIR)) {
    sendFile(res, indexFile);
    return true;
  }

  if (fs.existsSync(requestedFile) && fs.statSync(requestedFile).isFile()) {
    sendFile(res, requestedFile);
  } else {
    sendFile(res, indexFile);
  }

  return true;
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
  const isApiRequest = url.pathname.startsWith('/api');

  applySecurityHeaders(res, { isApi: isApiRequest });

  if (req.method === 'OPTIONS') {
    applyCorsHeaders(req, res);
    res.writeHead(204);
    res.end();
    return;
  }

  applyCorsHeaders(req, res);

  if (req.method === 'GET' && url.pathname === '/') {
    if (fs.existsSync(path.join(DIST_DIR, 'index.html'))) {
      sendFile(res, path.join(DIST_DIR, 'index.html'));
      return;
    }

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
        const lockoutMessage = getLockoutMessage(req);
        sendJson(res, 429, { ok: false, error: lockoutMessage || 'Too many attempts. Try again later.' });
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
        recordVerifyAttempt(req, false);
        sendJson(res, 401, { ok: false, error: 'Incorrect access code.' });
        return;
      }

      recordVerifyAttempt(req, true);

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

  if (serveStatic(req, res, url)) {
    return;
  }

  sendJson(res, 404, { ok: false, error: 'Not found.' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Secure lookup server running on http://localhost:${PORT}`);

  if (!SHEETS_WEBHOOK_URL) {
    console.warn('Google Sheets logging is disabled because GOOGLE_SHEETS_WEBHOOK_URL/SHEETS_WEBHOOK_URL is not set.');
  } else {
    console.log('Google Sheets logging is enabled.');
  }
});
