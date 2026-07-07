const {
  createAccessToken,
  getAccessCookieParts,
  getEnv,
  getJsonBody,
  handleOptions,
  isVerifyRateLimited,
  sendJson,
  timingSafeEqual,
} = require('./_lib/backend.cjs');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    handleOptions(req, res);
    return;
  }

  if (req.method !== 'POST') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed.' });
    return;
  }

  try {
    if (isVerifyRateLimited(req)) {
      sendJson(req, res, 429, { ok: false, error: 'Too many attempts. Try again later.' });
      return;
    }

    const { ACCESS_CODE, SESSION_TTL_MS } = getEnv();
    const body = await getJsonBody(req);
    const provided = String(body.code || '').trim();

    if (!ACCESS_CODE) {
      sendJson(req, res, 500, { ok: false, error: 'Server access code is not configured.' });
      return;
    }

    const expectedBuffer = Buffer.from(ACCESS_CODE);
    const providedBuffer = Buffer.from(provided);
    const matches = timingSafeEqual(expectedBuffer, providedBuffer);

    if (!matches) {
      sendJson(req, res, 401, { ok: false, error: 'Incorrect access code.' });
      return;
    }

    const token = createAccessToken();
    const cookieParts = getAccessCookieParts(token, Math.max(1, Math.floor(SESSION_TTL_MS / 1000)));

    res.setHeader('Set-Cookie', cookieParts.join('; '));
    sendJson(req, res, 200, { ok: true, expiresAt: Date.now() + SESSION_TTL_MS, sessionTtlMs: SESSION_TTL_MS });
  } catch (error) {
    sendJson(req, res, 400, { ok: false, error: 'Invalid request.' });
  }
};