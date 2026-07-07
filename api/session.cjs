const { getCookieValue, handleOptions, parseAccessToken, sendJson } = require('./_lib/backend.cjs');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    handleOptions(req, res);
    return;
  }

  if (req.method !== 'GET') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed.' });
    return;
  }

  const token = getCookieValue(req, 'vehicle_lookup_session');
  const payload = parseAccessToken(token);

  if (!payload) {
    sendJson(req, res, 401, { authenticated: false });
    return;
  }

  sendJson(req, res, 200, {
    authenticated: true,
    expiresAt: payload.exp,
    remainingMs: Math.max(0, payload.exp - Date.now()),
  });
};