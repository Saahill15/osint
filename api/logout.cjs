const { clearAccessCookieParts, handleOptions, sendJson } = require('./_lib/backend.cjs');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    handleOptions(req, res);
    return;
  }

  if (req.method !== 'POST') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed.' });
    return;
  }

  res.setHeader('Set-Cookie', clearAccessCookieParts().join('; '));
  sendJson(req, res, 200, { ok: true });
};