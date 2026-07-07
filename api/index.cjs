const { handleOptions, sendJson } = require('./_lib/backend.cjs');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    handleOptions(req, res);
    return;
  }

  if (req.method !== 'GET') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed.' });
    return;
  }

  sendJson(req, res, 200, { ok: true, message: 'Vehicle API is running on Vercel.' });
};