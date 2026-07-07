const { getCookieValue, getEnv, handleOptions, parseAccessToken, saveSearchToSheet, sendJson } = require('./_lib/backend.cjs');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    handleOptions(req, res);
    return;
  }

  if (req.method !== 'GET') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed.' });
    return;
  }

  const sessionToken = getCookieValue(req, 'vehicle_lookup_session');
  if (!parseAccessToken(sessionToken)) {
    sendJson(req, res, 401, { ok: false, error: 'Unauthorized.' });
    return;
  }

  const vehicle = String(req.query.rc || '').trim();
  if (!vehicle) {
    sendJson(req, res, 400, { ok: false, error: 'Vehicle number is required.' });
    return;
  }

  const { LOOKUP_KEY } = getEnv();
  if (!LOOKUP_KEY) {
    sendJson(req, res, 500, { ok: false, error: 'Lookup key is not configured.' });
    return;
  }

  try {
    const target = new URL('https://paid.originalapis.workers.dev/deep');
    target.searchParams.set('key', LOOKUP_KEY);
    target.searchParams.set('rc', vehicle);

    const response = await fetch(target.toString());
    const data = await response.json();

    const loggedPayload = response.ok
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
      result: loggedPayload,
      status: response.ok ? 'ok' : 'error',
      responseStatus: response.status,
    });

    sendJson(req, res, response.ok ? 200 : response.status, data);
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

    sendJson(req, res, 502, { ok: false, error: 'Lookup failed.' });
  }
};