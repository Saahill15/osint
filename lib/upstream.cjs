async function fetchLookupWithRetry({
  lookupKey,
  vehicle,
  baseUrl,
  maxAttempts = 3,
  retryDelayMs = 800,
  timeoutMs = 5000,
}) {
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const target = new URL(baseUrl);
      target.searchParams.set('key', lookupKey);
      target.searchParams.set('rc', vehicle);

      const response = await fetch(target.toString(), {
        method: 'GET',
        signal: controller.signal,
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data?.error || data?.result?.error || `Upstream returned ${response.status}`);
      }

      return {
        ok: true,
        attempts: attempt,
        data,
      };
    } catch (error) {
      lastError = error;
      if (attempt >= maxAttempts) {
        break;
      }

      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    ok: false,
    attempts: maxAttempts,
    error: lastError ? lastError.message : 'Lookup failed.',
  };
}

module.exports = {
  fetchLookupWithRetry,
};
