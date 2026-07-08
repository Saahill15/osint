const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { fetchLookupWithRetry } = require('../lib/upstream.cjs');

function startTestServer() {
  let calls = 0;
  const server = http.createServer((req, res) => {
    calls += 1;
    if (calls === 1) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'cold start' }));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, calls }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, port: address.port, getCalls: () => calls });
    });
  });
}

test('fetchLookupWithRetry retries transient upstream failures', async () => {
  const { server, port, getCalls } = await startTestServer();

  try {
    const result = await fetchLookupWithRetry({
      lookupKey: 'test-key',
      vehicle: 'ABC123',
      baseUrl: `http://127.0.0.1:${port}/deep`,
      maxAttempts: 3,
      retryDelayMs: 50,
      timeoutMs: 1000,
    });

    assert.equal(result.ok, true);
    assert.equal(result.attempts, 2);
    assert.equal(getCalls(), 2);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
