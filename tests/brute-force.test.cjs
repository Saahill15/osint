const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

function waitForServer(port, timeoutMs = 10000) {
  const startedAt = Date.now();

  return new Promise((resolve, reject) => {
    const tryConnect = async () => {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/`);
        if (response.ok) {
          resolve();
          return;
        }
      } catch (error) {
        // keep waiting
      }

      if (Date.now() - startedAt > timeoutMs) {
        reject(new Error(`Server did not start on port ${port}`));
        return;
      }

      setTimeout(tryConnect, 200);
    };

    tryConnect();
  });
}

async function verifyWithCookie(port, code, cookieHeader = '') {
  const headers = { 'Content-Type': 'application/json' };
  if (cookieHeader) {
    headers.Cookie = cookieHeader;
  }

  const response = await fetch(`http://127.0.0.1:${port}/api/verify`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ code }),
  });

  const setCookie = response.headers.get('set-cookie');
  const nextCookie = setCookie ? setCookie.split(';')[0] : cookieHeader;
  return { response, nextCookie };
}

test('verify endpoint throttles repeated failed attempts', async () => {
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.cjs')], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: '3415',
      ACCESS_CODE: 'test-access',
      BRUTE_FORCE_MAX_ATTEMPTS: '2',
      BRUTE_FORCE_WINDOW_MS: '60000',
      BRUTE_FORCE_LOCKOUT_MS: '1000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  server.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForServer(3415);

    const statuses = [];
    let cookieHeader = '';
    for (let index = 0; index < 3; index += 1) {
      const { response, nextCookie } = await verifyWithCookie(3415, 'wrong', cookieHeader);
      cookieHeader = nextCookie;
      statuses.push(response.status);
    }

    assert.deepEqual(statuses, [401, 401, 429]);
  } finally {
    server.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  if (stderr) {
    console.warn(stderr);
  }
});

test('verify endpoint keeps the lockout across forwarded-ip variants', async () => {
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.cjs')], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: '3416',
      ACCESS_CODE: 'test-access',
      BRUTE_FORCE_MAX_ATTEMPTS: '2',
      BRUTE_FORCE_WINDOW_MS: '60000',
      BRUTE_FORCE_LOCKOUT_MS: '1000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  server.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForServer(3416);

    const { response: firstResponse, nextCookie: cookieA } = await verifyWithCookie(3416, 'wrong', '');
    assert.equal(firstResponse.status, 401);

    const { response: secondResponse } = await verifyWithCookie(3416, 'wrong', cookieA);
    assert.equal(secondResponse.status, 401);

    const { response: lockedResponse } = await verifyWithCookie(3416, 'test-access', cookieA);

    assert.equal(lockedResponse.status, 429);
  } finally {
    server.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  if (stderr) {
    console.warn(stderr);
  }
});

test('verify endpoint scopes lockout to the browser client, not the shared network', async () => {
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.cjs')], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: '3417',
      ACCESS_CODE: 'test-access',
      BRUTE_FORCE_MAX_ATTEMPTS: '2',
      BRUTE_FORCE_WINDOW_MS: '60000',
      BRUTE_FORCE_LOCKOUT_MS: '1000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  server.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForServer(3417);

    const { response: firstBrowser, nextCookie: browserCookieA } = await verifyWithCookie(3417, 'wrong', 'osint_verify_client=browser-a');
    assert.equal(firstBrowser.status, 401);

    const { response: secondBrowser } = await verifyWithCookie(3417, 'wrong', browserCookieA);
    assert.equal(secondBrowser.status, 401);

    const { response: lockedBrowserA } = await verifyWithCookie(3417, 'test-access', browserCookieA);

    assert.equal(lockedBrowserA.status, 429);

    const { response: browserBResponse } = await verifyWithCookie(3417, 'test-access', 'osint_verify_client=browser-b');

    assert.equal(browserBResponse.status, 401);
  } finally {
    server.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  if (stderr) {
    console.warn(stderr);
  }
});
