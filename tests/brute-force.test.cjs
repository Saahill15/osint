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
    for (let index = 0; index < 3; index += 1) {
      const response = await fetch('http://127.0.0.1:3415/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'wrong' }),
      });
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

    const firstResponse = await fetch('http://127.0.0.1:3416/api/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '203.0.113.5, 10.0.0.1',
      },
      body: JSON.stringify({ code: 'wrong' }),
    });
    assert.equal(firstResponse.status, 401);

    const secondResponse = await fetch('http://127.0.0.1:3416/api/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '203.0.113.5',
      },
      body: JSON.stringify({ code: 'wrong' }),
    });
    assert.equal(secondResponse.status, 401);

    const lockedResponse = await fetch('http://127.0.0.1:3416/api/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '203.0.113.5',
      },
      body: JSON.stringify({ code: 'test-access' }),
    });

    assert.equal(lockedResponse.status, 429);
  } finally {
    server.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  if (stderr) {
    console.warn(stderr);
  }
});
