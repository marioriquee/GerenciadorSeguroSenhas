'use strict';

const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createPasswordManagerServer } = require('../src/server');

async function main() {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'pm-setor-'));
  const setupToken = 'codigo-inicial-seguro-2026';
  const app = createPasswordManagerServer({
    dataDir,
    publicDir: path.join(__dirname, '..', 'public'),
    storageProvider: 'file',
    setupToken
  });
  const server = await app.listen(0, '127.0.0.1');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';

  async function request(route, options = {}) {
    const response = await fetch(`${baseUrl}${route}`, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(cookie ? { Cookie: cookie } : {})
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    const setCookie = response.headers.get('set-cookie');
    if (setCookie) {
      cookie = setCookie.split(';')[0];
    }

    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(payload?.error || `HTTP ${response.status}`);
    }

    return payload;
  }

  try {
    let payload = await request('/api/setup');
    assert.equal(payload.hasUsers, false);

    await assert.rejects(
      () => request('/api/setup/first-admin', {
        method: 'POST',
        body: {
          name: 'Administrador',
          username: 'admin01',
          password: 'Senha26!',
          setupToken: 'codigo-errado'
        }
      }),
      /Codigo de instalacao invalido/
    );

    payload = await request('/api/setup/first-admin', {
      method: 'POST',
      body: {
        name: 'Administrador',
        username: 'admin01',
        password: 'Senha26!',
        setupToken
      }
    });
    assert.equal(payload.user.role, 'admin');

    payload = await request('/api/me');
    assert.equal(payload.user.username, 'admin01');

    await request('/api/vault', {
      method: 'POST',
      body: {
        title: 'Sistema interno',
        login: 'setor',
        password: 'SenhaMuitoSecreta!42',
        url: 'https://intranet.local',
        category: 'Infra',
        notes: 'Registro de teste'
      }
    });

    payload = await request('/api/vault');
    assert.equal(payload.entries.length, 1);
    assert.equal(payload.entries[0].password, 'SenhaMuitoSecreta!42');

    const rawDatabase = await fsp.readFile(path.join(dataDir, 'database.json'), 'utf8');
    assert.equal(rawDatabase.includes('SenhaMuitoSecreta!42'), false);

    await request('/api/users', {
      method: 'POST',
      body: {
        name: 'Equipe',
        username: 'equipe01',
        password: 'Equipe1!',
        role: 'user'
      }
    });

    payload = await request('/api/users');
    assert.equal(payload.users.some((user) => user.username === 'equipe01'), true);

    console.log('Smoke test passed: login, usuarios e cofre criptografado funcionando.');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
