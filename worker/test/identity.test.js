import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { ISSUER, digest, verifyIdentity } from '../src/index.js';

const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwk = await exportJWK(publicKey);
jwk.kid = 'test-key';
jwk.alg = 'RS256';
const origin = 'https://tongji.hachile.org';
const api = 'https://tongji-api.hachile.org';
function database() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../migrations/0001_identity.sql', import.meta.url), 'utf8'));
  const binding = {
    prepare(sql) {
      let params = [];
      const statement = { bind(...args) { params = args; return statement; }, async run() { return db.prepare(sql).run(...params); }, async first() { return db.prepare(sql).get(...params) || null; } };
      return statement;
    },
    async batch(statements) { return Promise.all(statements.map((s) => s.run())); }
  };
  return { db, binding };
}
function environment(binding) {
  return { AUTH_ENABLED: 'true', CLIENT_ID: 'test-client', CLIENT_SECRET: 'test-secret', PUBLIC_ORIGIN: origin, API_ORIGIN: api, DB: binding, RATE_LIMITER: { async limit() { return { success: true }; } } };
}
const req = (path, options = {}) => new Request(api + path, options);
const verifyRequest = (code, from = origin) => req('/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: from }, body: JSON.stringify({ code }) });
async function token(nonce, overrides = {}, key = privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ nonce, auth_time: now, ...overrides }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(ISSUER).setAudience('test-client').setSubject('not-persisted-student-id').setIssuedAt(now).setExpirationTime(now + 300).sign(key);
}

test('identity proof security and one-time lifecycle', async (t) => {
  const { db, binding } = database();
  const env = environment(binding);
  const actualFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = actualFetch; db.close(); });

  await t.test('default disabled: no database or upstream access', async () => {
    const config = await worker.fetch(req('/api/config', { headers: { Origin: origin } }), {});
    assert.equal((await config.json()).enabled, false);
    for (const request of [req('/auth/start?consent=1'), req('/auth/callback?code=test'), verifyRequest('TJ-' + 'x'.repeat(22))]) {
      assert.equal((await worker.fetch(request, {})).status, 503);
    }
    assert.equal((await worker.fetch(req('/api/config'), { ...env, CLIENT_SECRET: '' })).status, 200);
    assert.equal((await (await worker.fetch(req('/api/config'), { ...env, CLIENT_SECRET: '' })).json()).enabled, false);
  });
  await t.test('JWT rejects wrong nonce, audience, issuer, signature and stale identity', async () => {
    await verifyIdentity(await token('correct'), publicKey, 'test-client', 'correct');
    await assert.rejects(verifyIdentity(await token('wrong'), publicKey, 'test-client', 'correct'));
    await assert.rejects(verifyIdentity(await token('correct'), publicKey, 'other-client', 'correct'));
    await assert.rejects(verifyIdentity(await token('correct', { azp: 'other-client' }), publicKey, 'test-client', 'correct'));
    await assert.rejects(verifyIdentity(await token('correct', { auth_time: 1 }), publicKey, 'test-client', 'correct'));
    const badKey = await generateKeyPair('RS256');
    await assert.rejects(verifyIdentity(await token('correct', {}, badKey.privateKey), publicKey, 'test-client', 'correct'));
    const now = Math.floor(Date.now() / 1000);
    for (const claims of [
      { iss: 'https://attacker.invalid', aud: 'test-client', sub: 'id', exp: now + 60, iat: now, nonce: 'correct', auth_time: now },
      { iss: ISSUER, aud: 'test-client', sub: 'id', exp: now - 30, iat: now, nonce: 'correct', auth_time: now },
      { iss: ISSUER, aud: 'test-client', sub: 'id', exp: now + 60, iat: now, auth_time: now }
    ]) {
      const signed = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256' }).sign(privateKey);
      await assert.rejects(verifyIdentity(signed, publicKey, 'test-client', 'correct'));
    }
  });
  await t.test('authentication start requires consent, creates PKCE and secure cookie', async () => {
    assert.equal((await worker.fetch(req('/auth/start'), env)).status, 400);
    const response = await worker.fetch(req('/auth/start?consent=1'), env);
    assert.equal(response.status, 303);
    const url = new URL(response.headers.get('Location'));
    assert.equal(url.origin, 'https://api.tongji.edu.cn');
    assert.equal(url.searchParams.get('redirect_uri'), api + '/auth/callback');
    assert.equal(url.searchParams.get('scope'), 'openid');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('prompt'), 'login');
    const flow = db.prepare('SELECT * FROM auth_flows WHERE state_hash = ?').get(await digest(url.searchParams.get('state')));
    assert.equal(url.searchParams.get('code_challenge'), await digest(flow.verifier));
    assert.equal(flow.nonce, url.searchParams.get('nonce'));
    assert.match(response.headers.get('Set-Cookie'), /Secure; HttpOnly; SameSite=Lax/);
    assert.equal(db.prepare('SELECT count(*) AS n FROM proofs').get().n, 0);
  });
  await t.test('callback checks browser state before any upstream request; denial consumes flow', async () => {
    globalThis.fetch = () => { throw new Error('Unexpected upstream call'); };
    const started = await worker.fetch(req('/auth/start?consent=1'), env);
    const state = new URL(started.headers.get('Location')).searchParams.get('state');
    const deniedUrl = '/auth/callback?error=access_denied&state=' + state;
    const mismatch = await worker.fetch(req(deniedUrl), env);
    assert.match(mismatch.headers.get('Location'), /error=expired/);
    assert.ok(db.prepare('SELECT * FROM auth_flows WHERE state_hash = ?').get(await digest(state)));
    const denied = await worker.fetch(req(deniedUrl, { headers: { Cookie: '__Host-tj-auth=' + state } }), env);
    assert.match(denied.headers.get('Location'), /error=denied/);
    assert.equal(db.prepare('SELECT * FROM auth_flows WHERE state_hash = ?').get(await digest(state)), undefined);
  });
  await t.test('full callback verifies signed token; only hash/time persist; replay fails', async () => {
    const started = await worker.fetch(req('/auth/start?consent=1'), env);
    const auth = new URL(started.headers.get('Location'));
    const state = auth.searchParams.get('state');
    const nonce = auth.searchParams.get('nonce');
    globalThis.fetch = async (url, options) => {
      if (String(url).endsWith('/certs')) return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'Content-Type': 'application/json' } });
      assert.equal(String(url), 'https://api.tongji.edu.cn/v1/token');
      assert.equal(options.body.get('client_secret'), 'test-secret');
      assert.equal(await digest(options.body.get('code_verifier')), auth.searchParams.get('code_challenge'));
      return new Response(JSON.stringify({ id_token: await token(nonce), access_token: 'not-persisted-access-token' }));
    };
    const callback = req('/auth/callback?state=' + state + '&code=official-code', { headers: { Cookie: '__Host-tj-auth=' + state } });
    const response = await worker.fetch(callback, env);
    const fragment = new URLSearchParams(new URL(response.headers.get('Location')).hash.slice(1));
    const code = fragment.get('proof');
    assert.match(code, /^TJ-[A-Za-z0-9_-]{22}$/);
    const record = db.prepare('SELECT * FROM proofs WHERE code_hash = ?').get(await digest(code));
    assert.deepEqual(Object.keys(record), ['code_hash', 'issued_at', 'expires_at']);
    assert.equal(record.expires_at - record.issued_at, 600);
    assert.ok(!JSON.stringify(record).includes('not-persisted'));
    assert.match((await worker.fetch(callback, env)).headers.get('Location'), /error=expired/);
    assert.equal((await worker.fetch(verifyRequest(code, 'https://attacker.invalid'), env)).status, 403);
    assert.equal((await worker.fetch(verifyRequest(code), { ...env, RATE_LIMITER: { async limit() { return { success: false }; } } })).status, 429);
    const results = await Promise.all([worker.fetch(verifyRequest(code), env), worker.fetch(verifyRequest(code), env)]);
    const bodies = await Promise.all(results.map((r) => r.json()));
    assert.equal(bodies.filter((r) => r.valid).length, 1);
    assert.equal((await (await worker.fetch(verifyRequest(code), env)).json()).valid, false);
  });
  await t.test('expired, malformed and oversized codes fail; cleanup removes expired data', async () => {
    const code = 'TJ-' + 'A'.repeat(22);
    await binding.prepare('INSERT INTO proofs VALUES (?, ?, ?)').bind(await digest(code), 1, 2).run();
    assert.equal((await (await worker.fetch(verifyRequest(code), env)).json()).valid, false);
    assert.equal((await (await worker.fetch(verifyRequest("' OR 1=1 --"), env)).json()).valid, false);
    assert.equal((await worker.fetch(verifyRequest('x'.repeat(2000)), env)).status, 400);
    assert.equal((await worker.fetch(req('/api/verify', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: '{oops' }), env)).status, 400);
    await worker.fetch(req('/auth/start?consent=1'), env);
    assert.equal(db.prepare('SELECT count(*) AS n FROM proofs').get().n, 0);
  });
  await t.test('upstream failure produces safe result, never raw error or token', async () => {
    const started = await worker.fetch(req('/auth/start?consent=1'), env);
    const state = new URL(started.headers.get('Location')).searchParams.get('state');
    globalThis.fetch = async () => { throw new Error('sensitive secret'); };
    const response = await worker.fetch(req('/auth/callback?state=' + state + '&code=x', { headers: { Cookie: '__Host-tj-auth=' + state } }), env);
    assert.equal(response.headers.get('Location'), origin + '/#error=failed');
    assert.match(response.headers.get('Set-Cookie'), /Max-Age=0/);
    assert.equal(await response.text(), '');
  });
  await t.test('expiration is checked after request body finishes, including slow submissions', async () => {
    const code = 'TJ-' + 'B'.repeat(22);
    const actualNow = Date.now;
    let clock = actualNow();
    await binding.prepare('INSERT INTO proofs VALUES (?, ?, ?)').bind(await digest(code), Math.floor(clock / 1000), Math.floor(clock / 1000) + 10).run();
    Date.now = () => clock;
    try {
      let pulled = false;
      const body = new ReadableStream({ pull(controller) {
        if (!pulled) { pulled = true; controller.enqueue(new TextEncoder().encode(JSON.stringify({ code }))); }
        else { clock += 20000; controller.close(); }
      } });
      const request = req('/api/verify', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body, duplex: 'half' });
      assert.equal((await (await worker.fetch(request, env)).json()).valid, false);
    } finally { Date.now = actualNow; }
  });
});
