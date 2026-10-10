import { createRemoteJWKSet, jwtVerify } from 'jose';

export const ISSUER = 'https://api.tongji.edu.cn/keycloak/realms/OpenPlatform';
const AUTH = ISSUER + '/protocol/openid-connect/auth';
const TOKEN = 'https://api.tongji.edu.cn/v1/token';
const JWKS = createRemoteJWKSet(new URL(ISSUER + '/protocol/openid-connect/certs'));
const TTL = 600;
const COOKIE = '__Host-tj-auth';
const random = (bytes = 32) => base64url(crypto.getRandomValues(new Uint8Array(bytes)));
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export async function digest(text) {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))));
}
function configured(env) {
  return env.AUTH_ENABLED === 'true' && typeof env.CLIENT_ID === 'string' && env.CLIENT_ID.length > 0 &&
    typeof env.CLIENT_SECRET === 'string' && env.CLIENT_SECRET.length > 0 && env.DB && env.RATE_LIMITER &&
    env.PUBLIC_ORIGIN === 'https://tongji.hachile.org' && env.API_ORIGIN === 'https://tongji-api.hachile.org';
}
function headers(env, origin) {
  const result = new Headers({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Vary': 'Origin' });
  if (origin === env.PUBLIC_ORIGIN) {
    result.set('Access-Control-Allow-Origin', origin);
    result.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    result.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  return result;
}
function json(data, status, env, origin) {
  const h = headers(env, origin);
  h.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(data), { status, headers: h });
}
function redirect(env, values, cookie = '') {
  const h = headers(env);
  h.set('Location', env.PUBLIC_ORIGIN + '/#' + new URLSearchParams(values));
  if (cookie) h.set('Set-Cookie', cookie);
  return new Response(null, { status: 303, headers: h });
}
const clearCookie = `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
async function cleanup(env) {
  const now = Math.floor(Date.now() / 1000);
  if (env.DB) await env.DB.batch([
    env.DB.prepare('DELETE FROM auth_flows WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM proofs WHERE expires_at <= ?').bind(now)
  ]);
}
// 令牌必须验证签名和所有本次登录声明；解码 JWT 不能证明身份。
export async function verifyIdentity(token, key, clientId, nonce) {
  const { payload } = await jwtVerify(token, key, {
    issuer: ISSUER, audience: clientId, algorithms: ['RS256'], clockTolerance: 5,
    maxTokenAge: '10m', requiredClaims: ['sub', 'exp', 'iat', 'nonce', 'auth_time']
  });
  const now = Math.floor(Date.now() / 1000);
  if (payload.nonce !== nonce || typeof payload.sub !== 'string' || !payload.sub ||
    (payload.azp !== undefined && payload.azp !== clientId) ||
    (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId) ||
    !Number.isInteger(payload.auth_time) || payload.auth_time > now + 5 || payload.auth_time < now - TTL) {
    throw new Error('Invalid identity claims');
  }
}
async function handle(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (url.pathname === '/api/config' && request.method === 'GET') {
    return json({ enabled: Boolean(configured(env)), expiresIn: TTL, oneTime: true }, 200, env, origin);
  }
  if (url.pathname === '/api/verify' && request.method === 'OPTIONS') {
    return origin === env.PUBLIC_ORIGIN ? new Response(null, { status: 204, headers: headers(env, origin) }) : json({ error: 'forbidden' }, 403, env, origin);
  }
  const route = `${request.method} ${url.pathname}`;
  if (!['GET /auth/start', 'GET /auth/callback', 'POST /api/verify'].includes(route)) return json({ error: 'not_found' }, 404, env, origin);
  if (!configured(env)) return json({ error: 'authentication_not_enabled' }, 503, env, origin);
  if (url.origin !== env.API_ORIGIN) return json({ error: 'forbidden' }, 403, env, origin);
  if (route === 'POST /api/verify' && (origin !== env.PUBLIC_ORIGIN || !/^application\/json(?:;|$)/i.test(request.headers.get('Content-Type') || ''))) {
    return json({ error: 'forbidden' }, 403, env, origin);
  }
  // shortcut: 限流按 Cloudflare 机房和 IP 分组；高流量校园 NAT 可改为挑战票据限流。
  const key = 'tongji:' + url.pathname + ':' + await digest(request.headers.get('CF-Connecting-IP') || 'unknown');
  if (!(await env.RATE_LIMITER.limit({ key })).success) return json({ error: 'rate_limited' }, 429, env, origin);
  const now = Math.floor(Date.now() / 1000);
  if (route === 'GET /auth/start') {
    if (url.searchParams.get('consent') !== '1') return json({ error: 'consent_required' }, 400, env, origin);
    await cleanup(env);
    const state = random(), nonce = random(), verifier = random();
    await env.DB.prepare('INSERT INTO auth_flows (state_hash, nonce, verifier, expires_at) VALUES (?, ?, ?, ?)').bind(await digest(state), nonce, verifier, now + TTL).run();
    const auth = new URL(AUTH);
    auth.search = new URLSearchParams({ client_id: env.CLIENT_ID, redirect_uri: env.API_ORIGIN + '/auth/callback', response_type: 'code', response_mode: 'query', scope: 'openid', kc_idp_hint: 'tjiam', state, nonce, code_challenge: await digest(verifier), code_challenge_method: 'S256', prompt: 'login', max_age: '0' }).toString();
    const h = headers(env);
    h.set('Location', auth.href);
    h.set('Set-Cookie', `${COOKIE}=${state}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${TTL}`);
    return new Response(null, { status: 303, headers: h });
  }
  if (route === 'GET /auth/callback') {
    const state = url.searchParams.get('state');
    const cookie = request.headers.get('Cookie')?.split(';').map((item) => item.trim()).find((item) => item.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(state || '') || cookie !== state) return redirect(env, { error: 'expired' }, clearCookie);
    const flow = await env.DB.prepare('DELETE FROM auth_flows WHERE state_hash = ? RETURNING nonce, verifier, expires_at').bind(await digest(state)).first();
    if (!flow || flow.expires_at <= now) return redirect(env, { error: 'expired' }, clearCookie);
    if (url.searchParams.has('error')) return redirect(env, { error: 'denied' }, clearCookie);
    const code = url.searchParams.get('code');
    if (!code || code.length > 4096) return redirect(env, { error: 'failed' }, clearCookie);
    const response = await fetch(TOKEN, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: env.CLIENT_ID, client_secret: env.CLIENT_SECRET, code, code_verifier: flow.verifier, redirect_uri: env.API_ORIGIN + '/auth/callback' }), signal: AbortSignal.timeout(10000) });
    if (!response.ok) return redirect(env, { error: 'failed' }, clearCookie);
    const tokens = await response.json();
    await verifyIdentity(tokens.id_token, JWKS, env.CLIENT_ID, flow.nonce);
    const issuedAt = Math.floor(Date.now() / 1000);
    const proof = 'TJ-' + random(16);
    await env.DB.prepare('INSERT INTO proofs (code_hash, issued_at, expires_at) VALUES (?, ?, ?)').bind(await digest(proof), issuedAt, issuedAt + TTL).run();
    return redirect(env, { proof, expires: String(issuedAt + TTL) }, clearCookie);
  }
  if (Number(request.headers.get('Content-Length') || 0) > 1024) return json({ error: 'invalid_request' }, 400, env, origin);
  const reader = request.body?.getReader();
  if (!reader) return json({ error: 'invalid_request' }, 400, env, origin);
  let chunks = [], size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 1024) { await reader.cancel(); return json({ error: 'invalid_request' }, 400, env, origin); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let data;
  try { data = JSON.parse(new TextDecoder().decode(bytes)); } catch { return json({ error: 'invalid_request' }, 400, env, origin); }
  if (typeof data?.code !== 'string' || !/^TJ-[A-Za-z0-9_-]{22}$/.test(data.code.trim())) return json({ valid: false }, 200, env, origin);
  // 单条 DELETE RETURNING 保证并发核验最多只有一次成功。
  const verifiedAt = Math.floor(Date.now() / 1000);
  const proof = await env.DB.prepare('DELETE FROM proofs WHERE code_hash = ? AND expires_at > ? RETURNING issued_at, expires_at').bind(await digest(data.code.trim()), verifiedAt).first();
  return json(proof ? { valid: true, type: 'tongji_account', issuedAt: proof.issued_at, expiresAt: proof.expires_at, verifiedAt } : { valid: false }, 200, env, origin);
}
export default {
  async fetch(request, env) {
    try { return await handle(request, env); }
    catch {
      if (new URL(request.url).pathname === '/auth/callback' && env.PUBLIC_ORIGIN === 'https://tongji.hachile.org') return redirect(env, { error: 'failed' }, clearCookie);
      return json({ error: 'service_unavailable' }, 503, env, request.headers.get('Origin'));
    }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(cleanup(env)); }
};
