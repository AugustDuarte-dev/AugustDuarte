const COOKIE = 'auth';
const TTL = 24 * 60 * 60 * 1000; // 24 hours

async function getKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function toB64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function fromB64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(s + '='.repeat((4 - s.length % 4) % 4));
}

export async function createToken(secret) {
  const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({ ok: true, exp: Date.now() + TTL })).replace(/=/g, '');
  const data    = `${header}.${payload}`;
  const key     = await getKey(secret);
  const sig     = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${toB64url(sig)}`;
}

export async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [h, p, s] = parts;
    const key = await getKey(secret);
    const sigBytes = Uint8Array.from(fromB64url(s), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(`${h}.${p}`));
    if (!valid) return false;
    const { exp } = JSON.parse(fromB64url(p));
    return Date.now() < exp;
  } catch {
    return false;
  }
}

export function getToken(request) {
  const cookies = request.headers.get('cookie') || '';
  const match = cookies.match(new RegExp(`(?:^|; )${COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}

export async function isAuthed(request, env) {
  const token = getToken(request);
  return token ? verifyToken(token, env.JWT_SECRET) : false;
}

export const setCookie = (token) =>
  `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;

export const clearCookie = () =>
  `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' }
  });

export const unauthed = () => json({ error: 'Unauthorized' }, 401);
