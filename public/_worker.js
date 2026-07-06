/**
 * AugustDuarte File Portal — Cloudflare Pages Worker
 *
 * Required setup in Cloudflare Pages → Settings:
 *   Build output directory : public
 *   Environment variables  : SITE_USER, SITE_PASS, JWT_SECRET
 *   R2 bucket binding      : variable "FILES" → bucket "augustduarte-files"
 */

const COOKIE   = 'auth';
const TTL      = 24 * 60 * 60 * 1000;  // 24 hours
const MAX_SIZE = 500 * 1024 * 1024;     // 500 MB

// ── JWT (built-in Web Crypto, zero dependencies) ──────────────────────────────

async function jwtKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']
  );
}

const b64u = buf =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

const b64d = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  return atob(s + '='.repeat((4 - s.length % 4) % 4));
};

async function signToken(secret) {
  const h   = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const p   = btoa(JSON.stringify({ ok: 1, exp: Date.now() + TTL })).replace(/=/g, '');
  const key = await jwtKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(sig)}`;
}

async function verifyToken(token, secret) {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) return false;
    const key      = await jwtKey(secret);
    const sigBytes = Uint8Array.from(b64d(s), c => c.charCodeAt(0));
    const ok       = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return false;
    const { exp } = JSON.parse(b64d(p));
    return Date.now() < exp;
  } catch { return false; }
}

function getToken(request) {
  const cookies = request.headers.get('cookie') || '';
  const m = cookies.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? m[1] : null;
}

const authed = async (req, env) => {
  const t = getToken(req);
  return t ? verifyToken(t, env.JWT_SECRET) : false;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const json    = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json' } });
const redir   = (url, extra = {}) => new Response(null, { status: 302, headers: { location: url, ...extra } });
const unauth  = () => json({ error: 'Unauthorized' }, 401);
const setCook = t  => `${COOKIE}=${t}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;
const clrCook = () => `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;

const safeKey = raw => {
  const k = decodeURIComponent(raw);
  return (!k || k.includes('/') || k.includes('..')) ? null : k;
};

// ── Handlers ──────────────────────────────────────────────────────────────────

async function login(req, env) {
  const form = await req.formData();
  if (form.get('username') === env.SITE_USER && form.get('password') === env.SITE_PASS) {
    return redir('/', { 'set-cookie': setCook(await signToken(env.JWT_SECRET)) });
  }
  return redir('/login?error=1');
}

const logout = () => redir('/login', { 'set-cookie': clrCook() });

async function listFiles(req, env) {
  if (!await authed(req, env)) return unauth();
  const listed = await env.FILES.list();
  const files  = (listed.objects || [])
    .map(o => ({ name: o.key, size: o.size, modified: o.uploaded }))
    .sort((a, b) => new Date(b.modified) - new Date(a.modified));
  return json(files);
}

async function upload(req, env) {
  if (!await authed(req, env)) return unauth();
  const form  = await req.formData();
  const files = form.getAll('files');
  if (!files.length) return json({ error: 'No files received' }, 400);
  const uploaded = [];
  for (const file of files) {
    if (file.size > MAX_SIZE) return json({ error: `"${file.name}" exceeds 500 MB` }, 413);
    const name = file.name.replace(/[^\w.\-\s]/g, '_');
    if (!name) continue;
    await env.FILES.put(name, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type || 'application/octet-stream' }
    });
    uploaded.push(name);
  }
  return json({ success: true, uploaded });
}

async function deleteFile(req, env, raw) {
  if (!await authed(req, env)) return unauth();
  const key = safeKey(raw);
  if (!key) return json({ error: 'Invalid filename' }, 400);
  await env.FILES.delete(key);
  return json({ success: true });
}

async function download(req, env, raw) {
  if (!await authed(req, env)) return unauth();
  const key = safeKey(raw);
  if (!key) return new Response('Invalid filename', { status: 400 });
  const obj = await env.FILES.get(key);
  if (!obj) return new Response('File not found', { status: 404 });
  const headers = new Headers({
    'content-type':        obj.httpMetadata?.contentType || 'application/octet-stream',
    'content-disposition': `attachment; filename="${encodeURIComponent(key)}"`,
  });
  if (obj.size) headers.set('content-length', String(obj.size));
  return new Response(obj.body, { headers });
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const m = request.method;

    if (pathname === '/api/login'  && m === 'POST')   return login(request, env);
    if (pathname === '/api/logout' && m === 'POST')   return logout();
    if (pathname === '/api/files'  && m === 'GET')    return listFiles(request, env);
    if (pathname === '/api/upload' && m === 'POST')   return upload(request, env);

    if (pathname.startsWith('/api/files/')    && m === 'DELETE')
      return deleteFile(request, env, pathname.slice(11));

    if (pathname.startsWith('/api/download/') && m === 'GET')
      return download(request, env, pathname.slice(14));

    // Everything else → serve static files (login.html, index.html, etc.)
    return env.ASSETS.fetch(request);
  }
};
