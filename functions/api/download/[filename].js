import { isAuthed, unauthed } from '../../_shared/auth.js';

export async function onRequestGet({ request, env, params }) {
  if (!await isAuthed(request, env)) return unauthed();

  const key = decodeURIComponent(params.filename);
  if (!key || key.includes('/') || key.includes('..')) {
    return new Response('Invalid filename', { status: 400 });
  }

  const object = await env.FILES.get(key);
  if (!object) return new Response('File not found', { status: 404 });

  const headers = new Headers();
  headers.set('content-disposition', `attachment; filename="${encodeURIComponent(key)}"`);
  headers.set('content-type', object.httpMetadata?.contentType || 'application/octet-stream');
  if (object.size) headers.set('content-length', String(object.size));

  return new Response(object.body, { headers });
}
