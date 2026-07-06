import { isAuthed, unauthed, json } from '../../_shared/auth.js';

export async function onRequestDelete({ request, env, params }) {
  if (!await isAuthed(request, env)) return unauthed();

  const key = decodeURIComponent(params.filename);
  if (!key || key.includes('/') || key.includes('..')) {
    return json({ error: 'Invalid filename' }, 400);
  }

  await env.FILES.delete(key);
  return json({ success: true });
}
