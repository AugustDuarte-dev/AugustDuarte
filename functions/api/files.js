import { isAuthed, unauthed, json } from '../_shared/auth.js';

export async function onRequestGet({ request, env }) {
  if (!await isAuthed(request, env)) return unauthed();

  const listed = await env.FILES.list();
  const files = (listed.objects || [])
    .map(obj => ({ name: obj.key, size: obj.size, modified: obj.uploaded }))
    .sort((a, b) => new Date(b.modified) - new Date(a.modified));

  return json(files);
}
