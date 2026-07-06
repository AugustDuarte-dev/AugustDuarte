import { isAuthed, unauthed, json } from '../_shared/auth.js';

const MAX_FILE_BYTES = 500 * 1024 * 1024; // 500 MB

export async function onRequestPost({ request, env }) {
  if (!await isAuthed(request, env)) return unauthed();

  let formData;
  try {
    formData = await request.formData();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  const files = formData.getAll('files');
  if (!files || files.length === 0) {
    return json({ error: 'No files received' }, 400);
  }

  const uploaded = [];
  for (const file of files) {
    if (file.size > MAX_FILE_BYTES) {
      return json({ error: `${file.name} exceeds 500 MB limit` }, 413);
    }
    // Sanitize filename
    const safeName = file.name.replace(/[^\w.\-\s]/g, '_');
    if (!safeName) continue;

    const buffer = await file.arrayBuffer();
    await env.FILES.put(safeName, buffer, {
      httpMetadata: { contentType: file.type || 'application/octet-stream' }
    });
    uploaded.push(safeName);
  }

  return json({ success: true, uploaded });
}
