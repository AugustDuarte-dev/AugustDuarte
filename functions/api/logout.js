import { clearCookie } from '../_shared/auth.js';

export async function onRequestPost() {
  return new Response(null, {
    status: 302,
    headers: { location: '/login', 'set-cookie': clearCookie() }
  });
}
