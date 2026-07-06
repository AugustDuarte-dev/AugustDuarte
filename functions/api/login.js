import { createToken, setCookie } from '../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  const form = await request.formData();
  const username = form.get('username');
  const password = form.get('password');

  if (username === env.SITE_USER && password === env.SITE_PASS) {
    const token = await createToken(env.JWT_SECRET);
    return new Response(null, {
      status: 302,
      headers: { location: '/', 'set-cookie': setCookie(token) }
    });
  }

  return new Response(null, {
    status: 302,
    headers: { location: '/login?error=1' }
  });
}
