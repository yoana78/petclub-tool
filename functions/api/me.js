import { verifyToken, getCookie } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const token = getCookie(request, 'session');
  const payload = await verifyToken(token, env.SESSION_SECRET);
  if (!payload) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  const user = await env.DB.prepare('SELECT id, name, status FROM users WHERE id = ?')
    .bind(payload.id)
    .first();

  if (!user || user.status !== 'approved') {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  return Response.json({ id: user.id, name: user.name });
}
