import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  if (!(await requireAdmin(request, env))) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  const { results } = await env.DB.prepare(
    'SELECT id, name, status, created_at FROM users ORDER BY created_at DESC'
  ).all();

  return Response.json({ users: results });
}
