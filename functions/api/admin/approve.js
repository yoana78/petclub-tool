import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  if (!(await requireAdmin(request, env))) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  const { id } = await request.json().catch(() => ({}));
  if (!id) {
    return Response.json({ error: 'invalid id' }, { status: 400 });
  }

  await env.DB.prepare("UPDATE users SET status = 'approved' WHERE id = ?").bind(id).run();
  return Response.json({ ok: true });
}
