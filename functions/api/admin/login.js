import { signToken, cookieHeader } from '../../_lib/auth.js';

const ADMIN_SESSION_MAX_AGE = 60 * 60 * 8; // 8 hours

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const password = typeof body.password === 'string' ? body.password : '';

  if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) {
    return Response.json({ error: '비밀번호가 올바르지 않습니다.' }, { status: 401 });
  }

  const token = await signToken(
    { admin: true, exp: Date.now() + ADMIN_SESSION_MAX_AGE * 1000 },
    env.SESSION_SECRET
  );

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': cookieHeader('admin_session', token, ADMIN_SESSION_MAX_AGE),
    },
  });
}
