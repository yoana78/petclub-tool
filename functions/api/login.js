import { hashPin, signToken, cookieHeader } from '../_lib/auth.js';

const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const pin = typeof body.pin === 'string' ? body.pin : '';

  if (!name || !/^\d{4}$/.test(pin)) {
    return Response.json({ error: '이름과 4자리 비밀번호를 입력해주세요.' }, { status: 400 });
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE name = ?').bind(name).first();
  if (!user) {
    return Response.json({ error: '가입되지 않은 이름입니다.' }, { status: 401 });
  }

  const pinHash = await hashPin(pin);
  if (pinHash !== user.pin) {
    return Response.json({ error: '비밀번호가 일치하지 않습니다.' }, { status: 401 });
  }
  if (user.status !== 'approved') {
    return Response.json({ error: '관리자 승인 대기 중입니다.' }, { status: 403 });
  }

  const token = await signToken(
    { id: user.id, name: user.name, exp: Date.now() + SESSION_MAX_AGE * 1000 },
    env.SESSION_SECRET
  );

  return new Response(JSON.stringify({ ok: true, name: user.name }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': cookieHeader('session', token, SESSION_MAX_AGE),
    },
  });
}
