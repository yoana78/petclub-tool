import { hashPin } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const pin = typeof body.pin === 'string' ? body.pin : '';

  if (!name || name.length > 30) {
    return Response.json({ error: '이름을 올바르게 입력해주세요.' }, { status: 400 });
  }
  if (!/^\d{4}$/.test(pin)) {
    return Response.json({ error: '비밀번호는 숫자 4자리로 입력해주세요.' }, { status: 400 });
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE name = ?').bind(name).first();
  if (existing) {
    return Response.json({ error: '이미 등록된 이름입니다.' }, { status: 409 });
  }

  const pinHash = await hashPin(pin);
  await env.DB.prepare('INSERT INTO users (name, pin, status) VALUES (?, ?, ?)')
    .bind(name, pinHash, 'pending')
    .run();

  return Response.json({ ok: true });
}
