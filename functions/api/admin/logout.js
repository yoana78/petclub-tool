import { cookieHeader } from '../../_lib/auth.js';

export async function onRequestPost() {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': cookieHeader('admin_session', '', 0),
    },
  });
}
