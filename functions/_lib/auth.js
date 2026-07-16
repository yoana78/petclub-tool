function bytesToB64url(bytes) {
  let binary = '';
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function textToB64url(str) {
  return bytesToB64url(new TextEncoder().encode(str));
}

function b64urlToText(str) {
  return new TextDecoder().decode(b64urlToBytes(str));
}

async function hmac(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return bytesToB64url(new Uint8Array(sig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function hashPin(pin) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(pin));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function signToken(payload, secret) {
  const body = textToB64url(JSON.stringify(payload));
  const sig = await hmac(secret, body);
  return `${body}.${sig}`;
}

export async function verifyToken(token, secret) {
  if (!token) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = await hmac(secret, body);
  if (!timingSafeEqual(expected, sig)) return null;
  try {
    const payload = JSON.parse(b64urlToText(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function cookieHeader(name, value, maxAgeSeconds) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax'];
  parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join('; ');
}

export async function requireAdmin(request, env) {
  const token = getCookie(request, 'admin_session');
  const payload = await verifyToken(token, env.SESSION_SECRET);
  return !!(payload && payload.admin);
}
