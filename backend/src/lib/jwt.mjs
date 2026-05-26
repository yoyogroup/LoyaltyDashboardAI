// Minimal HS256 JWT — zero npm deps, uses only node's built-in crypto.
// We deliberately avoid a JWT library so the supply chain is tiny.
import { createHmac, timingSafeEqual } from 'node:crypto';

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlJson(obj) { return b64url(JSON.stringify(obj)); }
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

export function signJwt({ email, sessionDays }, secret) {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const nowSec  = Math.floor(Date.now() / 1000);
  const payload = {
    sub: email,
    email,
    iat: nowSec,
    exp: nowSec + (sessionDays * 24 * 60 * 60),
    iss: 'yoyo-loyalty-portal',
  };
  const headerB64  = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const data = headerB64 + '.' + payloadB64;
  const sig = createHmac('sha256', secret).update(data).digest();
  return data + '.' + b64url(sig);
}

// Server-side verification helper (for future authenticated endpoints).
// Returns the payload on success, throws on failure.
export function verifyJwt(jwt, secret) {
  if (typeof jwt !== 'string') throw new Error('jwt-not-string');
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('jwt-malformed');
  const [headerB64, payloadB64, sigB64] = parts;
  const expected = createHmac('sha256', secret).update(headerB64 + '.' + payloadB64).digest();
  const actual = b64urlDecode(sigB64);
  if (actual.length !== expected.length) throw new Error('jwt-bad-sig');
  if (!timingSafeEqual(actual, expected)) throw new Error('jwt-bad-sig');
  const payload = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
  if (typeof payload.exp !== 'number') throw new Error('jwt-no-exp');
  if (payload.exp <= Math.floor(Date.now() / 1000)) throw new Error('jwt-expired');
  return payload;
}
