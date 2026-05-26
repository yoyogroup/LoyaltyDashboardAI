// OTP generation + verification.
//
// - 6-digit code from crypto.randomInt (uniform; not Math.random).
// - Stored as scrypt hash with per-record salt (zero crypto deps).
// - 10-minute TTL (DynamoDB auto-deletes via ttl attribute).
// - Max 5 verify attempts before the record is invalidated.
import { randomInt, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export const OTP_TTL_SECONDS = 10 * 60;     // 10 minutes
export const OTP_MAX_ATTEMPTS = 5;

export function generateOtp() {
  // 100000–999999 inclusive
  return String(randomInt(100000, 1000000));
}

// scrypt is built-in and resistant to GPU brute-forcing; for a 6-digit code
// in a 10-minute window with 5 attempts, this is more than adequate.
const SCRYPT_KEYLEN = 32;
const SCRYPT_N = 16384;   // 2^14 — fast on Lambda but still costly to brute
const SCRYPT_r = 8;
const SCRYPT_p = 1;

export function hashOtp(code) {
  const salt = randomBytes(16);
  const hash = scryptSync(code, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p });
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}

export function verifyOtp(code, saltB64, hashB64) {
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(String(code), salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p });
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
