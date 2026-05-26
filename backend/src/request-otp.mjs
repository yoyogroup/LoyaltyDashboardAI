// POST /auth/request-otp
// Body: { email: string }
// 200 → { ok: true } (always — never leak whether email is recognised)
// 400 → malformed input
// 429 → rate limited (1 OTP per 60 seconds per email)
// 500 → unexpected error
//
// Security posture:
//   - Email is validated, lowercased, length-capped.
//   - Domain must match ALLOWED_DOMAINS env (yoyogroup.com / yoyorewards.com).
//   - OTP is hashed (scrypt) before storage. Plaintext lives only in memory + the email itself.
//   - DynamoDB record has a 10-min TTL — auto-deleted by DynamoDB after expiry.
//   - Rate-limited via a second DynamoDB table (TTL = 60s).
//   - For domain-allowed but not-in-allowlist callers: same 200 response (timing-safe-ish).

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { normalise, isAllowedDomain, emailHash } from './lib/email.mjs';
import { generateOtp, hashOtp, OTP_TTL_SECONDS } from './lib/otp.mjs';
import { getSecret } from './lib/secrets.mjs';
import { sendOtpEmail } from './lib/resend.mjs';
import { json, parseBody, audit } from './lib/http.mjs';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const RATE_WINDOW_SECONDS = 60;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://yoyogroup.github.io';

export const handler = async (event) => {
  const origin = ALLOWED_ORIGIN;
  try {
    const body = parseBody(event);
    if (body === null) return json(400, { error: 'bad-json' }, origin);

    const email = normalise(body?.email);
    if (!email) {
      audit(event, { evt: 'otp.request.bad-email' });
      return json(400, { error: 'bad-email' }, origin);
    }

    const hash = emailHash(email);

    // — Disallowed domain: respond 200 to avoid leaking which domains we accept.
    // We DO NOT send an email or store an OTP. Logged for audit.
    if (!isAllowedDomain(email)) {
      audit(event, { evt: 'otp.request.domain-blocked', email_hash: hash });
      return json(200, { ok: true }, origin);
    }

    // — Rate limit: 1 OTP per email per 60 seconds —
    const rateKey = 'otp:' + hash;
    const existing = await ddb.send(new GetCommand({
      TableName: process.env.RATE_TABLE,
      Key: { key: rateKey },
    }));
    if (existing.Item && existing.Item.ttl > Math.floor(Date.now() / 1000)) {
      audit(event, { evt: 'otp.request.rate-limited', email_hash: hash });
      return json(429, { error: 'rate-limited' }, origin);
    }

    // — Generate + store OTP —
    const code = generateOtp();
    const { salt, hash: codeHash } = hashOtp(code);
    const nowSec = Math.floor(Date.now() / 1000);

    await ddb.send(new PutCommand({
      TableName: process.env.OTP_TABLE,
      Item: {
        email_hash: hash,
        salt,
        code_hash: codeHash,
        attempts: 0,
        created_at: nowSec,
        ttl: nowSec + OTP_TTL_SECONDS,
      },
    }));

    // — Set rate-limit marker —
    await ddb.send(new PutCommand({
      TableName: process.env.RATE_TABLE,
      Item: {
        key: rateKey,
        ttl: nowSec + RATE_WINDOW_SECONDS,
      },
    }));

    // — Send the email —
    const apiKey = await getSecret(process.env.RESEND_SECRET_ARN);
    await sendOtpEmail({
      apiKey,
      from: process.env.RESEND_FROM,
      to: email,
      code,
    });

    audit(event, { evt: 'otp.request.sent', email_hash: hash });
    return json(200, { ok: true }, origin);
  } catch (err) {
    // Never leak the error to the client — log it server-side.
    audit(event, { evt: 'otp.request.error', err: String(err?.message || err) });
    return json(500, { error: 'server-error' }, origin);
  }
};
