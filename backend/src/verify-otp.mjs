// POST /auth/verify-otp
// Body: { email: string, code: string }
// 200 → { token: <JWT> }  (30-day session)
// 400 → bad input
// 401 → invalid / expired / too many attempts
// 500 → unexpected error
//
// Security posture:
//   - Constant-time OTP comparison (scrypt + timingSafeEqual).
//   - Attempt counter incremented on every wrong code; ≥ OTP_MAX_ATTEMPTS deletes the record.
//   - On success the record is deleted (codes are single-use).
//   - JWT signing key is fetched from Secrets Manager, cached for 5 min.

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { normalise, isAllowedDomain, emailHash } from './lib/email.mjs';
import { verifyOtp, OTP_MAX_ATTEMPTS } from './lib/otp.mjs';
import { signJwt } from './lib/jwt.mjs';
import { getSecret } from './lib/secrets.mjs';
import { json, parseBody, audit } from './lib/http.mjs';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://yoyogroup.github.io';
const SESSION_DAYS = Number(process.env.SESSION_DAYS || '30');

export const handler = async (event) => {
  const origin = ALLOWED_ORIGIN;
  try {
    const body = parseBody(event);
    if (body === null) return json(400, { error: 'bad-json' }, origin);

    const email = normalise(body?.email);
    const code  = typeof body?.code === 'string' ? body.code.trim() : '';

    if (!email || !/^\d{6}$/.test(code)) {
      audit(event, { evt: 'otp.verify.bad-input' });
      return json(400, { error: 'bad-input' }, origin);
    }
    if (!isAllowedDomain(email)) {
      audit(event, { evt: 'otp.verify.domain-blocked', email_hash: emailHash(email) });
      return json(401, { error: 'invalid' }, origin);
    }

    const hash = emailHash(email);

    const got = await ddb.send(new GetCommand({
      TableName: process.env.OTP_TABLE,
      Key: { email_hash: hash },
    }));
    const rec = got.Item;
    if (!rec) {
      audit(event, { evt: 'otp.verify.no-record', email_hash: hash });
      return json(401, { error: 'invalid' }, origin);
    }
    if (rec.ttl <= Math.floor(Date.now() / 1000)) {
      // Defensive — DynamoDB TTL has up to 48h sweep latency
      await ddb.send(new DeleteCommand({ TableName: process.env.OTP_TABLE, Key: { email_hash: hash } }));
      audit(event, { evt: 'otp.verify.expired', email_hash: hash });
      return json(401, { error: 'invalid' }, origin);
    }
    if ((rec.attempts || 0) >= OTP_MAX_ATTEMPTS) {
      await ddb.send(new DeleteCommand({ TableName: process.env.OTP_TABLE, Key: { email_hash: hash } }));
      audit(event, { evt: 'otp.verify.lockout', email_hash: hash });
      return json(401, { error: 'invalid' }, origin);
    }

    const ok = verifyOtp(code, rec.salt, rec.code_hash);
    if (!ok) {
      // Bump attempt counter — burns one of the 5 allowed tries.
      await ddb.send(new UpdateCommand({
        TableName: process.env.OTP_TABLE,
        Key: { email_hash: hash },
        UpdateExpression: 'SET attempts = if_not_exists(attempts, :z) + :one',
        ExpressionAttributeValues: { ':z': 0, ':one': 1 },
      }));
      audit(event, { evt: 'otp.verify.wrong-code', email_hash: hash });
      return json(401, { error: 'invalid' }, origin);
    }

    // — Success. Codes are single-use — delete the record. —
    await ddb.send(new DeleteCommand({ TableName: process.env.OTP_TABLE, Key: { email_hash: hash } }));

    const jwtSecret = await getSecret(process.env.JWT_SECRET_ARN);
    const token = signJwt({ email, sessionDays: SESSION_DAYS }, jwtSecret);

    audit(event, { evt: 'otp.verify.success', email_hash: hash, session_days: SESSION_DAYS });
    return json(200, { token, expires_in_days: SESSION_DAYS }, origin);
  } catch (err) {
    audit(event, { evt: 'otp.verify.error', err: String(err?.message || err) });
    return json(500, { error: 'server-error' }, origin);
  }
};
