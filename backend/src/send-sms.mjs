// POST /campaigns/send-sms
// Body: { text: string, reference?: string }
// 200 → { ok:true, reference }
// 401 → missing/invalid session JWT
// 400 → bad input
// 502 → SMS service failed
//
// Security posture:
//   - Requires a valid session JWT (only signed-in merchants can dispatch).
//   - The SMS API key lives ONLY in Secrets Manager — never in the browser.
//   - Server-to-server call avoids browser CORS limits entirely.
//   - TEST PHASE: always sends to TEST_SMS_MOBILE (env). Swap to the real
//     audience list once we're ready to send to customers.
import { randomUUID } from 'node:crypto';
import { verifyJwt } from './lib/jwt.mjs';
import { getSecret } from './lib/secrets.mjs';
import { sendSms } from './lib/sms.mjs';
import { json, parseBody, audit } from './lib/http.mjs';

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://yoyogroup.github.io';

export const handler = async (event) => {
  const origin = ALLOWED_ORIGIN;
  try {
    // ── Require a valid session JWT ──
    const hdrs = event.headers || {};
    const authHeader = hdrs.authorization || hdrs.Authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return json(401, { error: 'unauthorized' }, origin);

    let session;
    try {
      const jwtSecret = await getSecret(process.env.JWT_SECRET_ARN);
      session = verifyJwt(token, jwtSecret);
    } catch (_) {
      return json(401, { error: 'unauthorized' }, origin);
    }

    // ── Validate input ──
    const body = parseBody(event);
    if (body === null) return json(400, { error: 'bad-json' }, origin);
    const text = typeof body?.text === 'string' ? body.text.trim() : '';
    if (!text) return json(400, { error: 'missing-text' }, origin);
    if (text.length > 1000) return json(400, { error: 'text-too-long' }, origin);

    const reference = (typeof body?.reference === 'string' && body.reference) || randomUUID();
    const mobile = process.env.TEST_SMS_MOBILE; // test phase: fixed recipient

    // ── Forward to the SMS service with the key from Secrets Manager ──
    const apiKey = await getSecret(process.env.SMS_SECRET_ARN);
    await sendSms({ endpoint: process.env.SMS_ENDPOINT, apiKey, mobile, text, reference });

    audit(event, { evt: 'sms.sent', by: session.email, reference });
    return json(200, { ok: true, reference }, origin);
  } catch (err) {
    audit(event, { evt: 'sms.error', err: String(err?.message || err) });
    return json(502, { error: 'sms-send-failed' }, origin);
  }
};
