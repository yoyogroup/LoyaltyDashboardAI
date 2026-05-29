// POST /channels/whatsapp/create
// Body: (none required — label is derived server-side from the JWT)
// 200 → { ok:true, onboarding_url, expires_at, channel_label }
// 401 → missing/invalid session JWT
// 502 → nineteen58 API failed
//
// Security posture:
//   - Requires a valid session JWT (only signed-in merchants can mint links).
//   - The nineteen58 x-api-key lives ONLY in Secrets Manager — never in the
//     browser, never in repo. Lambda reads it at invoke time (cached 5 min).
//   - The channel_label is derived from the JWT claim, NOT from request body.
//     Clients cannot label a channel as someone else's brand.
//   - Server-to-server call avoids browser CORS limits entirely.
//   - We only return onboarding_url + expires_at to the browser — every other
//     field from nineteen58 (ids, tokens, internal state) stays server-side.
import { verifyJwt } from './lib/jwt.mjs';
import { getSecret } from './lib/secrets.mjs';
import { json, audit } from './lib/http.mjs';

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://yoyogroup.github.io';
const NINETEEN58_ENDPOINT = process.env.NINETEEN58_ENDPOINT
  || 'https://app.nineteen58.dev/api/v1/whatsapp/onboarding-links';
const LINK_EXPIRY_HOURS = Number(process.env.WHATSAPP_LINK_EXPIRY_HOURS || 24);

// Title-case the email's local part as a fallback channel label.
// e.g. "bevan.smith@yoyogroup.com" → "Bevan Smith WhatsApp Channel"
// TODO: once the store-selector context lands in the JWT, prefer storeName
//       here so labels read e.g. "Treat Café WhatsApp Channel".
function deriveLabel(session) {
  const email = String(session?.email || '').toLowerCase();
  const local = email.split('@')[0] || 'merchant';
  const pretty = local
    .replace(/[._-]+/g, ' ')
    .replace(/\b(\w)/g, (_, c) => c.toUpperCase())
    .trim();
  return `${pretty || 'Merchant'} WhatsApp Channel`;
}

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

    const channelLabel = deriveLabel(session);

    // ── Call nineteen58 server-to-server ──
    const apiKey = await getSecret(process.env.NINETEEN58_SECRET_ARN);
    const upstream = await fetch(NINETEEN58_ENDPOINT, {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        channel_label: channelLabel,
        expires_in_hours: LINK_EXPIRY_HOURS,
      }),
    });

    if (!upstream.ok) {
      const text = await upstream.text().catch(() => '');
      audit(event, {
        evt: 'whatsapp.create.upstream_error',
        status: upstream.status,
        // truncate to avoid logging anything sensitive in full
        snippet: text.slice(0, 300),
      });
      return json(502, { error: 'upstream-failed' }, origin);
    }

    const data = await upstream.json().catch(() => ({}));

    // nineteen58's response shape isn't documented in the brief — accept the
    // common field names and pick whichever is present. If we get nothing
    // usable, treat it as a 502 rather than leak a half-broken response.
    const onboardingUrl =
      data.onboarding_url || data.url || data.link || data.onboardingUrl || null;
    const expiresAt =
      data.expires_at || data.expiresAt || data.expiry || null;

    if (!onboardingUrl) {
      audit(event, { evt: 'whatsapp.create.no_url', keys: Object.keys(data || {}) });
      return json(502, { error: 'no-onboarding-url' }, origin);
    }

    audit(event, {
      evt: 'whatsapp.create.ok',
      by: session.email,
      channel_label: channelLabel,
    });

    return json(200, {
      ok: true,
      onboarding_url: onboardingUrl,
      expires_at: expiresAt,
      channel_label: channelLabel,
    }, origin);
  } catch (err) {
    audit(event, { evt: 'whatsapp.create.error', err: String(err?.message || err) });
    return json(502, { error: 'create-channel-failed' }, origin);
  }
};
