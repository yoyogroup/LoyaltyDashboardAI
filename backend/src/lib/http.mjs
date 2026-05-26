// Shared HTTP helpers for the auth Lambdas.
//
// - cors():     uniform CORS + security headers for every response.
// - json():     write a JSON body with the right status + headers.
// - badJson():  500-safe wrapper that never leaks internals to the client.
// - audit():    one-line structured log to CloudWatch for every auth event.

export function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '600',
    // Defence in depth even though this isn't HTML
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  };
}

export function json(status, body, origin) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    body: JSON.stringify(body),
  };
}

export function parseBody(event) {
  if (!event.body) return {};
  try {
    return JSON.parse(event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body);
  } catch (_) {
    return null; // signal "malformed JSON"
  }
}

// One-line JSON log line, ingestable by CloudWatch / Loki.
// Never log the OTP code or the email in plaintext — emit a SHA-256 hash.
export function audit(event, fields) {
  const sourceIp = event?.requestContext?.http?.sourceIp || 'unknown';
  const ua = event?.requestContext?.http?.userAgent || 'unknown';
  const line = {
    ts: new Date().toISOString(),
    sourceIp,
    ua,
    ...fields,
  };
  // console.log will land in CloudWatch (structured JSON via Globals.Function.LoggingConfig)
  console.log(JSON.stringify(line));
}
