// POST /data/query
// Body: { sql: string }
// 200 → { columns: string[], rows: any[][] }
// 401 → missing/invalid session JWT
// 400 → bad input (missing sql, too long, or write statement detected)
// 502 → Redshift query failed
//
// Security posture:
//   - Requires a valid session JWT (only signed-in users can query).
//   - Cross-account role assumption happens server-side — no credentials in the browser.
//   - Basic SQL validation rejects write operations (INSERT, UPDATE, DELETE, DROP, etc.).
//   - Query timeout prevents runaway statements.

import { verifyJwt } from './lib/jwt.mjs';
import { getSecret } from './lib/secrets.mjs';
import { queryRedshift } from './lib/redshift.mjs';
import { json, parseBody, audit } from './lib/http.mjs';

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://yoyogroup.github.io';
const MAX_SQL_LENGTH = 4000;

// Reject obvious write/DDL statements — not a security boundary, just a guardrail.
const WRITE_PATTERNS = /^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|COPY)\b/i;

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

    const sql = typeof body?.sql === 'string' ? body.sql.trim() : '';
    if (!sql) return json(400, { error: 'missing-sql' }, origin);
    if (sql.length > MAX_SQL_LENGTH) return json(400, { error: 'sql-too-long' }, origin);
    if (WRITE_PATTERNS.test(sql)) return json(400, { error: 'write-not-allowed' }, origin);

    // ── Execute query via cross-account Redshift Data API ──
    audit(event, { evt: 'redshift.query', by: session.email, sqlLength: sql.length });

    const result = await queryRedshift(sql, { timeoutMs: 25000 });

    audit(event, { evt: 'redshift.success', by: session.email, rowCount: result.rows.length });
    return json(200, result, origin);
  } catch (err) {
    audit(event, { evt: 'redshift.error', err: String(err?.message || err) });
    return json(502, { error: 'query-failed', message: err?.message || 'unknown error' }, origin);
  }
};
