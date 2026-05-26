// Validate emails against the configured allow-list. The list comes from
// env (ALLOWED_DOMAINS, CSV) so it can be changed without redeploying code.
import { createHash } from 'node:crypto';

const RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalise(email) {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  if (!RE.test(trimmed)) return null;
  if (trimmed.length > 254) return null; // RFC 5321 cap
  return trimmed;
}

export function isAllowedDomain(email) {
  const allowed = (process.env.ALLOWED_DOMAINS || '')
    .split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1);
  return allowed.includes(domain);
}

// Stable, non-reversible hash of the email — used as the DynamoDB key
// so we never store the raw PII as the partition key.
export function emailHash(email) {
  return createHash('sha256').update(email).digest('hex');
}
