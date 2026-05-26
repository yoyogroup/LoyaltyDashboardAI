// Tiny cached fetcher for Secrets Manager. Lambda reuses warm containers,
// so we cache the value to avoid hitting SM on every invocation (cost + latency).
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const sm = new SecretsManagerClient({});
const cache = new Map(); // arn -> { value, expiresAt }
const TTL_MS = 5 * 60 * 1000; // 5 min — short enough to pick up rotation soon

export async function getSecret(arn) {
  const now = Date.now();
  const hit = cache.get(arn);
  if (hit && hit.expiresAt > now) return hit.value;

  const out = await sm.send(new GetSecretValueCommand({ SecretId: arn }));
  const value = out.SecretString;
  if (!value) throw new Error('secret has no SecretString: ' + arn);
  cache.set(arn, { value, expiresAt: now + TTL_MS });
  return value;
}
