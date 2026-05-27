// Thin server-side client for Yoyo's SMS integration service.
// Uses fetch (built into Node 20) — no extra npm dependency.
export async function sendSms({ endpoint, apiKey, mobile, text, reference }) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'apiKey': apiKey },
    body: JSON.stringify({ mobile, text, reference }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`sms-service status=${res.status} body=${body.slice(0, 200)}`);
  }
  return res.json().catch(() => ({}));
}
