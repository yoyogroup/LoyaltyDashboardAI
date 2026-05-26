// Thin client for the Resend API. We use fetch (built into Node 20) so
// there's no extra npm dependency.
//
// Docs: https://resend.com/docs/api-reference/emails/send-email

export async function sendOtpEmail({ apiKey, from, to, code }) {
  const minutes = 10;
  const subject = 'Your Yoyo Loyalty Portal sign-in code';

  const text = [
    'Your one-time sign-in code:',
    '',
    `    ${code}`,
    '',
    `This code expires in ${minutes} minutes. If you didn't request it, you can ignore this email.`,
    '',
    '— Yoyo',
  ].join('\n');

  // Lightweight HTML — no remote assets so it renders the same everywhere
  // and never makes the recipient's client phone home.
  const html = `<!DOCTYPE html>
<html><body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,sans-serif;background:#F5F5F7;padding:32px;color:#1D1D1F">
  <div style="max-width:480px;margin:0 auto;background:white;border-radius:16px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.05)">
    <div style="font-size:11px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:18px">Yoyo · Merchant Portal</div>
    <h1 style="font-size:22px;margin:0 0 12px;font-weight:800;letter-spacing:-0.02em">Your sign-in code</h1>
    <p style="font-size:14px;line-height:1.5;color:#475569;margin:0 0 24px">Enter this code in the portal to finish signing in. It expires in ${minutes} minutes.</p>
    <div style="background:#F5F5F7;border-radius:12px;padding:18px;text-align:center;font-size:28px;font-weight:800;letter-spacing:10px;color:#1D1D1F">${code}</div>
    <p style="font-size:12px;color:#94A3B8;margin:24px 0 0;line-height:1.5">Didn't request this? You can safely ignore the email — no one can sign in without the code.</p>
  </div>
</body></html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to: [to], subject, text, html }),
  });

  if (!res.ok) {
    // Don't include the email body in the error — keep it short
    const errText = await res.text().catch(() => '');
    throw new Error(`resend-failed status=${res.status} body=${errText.slice(0,200)}`);
  }
  return await res.json();
}
