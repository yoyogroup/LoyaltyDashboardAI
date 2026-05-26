// ═══════════════════════════════════════════════════════════════════
// Yoyo Loyalty Portal — runtime config
// ═══════════════════════════════════════════════════════════════════
// IMPORTANT: This file contains NO secrets. The Resend API key and JWT
// signing key live ONLY in AWS Secrets Manager — never in the browser.
//
// AUTH_ENABLED flag:
//   - false (default): portal is open, dummy-data only. Use during pre-launch.
//   - true: hard auth wall. Flip ONLY after the AWS SAM stack is deployed
//          AND `apiBase` below points to your live API Gateway URL.
// ═══════════════════════════════════════════════════════════════════

window.YOYO_CONFIG = Object.freeze({
  // Master switch for the auth wall.
  // Keep false until the backend stack is live, then flip to true and redeploy.
  AUTH_ENABLED: false,

  // API Gateway base URL — replace after `sam deploy`.
  // Format: https://{api-id}.execute-api.{region}.amazonaws.com
  apiBase: 'https://REPLACE-WITH-API-GATEWAY-URL.execute-api.eu-west-1.amazonaws.com',

  // Allowed email domains. Server-side enforces the same list authoritatively;
  // this is purely for client-side UX (early validation hint).
  allowedDomains: Object.freeze(['yoyogroup.com', 'yoyorewards.com']),

  // Session length matches what the server signs into the JWT.
  // Purely informational on the client; the JWT `exp` claim is the source of truth.
  sessionDays: 30,
});
