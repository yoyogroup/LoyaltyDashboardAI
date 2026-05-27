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
  // HELD AT false: backend is deployed, but /auth/request-otp is currently
  // returning 500 (OTP email send failing — see backend logs). Flip to true
  // ONLY once request-otp returns 200, otherwise the portal locks everyone out.
  AUTH_ENABLED: false,

  // Live API Gateway base URL (SAM stack: yoyo-loyalty-portal, eu-west-1).
  apiBase: 'https://7ghddg7uji.execute-api.eu-west-1.amazonaws.com',

  // Allowed email domains. Server-side enforces the same list authoritatively;
  // this is purely for client-side UX (early validation hint).
  allowedDomains: Object.freeze(['yoyogroup.com', 'yoyorewards.com']),

  // Session length matches what the server signs into the JWT.
  // Purely informational on the client; the JWT `exp` claim is the source of truth.
  sessionDays: 30,
});
