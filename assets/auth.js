// ═══════════════════════════════════════════════════════════════════
// Yoyo Loyalty Portal — client-side auth helpers
// ═══════════════════════════════════════════════════════════════════
// Responsibilities:
//   - Hold the session JWT in localStorage (key: yoyo_session)
//   - Parse JWT exp client-side so we can redirect to login *before*
//     making an authenticated API call (the server still validates)
//   - Provide guardSession() — call early in every protected page
//   - Provide logout() — clears the token and bounces to /login.html
//
// Security notes:
//   - JWT signature is NOT verified client-side (we don't ship the secret).
//     Authoritative verification happens server-side on every API call.
//   - localStorage is fine here because: (1) CSP locks script origins,
//     (2) every DOM render uses textContent/createElement (no XSS sink),
//     (3) tokens are short-lived (30 days) and revocable server-side.
//   - When the site moves to a yoyogroup.com subdomain, switch to
//     HttpOnly+Secure+SameSite=Lax cookies (see backend/README.md).
// ═══════════════════════════════════════════════════════════════════

(function () {
  const STORAGE_KEY = 'yoyo_session';
  const cfg = window.YOYO_CONFIG;

  function getToken() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (_) { return null; }
  }

  function setToken(jwt) {
    try { localStorage.setItem(STORAGE_KEY, jwt); } catch (_) {}
  }

  function clearToken() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
  }

  // Base64url decode without using atob shortcuts that fail on padding.
  function b64urlDecode(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return atob(s);
  }

  function parseJwt(jwt) {
    if (!jwt || typeof jwt !== 'string') return null;
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    try {
      const payload = JSON.parse(b64urlDecode(parts[1]));
      return payload;
    } catch (_) {
      return null;
    }
  }

  // Returns the parsed payload if the JWT is structurally valid AND not
  // expired. Does NOT verify the signature — that's a server concern.
  function getValidPayload() {
    const jwt = getToken();
    const payload = parseJwt(jwt);
    if (!payload) return null;
    if (typeof payload.exp !== 'number') return null;
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSec) {
      clearToken(); // proactive cleanup of expired tokens
      return null;
    }
    if (!payload.email || typeof payload.email !== 'string') return null;
    return payload;
  }

  // Called by protected pages on load. If auth is enabled and there's no
  // valid session, bounce to login. Returns the payload on success.
  function guardSession() {
    if (!cfg || !cfg.AUTH_ENABLED) {
      // Auth disabled — show a small dev banner so this isn't forgotten
      // before going live with sensitive data.
      showDevBanner();
      return { email: 'dev@local', dev: true };
    }
    const payload = getValidPayload();
    if (!payload) {
      // Preserve the original URL so we can bounce back after login.
      const next = encodeURIComponent(location.pathname + location.search);
      location.replace('login.html?next=' + next);
      return null;
    }
    return payload;
  }

  function logout() {
    clearToken();
    location.replace('login.html');
  }

  // Build the auth banner DOM-safely (no innerHTML).
  // guardSession() typically runs in <head> before <body> exists, so we
  // defer the DOM mutation to DOMContentLoaded.
  function showDevBanner() {
    const mount = () => {
      if (!document.body || document.getElementById('yoyo-dev-banner')) return;
      const bar = document.createElement('div');
      bar.id = 'yoyo-dev-banner';
      bar.setAttribute('role', 'status');
      Object.assign(bar.style, {
        position: 'fixed', top: '0', left: '0', right: '0',
        background: '#FEF3C7', color: '#92400E', fontSize: '12px',
        fontWeight: '600', padding: '6px 14px', textAlign: 'center',
        zIndex: '9999', letterSpacing: '0.02em',
        borderBottom: '1px solid #F59E0B',
      });
      bar.textContent = 'AUTH DISABLED · dummy data only · flip YOYO_CONFIG.AUTH_ENABLED to true once AWS stack is live';
      document.body.appendChild(bar);
      // Push page down a touch so the banner doesn't overlap content.
      document.body.style.paddingTop = '26px';
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', mount, { once: true });
    } else {
      mount();
    }
  }

  // Tiny helper for authenticated fetches (used later by data endpoints).
  async function authFetch(path, init = {}) {
    const token = getToken();
    const headers = new Headers(init.headers || {});
    if (token) headers.set('Authorization', 'Bearer ' + token);
    headers.set('Content-Type', 'application/json');
    const res = await fetch(cfg.apiBase + path, { ...init, headers });
    if (res.status === 401) {
      clearToken();
      location.replace('login.html');
      throw new Error('session expired');
    }
    return res;
  }

  // Public API
  window.YoyoAuth = Object.freeze({
    guardSession,
    logout,
    getValidPayload,
    setToken,
    clearToken,
    authFetch,
  });
})();
