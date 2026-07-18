import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

/**
 * Finngo SSO landing route.
 *
 * Tools opens `https://cal.finngo.com/api/auth/finngo-sso?token=<supabase_access_token>` in a
 * new tab (or POSTs the token). We hand the token to the `finngo-supabase` NextAuth Credentials
 * provider via an auto-submitting CSRF-bearing form → the provider verifies the Supabase token
 * and find-or-provisions the cal.diy User → the user lands authed. No second login.
 *
 * The Supabase token is short-lived and travels once over TLS; the NextAuth session cookie then
 * owns the cal.diy side. (v2 hardening: swap token-in-URL for a one-time nonce exchanged
 * server-to-server — see the integration runbook.)
 */

export const dynamic = "force-dynamic";

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

async function handle(token: string | null, origin: string) {
  if (!token) {
    return NextResponse.redirect(new URL("/auth/login", origin));
  }

  // Fetch a CSRF token from NextAuth (same origin) so the Credentials callback accepts the POST.
  const csrfRes = await fetch(new URL("/api/auth/csrf", origin), {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const { csrfToken } = (await csrfRes.json()) as { csrfToken: string };

  const action = new URL("/api/auth/callback/finngo-supabase", origin).toString();
  const callbackUrl = new URL("/", origin).toString();

  // Auto-submitting POST form → NextAuth Credentials callback → FinngoSupabaseProvider.authorize.
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Signing in…</title>
<meta name="robots" content="noindex"></head>
<body><form id="f" method="post" action="${escapeHtml(action)}">
<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}"/>
<input type="hidden" name="supabaseToken" value="${escapeHtml(token)}"/>
<input type="hidden" name="callbackUrl" value="${escapeHtml(callbackUrl)}"/>
</form><script>document.getElementById('f').submit()</script>
<noscript>Enable JavaScript to finish signing in to Finngo Scheduling.</noscript></body></html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate, private",
      "referrer-policy": "no-referrer",
    },
  });
}

export async function GET(req: NextRequest) {
  return handle(req.nextUrl.searchParams.get("token"), req.nextUrl.origin);
}

export async function POST(req: NextRequest) {
  const form = await req.formData().catch(() => null);
  const token = form?.get("token");
  return handle(typeof token === "string" ? token : null, req.nextUrl.origin);
}
