import CredentialsProvider from "next-auth/providers/credentials";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { DEFAULT_SCHEDULE, getAvailabilityFromSchedule } from "@calcom/lib/availability";
import prisma from "@calcom/prisma";
import { IdentityProvider } from "@calcom/prisma/enums";

/**
 * Finngo Supabase SSO bridge.
 *
 * Verifies a Finngo **Supabase ES256** access token against the Finngo project's JWKS
 * (fail-closed: ES256 pinned, aud enforced, exp required, `app_metadata.staff===true`
 * required — the same bar hardened in Finngo's supabaseAuthService), then find-or-provisions
 * the cal.diy User keyed on the **IMMUTABLE Supabase `sub`** (stored in identityProviderId),
 * NEVER email — so a reused/changed email can never take over an account.
 *
 * Used by the finngo-sso landing route: Tools opens it in a new tab, it hands the Supabase
 * token to this provider, the user lands authed. No second login.
 */

// createRemoteJWKSet handles fetch + cache + kid selection + key rotation. Memoized so we
// read SUPABASE_URL at first use (not import time) and reuse one keyset across invocations.
let _jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function getJwks() {
  if (_jwks) return _jwks;
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL not set — cannot verify Finngo Supabase tokens");
  _jwks = createRemoteJWKSet(new URL(`${base.replace(/\/+$/, "")}/auth/v1/.well-known/jwks.json`));
  return _jwks;
}

interface FinngoIdentity {
  sub: string;
  email: string;
  name?: string;
}

async function verifyFinngoSupabaseToken(token: string): Promise<FinngoIdentity> {
  // jwtVerify with algorithms:["ES256"] rejects HS256 / alg:none (alg-confusion) at the
  // signature layer; audience enforces aud; the keyset selects the signing key by kid.
  const { payload } = await jwtVerify(token, getJwks(), {
    algorithms: ["ES256"],
    audience: process.env.SUPABASE_JWT_AUD ?? "authenticated",
  });
  // jose does NOT require exp to be PRESENT (a token with no exp passes) — require it explicitly.
  if (typeof payload.exp !== "number") throw new Error("Finngo token missing exp");
  // STAFF gate — strict === true (a truthy string / missing claim must not pass).
  const appMeta = (payload.app_metadata ?? {}) as { staff?: unknown };
  if (appMeta.staff !== true) throw new Error("Finngo token is not staff");
  const sub = String(payload.sub ?? "").trim();
  if (!sub) throw new Error("Finngo token missing sub");
  const userMeta = (payload.user_metadata ?? {}) as { full_name?: string };
  const email = String((payload as { email?: string }).email ?? "").trim().toLowerCase();
  return { sub, email, name: userMeta.full_name };
}

async function findOrProvisionUser(id: FinngoIdentity) {
  // 1. Primary key = the immutable Supabase sub (takeover-safe). Email is NEVER the match key.
  const existing = await prisma.user.findFirst({
    where: { identityProvider: IdentityProvider.SUPABASE, identityProviderId: id.sub },
  });
  if (existing) return existing;

  // 2. No sub match → provision. If the email is already taken by a row NOT bound to this sub,
  //    do NOT claim it (would be an email-based takeover) — provision a distinct Finngo-owned
  //    identity under a namespaced email and let admins reconcile. (email = display only.)
  const emailTaken = id.email
    ? await prisma.user.findFirst({ where: { email: id.email }, select: { id: true } })
    : null;
  const email = emailTaken || !id.email ? `finngo+${id.sub}@sso.finngo.local` : id.email;

  return prisma.user.create({
    data: {
      email,
      name: id.name ?? null,
      username: `finngo-${id.sub.slice(0, 8)}`,
      identityProvider: IdentityProvider.SUPABASE,
      identityProviderId: id.sub, // ← the immutable binding
      emailVerified: new Date(),
      completedOnboarding: true,
      // no password: this is an external federated identity.
    },
  });
}

/**
 * Self-heal-on-login: SSO-provisioned users skip cal.com's onboarding, which is where the
 * default availability Schedule is normally created — leaving defaultScheduleId null and the
 * availability UI non-functional. On every login, idempotently top up a missing default
 * schedule using cal.com's own canonical shape (mirrors the availability create.handler:
 * DEFAULT_SCHEDULE Mon-Fri 9-17 + user's timeZone). Also repairs any past partial provision.
 */
async function ensureDefaultSchedule(user: { id: number; timeZone: string | null; defaultScheduleId: number | null }) {
  if (user.defaultScheduleId != null) return;
  const availability = getAvailabilityFromSchedule(DEFAULT_SCHEDULE);
  const schedule = await prisma.schedule.create({
    data: {
      name: "Working Hours",
      user: { connect: { id: user.id } },
      timeZone: user.timeZone ?? undefined,
      availability: {
        createMany: {
          data: availability.map((a) => ({ days: a.days, startTime: a.startTime, endTime: a.endTime })),
        },
      },
    },
  });
  await prisma.user.update({ where: { id: user.id }, data: { defaultScheduleId: schedule.id } });
}

async function authorizeFinngoSupabase(
  credentials: Record<"supabaseToken", string> | undefined
): Promise<{ id: number; email: string; name: string | null; username: string | null } | null> {
  const token = credentials?.supabaseToken;
  if (!token) return null;
  // Any throw here → NextAuth denies the sign-in (fail-closed).
  const identity = await verifyFinngoSupabaseToken(token);
  const user = await findOrProvisionUser(identity);
  if (user.locked) throw new Error("UserAccountLocked");
  await ensureDefaultSchedule(user);
  return { id: user.id, email: user.email, name: user.name, username: user.username };
}

export const FinngoSupabaseProvider = CredentialsProvider({
  id: "finngo-supabase",
  name: "Finngo",
  type: "credentials",
  credentials: {
    supabaseToken: { label: "Finngo session", type: "text" },
  },
  authorize: authorizeFinngoSupabase,
});
