import { UserPermissionRole } from "@calcom/prisma/enums";
import { describe, expect, it } from "vitest";

import { resolveUserRole } from "./finngoSupabaseProvider";

/**
 * resolveUserRole — the admin-by-construction mapping (app_metadata.role → cal.diy role).
 *
 * Pure-function unit tests: they prove the FAIL-CLOSED contract — ONLY the exact string
 * "admin" from the issuer-controlled app_metadata maps to ADMIN; every other shape is USER.
 * (The provider passes `payload.app_metadata` here and NEVER `user_metadata` — user_metadata
 * is user-editable via Supabase updateUser, so trusting it would be privilege escalation;
 * that caller-side guarantee is visible in verifyFinngoSupabaseToken.)
 */
describe("finngoSupabaseProvider resolveUserRole", () => {
  it("app_metadata.role === 'admin' → ADMIN (the one and only elevation)", () => {
    expect(resolveUserRole({ role: "admin", staff: true })).toBe(UserPermissionRole.ADMIN);
  });

  it("non-admin staff role → USER", () => {
    expect(resolveUserRole({ role: "manager", staff: true })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: "user", staff: true })).toBe(UserPermissionRole.USER);
  });

  it("missing role / missing app_metadata → USER (fail-closed)", () => {
    expect(resolveUserRole({ staff: true })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({})).toBe(UserPermissionRole.USER);
    expect(resolveUserRole(undefined)).toBe(UserPermissionRole.USER);
    expect(resolveUserRole(null)).toBe(UserPermissionRole.USER);
  });

  it("wrong case / whitespace is NOT admin (strict string equality)", () => {
    expect(resolveUserRole({ role: "Admin" })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: "ADMIN" })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: " admin" })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: "admin " })).toBe(UserPermissionRole.USER);
  });

  it("non-string truthy values are NOT admin (no coercion)", () => {
    expect(resolveUserRole({ role: true })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: 1 })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: ["admin"] })).toBe(UserPermissionRole.USER);
    expect(resolveUserRole({ role: { role: "admin" } })).toBe(UserPermissionRole.USER);
  });

  it("a user_metadata-shaped object grants nothing (defense-in-depth: even if miswired, no elevation via display fields)", () => {
    expect(resolveUserRole({ legacy_username: "admin", full_name: "admin" })).toBe(UserPermissionRole.USER);
  });
});
