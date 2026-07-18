-- Finngo Supabase SSO: add the SUPABASE identity provider so cal.diy Users provisioned
-- from a Finngo Supabase login can be keyed on the immutable Supabase `sub`
-- (User.identityProviderId), never on email.
ALTER TYPE "IdentityProvider" ADD VALUE IF NOT EXISTS 'SUPABASE';
