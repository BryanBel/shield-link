-- Shield Link — reputation store
--
-- Run this against the database named in DATABASE_URL. It is idempotent: safe on a fresh
-- database and safe to re-run on an existing one without losing rows.
--
-- A NOTE ON ACCESS CONTROL, because this file used to carry the opposite.
--
-- On Supabase these two tables were reachable from the browser through PostgREST with a
-- public anonymous key, so they needed row-level security to be safe -- and an early
-- version shipped `FOR ALL USING (true)`, which granted select, insert, update and delete
-- to every caller. Anyone could insert a malicious URL into lista_blanca and have Shield
-- Link vouch for it.
--
-- The database now sits behind a connection string that only the server holds. There is
-- no anonymous role and no HTTP interface in front of it, so there is nothing for a
-- policy to defend against: RLS here would be theatre rather than protection. What keeps
-- these tables safe is that /api/scan is the only code that can reach them, and the
-- browser bundle contains no credential -- verifiable with `grep -r neon dist/client`
-- after a build.

CREATE TABLE IF NOT EXISTS lista_blanca (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_segura     TEXT UNIQUE NOT NULL,
    fecha_analisis TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lista_negra (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_maliciosa  TEXT UNIQUE NOT NULL,
    motivo         TEXT NOT NULL,
    fecha_reporte  TIMESTAMPTZ NOT NULL DEFAULT now()
);
