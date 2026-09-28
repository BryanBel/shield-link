-- Shield Link — reputation store
--
-- Run this as the database owner, not as the application role:
--
--     psql "$DATABASE_URL_ADMIN" -f schema.sql
--
-- It is idempotent: safe on a fresh database and safe to re-run on an existing one without
-- losing rows. It uses a DO block, so it needs a client that sends the file as-is, like
-- psql, rather than one that splits it on semicolons.
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
-- these tables safe is that only the server routes can reach them, and the
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

-- Per-IP budget for VirusTotal lookups. One row per client, scope ('minuto' or 'dia') and
-- window start; /api/scan increments it before every lookup and prunes rows older than
-- two days. See the comment on LIMITE_POR_MINUTO in src/pages/api/scan.js.
CREATE TABLE IF NOT EXISTS limite_peticiones (
    alcance  TEXT        NOT NULL,
    ip       TEXT        NOT NULL,
    ventana  TIMESTAMPTZ NOT NULL,
    conteo   INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (alcance, ip, ventana)
);

-- LEAST PRIVILEGE. The application connects as shieldlink_app, never as the owner. That
-- role can read and write rows in these tables and nothing else: it cannot create, alter
-- or drop tables, create roles or databases, or touch any other schema. A leaked
-- DATABASE_URL then costs the rows, not the database.
--
-- The role itself is created once, by hand, so its password never appears in this file:
--
--     CREATE ROLE shieldlink_app LOGIN PASSWORD '...';
--
-- Create it with SQL rather than through the Neon console or API: roles made there are
-- added to neon_superuser, which would defeat the point. This block only grants, and only
-- if the role exists, so the file still runs on a database without it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shieldlink_app') THEN
        GRANT USAGE ON SCHEMA public TO shieldlink_app;
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON lista_blanca, lista_negra, limite_peticiones
            TO shieldlink_app;
    END IF;
END
$$;
