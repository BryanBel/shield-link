-- Shield Link — analysis store
--
-- Run this as the database owner, not as the application role:
--
--     psql "$DATABASE_URL_ADMIN" -f schema.sql
--
-- It is idempotent: safe on a fresh database and safe to re-run on an existing one without
-- losing rows. It uses a DO block, so it needs a client that sends the file as-is, like
-- psql, rather than one that splits it on semicolons.
--
-- A NOTE ON ACCESS CONTROL, because this project used to carry the opposite.
--
-- On Supabase the reputation tables were reachable from the browser through PostgREST
-- with a public anonymous key, so they needed row-level security to be safe -- and an
-- early version shipped `FOR ALL USING (true)`, which granted select, insert, update and
-- delete to every caller. Anyone could insert a malicious URL into the allowlist and have
-- Shield Link vouch for it.
--
-- The database now sits behind a connection string that only the server holds. There is
-- no anonymous role and no HTTP interface in front of it, so there is nothing for a
-- policy to defend against: RLS here would be theatre rather than protection. What keeps
-- these tables safe is that only the server routes can reach them, as a role that can
-- touch rows and nothing else (see the end of this file), and the browser bundle contains
-- no credential -- verifiable with `grep -r neon dist/client` after a build.

-- One row per analysed URL. The key is the SHA-256 of the URL, never the URL itself: a
-- link can carry a password-reset or session token, and nothing here needs to read it
-- back. `informe` is the full report as the API returns it, with the query stripped from
-- every URL it mentions. Rows expire -- 7 days for a safe verdict, 1 for caution, 30 for
-- dangerous -- and /api/scan prunes them as it writes.
CREATE TABLE IF NOT EXISTS analisis (
    url_hash  TEXT        PRIMARY KEY,
    nivel     TEXT        NOT NULL,
    informe   JSONB       NOT NULL,
    creado    TIMESTAMPTZ NOT NULL DEFAULT now(),
    vence     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS analisis_vence ON analisis (vence);

-- Per-IP budget for fresh analyses. One row per client, scope ('minuto' or 'dia') and
-- window start; /api/scan increments it before every analysis and prunes rows older than
-- two days. See src/utils/analisis/limite.server.js.
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
            ON analisis, limite_peticiones
            TO shieldlink_app;
    END IF;
END
$$;
