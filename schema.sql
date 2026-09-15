-- Shield Link — reputation store
--
-- Run this in the Supabase SQL editor. It is idempotent: safe to run on a fresh project
-- and safe to re-run on an existing one without losing rows.
--
-- SECURITY NOTE — read before changing the policies at the bottom.
--
-- These two tables decide whether the scanner tells a user a link is safe. Earlier
-- versions shipped them with:
--
--     CREATE POLICY "..." ON lista_blanca FOR ALL USING (true);
--
-- FOR ALL grants select, insert, update and delete, and USING (true) grants it to every
-- caller — including the anonymous key, which is public by design and readable in any
-- browser's devtools. Anyone could therefore insert a malicious URL into lista_blanca
-- and have Shield Link report it as "verificado en nuestra lista de confianza", or wipe
-- both tables outright. For a tool whose only job is to answer "is this link safe?",
-- that inverts the product.
--
-- The fix is not a narrower policy: the scanner needs to write here to cache verdicts,
-- and any policy that lets the browser write is a policy an attacker can use. So all
-- reads and writes moved into the /api/scan server route, which holds the service role
-- key and bypasses RLS. Below, RLS is enabled with no policies at all, which denies
-- every anonymous and authenticated request by default.

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

-- URLs confirmed safe, cached so a repeat lookup never spends VirusTotal quota.
CREATE TABLE IF NOT EXISTS lista_blanca (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_segura     TEXT UNIQUE NOT NULL,
    fecha_analisis TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- URLs confirmed malicious, with the verdict that justified the classification.
CREATE TABLE IF NOT EXISTS lista_negra (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_maliciosa  TEXT UNIQUE NOT NULL,
    motivo         TEXT NOT NULL,
    fecha_reporte  TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

-- Remove the permissive policies shipped by earlier versions, by name, so re-running
-- this file on an existing project actually closes the hole rather than leaving it.
DROP POLICY IF EXISTS "Permitir lectura y escritura anonima blanca" ON lista_blanca;
DROP POLICY IF EXISTS "Permitir lectura y escritura anonima negra"  ON lista_negra;

ALTER TABLE lista_blanca ENABLE ROW LEVEL SECURITY;
ALTER TABLE lista_negra  ENABLE ROW LEVEL SECURITY;

-- Deliberately no CREATE POLICY statements follow. With RLS enabled and no policy
-- present, PostgreSQL denies every operation for anon and authenticated. The service
-- role used by /api/scan bypasses RLS, so the server route keeps full access.

-- Defence in depth: nothing in the application uses the anon or authenticated roles
-- against these tables any more, so drop the table grants PostgREST relies on too. If a
-- permissive policy is ever added back by accident, this still blocks the request.
REVOKE ALL ON lista_blanca FROM anon, authenticated;
REVOKE ALL ON lista_negra  FROM anon, authenticated;
