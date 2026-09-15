import { createClient } from '@supabase/supabase-js';

/**
 * Server-only Supabase client.
 *
 * It uses the service role key, which bypasses row-level security. That is the whole
 * point of this module: the reputation tables deny every anonymous operation (see
 * schema.sql), so the only way to read or write them is through code that runs on the
 * server and holds this key.
 *
 * Never import this from anything that reaches the browser. The key grants full access
 * to the database, and Astro will happily bundle whatever a client-side script imports.
 * Note the variable names carry no PUBLIC_ prefix, so Astro refuses to expose them to
 * client code even by accident.
 *
 * Vercel injects environment variables at runtime rather than at build time, so read
 * process.env first and fall back to import.meta.env for local `astro dev`.
 */
export function getSupabase() {
  const url = process.env.SUPABASE_URL ?? import.meta.env.SUPABASE_URL;
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? import.meta.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) return null;

  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
