import { getSql } from '../../utils/db.server.js';

export const prerender = false;

/**
 * Configuration health check.
 *
 * A missing connection string and a wrong one both make the scanner quietly skip its
 * cache, which from the outside is indistinguishable from a working deploy — every lookup
 * just silently costs VirusTotal quota. This endpoint answers the question directly.
 *
 * It reports booleans and, when the query fails, the driver's message — which names the
 * host or the network failure, never the credential. No value, prefix or length of any
 * secret is exposed, so it is safe to leave reachable.
 */
export const GET = async () => {
  const env = (name) => Boolean(process.env[name] ?? import.meta.env[name]);

  const sql = getSql();
  let alcanzable = false;
  let error = null;

  if (sql) {
    try {
      await sql`select url_hash from analisis limit 1`;
      alcanzable = true;
    } catch (queryError) {
      error = queryError.message;
    }
  }

  return new Response(
    JSON.stringify(
      {
        base: {
          urlDefinida: env('DATABASE_URL'),
          alcanzable,
          error,
        },
        virustotal: { clave: env('VIRUSTOTAL_API_KEY') },
        node: process.version,
        cacheActivo: alcanzable,
      },
      null,
      2,
    ),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
};
