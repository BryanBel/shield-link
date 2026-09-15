import { getSupabase } from '../../utils/supabase.server.js';

export const prerender = false;

/**
 * Configuration health check.
 *
 * A missing key and a wrong key both make the scanner quietly skip its cache, which from
 * the outside is indistinguishable from a working deploy — every lookup just silently
 * costs VirusTotal quota. This endpoint answers the question directly.
 *
 * It reports booleans only: whether each variable is present and whether the database
 * actually answers. No value, prefix or length of any secret is exposed, so it is safe
 * to leave reachable.
 */
export const GET = async () => {
  const env = (name) => Boolean(process.env[name] ?? import.meta.env[name]);

  const supabase = getSupabase();
  let alcanzable = false;
  let error = null;

  if (supabase) {
    const { error: queryError } = await supabase
      .from('lista_blanca')
      .select('url_segura')
      .limit(1);

    alcanzable = !queryError;
    // The message names the table and the failure, never the credentials.
    if (queryError) error = queryError.message;
  }

  return new Response(
    JSON.stringify(
      {
        supabase: {
          url: env('SUPABASE_URL'),
          // Either name satisfies the client; the current one is SUPABASE_SECRET_KEY.
          clave: env('SUPABASE_SECRET_KEY') || env('SUPABASE_SERVICE_ROLE_KEY'),
          nombreUsado: env('SUPABASE_SECRET_KEY')
            ? 'SUPABASE_SECRET_KEY'
            : env('SUPABASE_SERVICE_ROLE_KEY')
              ? 'SUPABASE_SERVICE_ROLE_KEY'
              : null,
          alcanzable,
          error,
        },
        virustotal: { clave: env('VIRUSTOTAL_API_KEY') },
        // package.json bounds engines.node to a range rather than leaving it open-ended,
        // so the build cannot jump to a new Node major on its own. This reports which
        // version inside that range the platform actually chose.
        node: process.version,
        cacheActivo: alcanzable,
      },
      null,
      2,
    ),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
};
