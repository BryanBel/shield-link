import { createHash } from 'node:crypto';

/**
 * The analysis cache. A report is keyed by the SHA-256 of the URL, never the URL itself: a
 * link can carry a password-reset or session token in its query, and nothing here needs
 * to be able to read it back. The stored report already has queries stripped from every
 * URL it mentions.
 *
 * Reports expire. A verdict is a snapshot — a domain changes hands, a certificate lapses,
 * VirusTotal's engines catch up — so how long one is trusted depends on what it says.
 */

const VIGENCIA = { seguro: '7 days', precaucion: '1 day', peligroso: '30 days' };

/**
 * Bump when the report's shape changes. The version is part of the key, so reports in an
 * older shape are simply never read again — no manual purge, no half-rendered card from a
 * stale entry — and the pruning in guardarAnalisis clears them out as they expire.
 */
const VERSION_INFORME = 4;

export const hashUrl = (url) => createHash('sha256').update(`v${VERSION_INFORME}:${url}`).digest('hex');

export async function leerAnalisis(sql, hash) {
  const [fila] = await sql`
    select informe, creado from analisis where url_hash = ${hash} and vence > now() limit 1
  `;
  return fila ? { ...fila.informe, desdeCache: true, analizadoEn: new Date(fila.creado).toISOString() } : null;
}

/** Stores the report and prunes long-expired ones in the same round trip. */
export async function guardarAnalisis(sql, hash, informe) {
  await sql`
    with poda as (
      delete from analisis where vence < now() - interval '1 day'
    )
    insert into analisis (url_hash, nivel, informe, vence)
    values (${hash}, ${informe.nivel}, ${JSON.stringify(informe)}::jsonb, now() + ${VIGENCIA[informe.nivel]}::interval)
    on conflict (url_hash) do update
      set nivel = excluded.nivel, informe = excluded.informe, creado = now(), vence = excluded.vence
  `;
}
