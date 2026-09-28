/**
 * Per-client budget for fresh analyses.
 *
 * The endpoint is public, and every link it has not seen before costs a VirusTotal lookup
 * against a free tier of 4 a minute and 500 a day — shared by every visitor — plus a visit
 * to the site and a few registry queries. Without a limit, one client sending unique URLs
 * in a loop drains the day's quota for everyone, or uses the scanner as a proxy to hit
 * third-party sites.
 *
 * Only fresh analyses are counted: a cached report costs nothing, so ordinary use never
 * comes near these numbers. The counters live in Postgres because a serverless function
 * has no memory that outlives the request or is shared between instances.
 */
export const LIMITE_POR_MINUTO = 4;
export const LIMITE_POR_DIA = 50;

/**
 * Counts one analysis against the client's minute and day windows and reports which limit,
 * if any, it went over. One round trip: both upserts and the pruning of stale windows run
 * as a single statement. Rejected attempts count too, so hammering does not reset the
 * window.
 */
export async function consumirCupo(sql, ip) {
  const [fila] = await sql`
    with poda as (
      delete from limite_peticiones where ventana < now() - interval '2 days'
    ),
    minuto as (
      insert into limite_peticiones (alcance, ip, ventana)
      values ('minuto', ${ip}, date_trunc('minute', now()))
      on conflict (alcance, ip, ventana) do update set conteo = limite_peticiones.conteo + 1
      returning conteo
    ),
    dia as (
      insert into limite_peticiones (alcance, ip, ventana)
      values ('dia', ${ip}, date_trunc('day', now()))
      on conflict (alcance, ip, ventana) do update set conteo = limite_peticiones.conteo + 1
      returning conteo
    )
    select minuto.conteo as minuto, dia.conteo as dia from minuto, dia
  `;

  if (fila.dia > LIMITE_POR_DIA) return 'dia';
  if (fila.minuto > LIMITE_POR_MINUTO) return 'minuto';
  return null;
}
