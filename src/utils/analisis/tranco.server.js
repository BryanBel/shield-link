/**
 * Popularity, from the Tranco list — the ranking of the million most visited sites that
 * security research uses, built to resist manipulation (tranco-list.eu). Free and keyless.
 *
 * Popularity is not safety. What it does is give detections a scale: two engines out of
 * ninety flagging the most visited site in the world is almost certainly those two lists
 * being wrong, while the same two on a site nobody visits deserves attention.
 *
 * Never throws: an outage or a rate limit comes back as { disponible: false }.
 */

const TIEMPO_MS = 2500;

export async function rankTranco(dominio) {
  try {
    const respuesta = await fetch(`https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(dominio)}`, {
      headers: { 'user-agent': 'ShieldLink/2.0 (+https://shield-link.vercel.app)' },
      signal: AbortSignal.timeout(TIEMPO_MS),
    });
    if (!respuesta.ok) return { disponible: false };
    const datos = await respuesta.json();
    const ultimo = (datos.ranks ?? []).reduce((a, b) => (!a || b.date > a.date ? b : a), null);
    // An empty list is an answer too: the domain is not among the top million.
    return { disponible: true, rank: ultimo?.rank ?? null, fecha: ultimo?.date ?? null };
  } catch {
    return { disponible: false };
  }
}
