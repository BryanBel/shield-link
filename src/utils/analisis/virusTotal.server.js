/**
 * VirusTotal API v3, URL report. One lookup returns far more than a detection count: which
 * engines flagged the link and as what, how the web categorises it, when VirusTotal first
 * saw it, and where it redirects. All of it goes into the report.
 *
 * This never submits a URL for scanning — a submission is public to VirusTotal's
 * community, and a link can carry a token. It only reads what VirusTotal already has.
 */

import { MOTORES_DESTACADOS } from './datos.js';

const TIEMPO_MS = 5000;

/**
 * VirusTotal identifies a URL by its base64 encoding with the padding stripped, using the
 * URL-safe alphabet. Plain base64 produces "+" and "/", which are not valid in a path
 * segment, so any URL whose encoding contained them used to 404 here.
 */
const idVirusTotal = (url) => Buffer.from(url).toString('base64url').replace(/=/g, '');

const fecha = (segundos) => (segundos ? new Date(segundos * 1000).toISOString() : null);

const sinQuery = (texto) => {
  try {
    const u = new URL(texto);
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
};

const PALABRAS_VACIAS = new Set(['and', 'or', 'the', 'of', 'y', 'de']);
const palabrasDe = (etiqueta) =>
  new Set(
    etiqueta
      .split(/[^a-z0-9]+/)
      .filter((p) => p && !PALABRAS_VACIAS.has(p))
      // "search engine" and "search engines" are the same category.
      .map((p) => (p.length > 3 && p.endsWith('s') ? p.slice(0, -1) : p)),
  );
const contenido = (a, b) => [...a].every((p) => b.has(p));
// "searchengines" is "search engines" written as one word.
const cubre = (b, a) => contenido(a.palabras, b.palabras) || (a.palabras.size === 1 && b.compacto.includes(a.compacto));

/**
 * Every vendor labels a site its own way — "search engines", "search engines/portals",
 * "search engines and portals", "searchengines (alphamountain.ai)". A label whose words
 * are all contained in another's says nothing new, so only the most complete one of each
 * family is kept, in the order the vendors gave them.
 */
export function limpiarCategorias(valores) {
  const items = valores
    .map((v) => String(v).toLowerCase().replace(/\s*\([^)]*\)\s*$/, '').trim())
    .filter(Boolean)
    .map((etiqueta) => {
      const palabras = palabrasDe(etiqueta);
      return { etiqueta, palabras, compacto: [...palabras].join('') };
    })
    .filter((i) => i.palabras.size);

  return items
    .filter((a, i) => !items.some((b, j) => j !== i && cubre(b, a) && (b.palabras.size > a.palabras.size || j < i)))
    .map((i) => i.etiqueta)
    .slice(0, 5);
}

/**
 * `{ estado: 'conocido', ... }` with the report, `{ estado: 'desconocido' }` when
 * VirusTotal has never analysed the URL, or `{ estado: 'error' | 'sin-clave' }`. An outage
 * must not take the scanner down with it, so nothing here throws.
 */
export async function consultarVirusTotal(url) {
  const clave = process.env.VIRUSTOTAL_API_KEY ?? import.meta.env.VIRUSTOTAL_API_KEY;
  if (!clave) return { estado: 'sin-clave' };

  try {
    const respuesta = await fetch(`https://www.virustotal.com/api/v3/urls/${idVirusTotal(url)}`, {
      headers: { 'x-apikey': clave },
      signal: AbortSignal.timeout(TIEMPO_MS),
    });

    // 404 means VirusTotal has never been asked about this URL. That is not an error and
    // not a clean bill of health either — it just leaves the decision to the other signals.
    if (respuesta.status === 404) return { estado: 'desconocido' };
    if (respuesta.status === 429) return { estado: 'error', motivo: 'cuota de VirusTotal agotada' };
    if (!respuesta.ok) return { estado: 'error', motivo: `VirusTotal respondió ${respuesta.status}` };

    const a = (await respuesta.json())?.data?.attributes;
    const stats = a?.last_analysis_stats;
    if (!stats) return { estado: 'error', motivo: 'respuesta de VirusTotal sin estadísticas' };

    // last_analysis_stats reports harmless / malicious / suspicious / undetected / timeout.
    // An earlier version read stats.phishing, which does not exist, so the engine count
    // rendered as "NaN motores" on every malicious verdict.
    const total = Object.values(stats).reduce((suma, n) => suma + (n ?? 0), 0);
    const resultados = Object.values(a.last_analysis_results ?? {});
    // `method` says how the engine reached its verdict: "blacklist" means the URL is on its
    // list — reported by someone — not that it analysed the page.
    const detecciones = resultados
      .filter((r) => r.category === 'malicious' || r.category === 'suspicious')
      .map((r) => ({ motor: r.engine_name, categoria: r.category, resultado: r.result, metodo: r.method ?? null }))
      .sort((x, y) => (x.categoria === y.categoria ? x.motor.localeCompare(y.motor) : x.categoria === 'malicious' ? -1 : 1));
    const limpiosDestacados = MOTORES_DESTACADOS.filter((nombre) =>
      resultados.some((r) => r.engine_name.toLowerCase() === nombre.toLowerCase() && r.category === 'harmless'),
    );

    return {
      estado: 'conocido',
      maliciosos: stats.malicious ?? 0,
      sospechosos: stats.suspicious ?? 0,
      inofensivos: stats.harmless ?? 0,
      total,
      detecciones,
      limpiosDestacados,
      categorias: limpiarCategorias(Object.values(a.categories ?? {})),
      reputacion: a.reputation ?? 0,
      votos: { inofensivo: a.total_votes?.harmless ?? 0, malicioso: a.total_votes?.malicious ?? 0 },
      primerEnvio: fecha(a.first_submission_date),
      ultimoAnalisis: fecha(a.last_analysis_date),
      titulo: a.title ?? null,
      urlFinal: a.last_final_url ? sinQuery(a.last_final_url) : null,
      redirecciones: (a.redirection_chain ?? []).map(sinQuery).filter(Boolean).slice(0, 10),
      codigoHttp: a.last_http_response_code ?? null,
    };
  } catch {
    return { estado: 'error', motivo: 'VirusTotal no respondió' };
  }
}
