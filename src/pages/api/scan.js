import { getSupabase } from '../../utils/supabase.server.js';

/**
 * Astro's default output is static. Without this line the route is built as a plain
 * asset that answers POST with 405 — which is exactly what silently disabled the
 * VirusTotal layer in production while the UI kept reporting a verdict.
 */
export const prerender = false;

/**
 * TLDs that turn up disproportionately in phishing and malware campaigns. Checking them
 * first means an obvious throwaway domain never costs a VirusTotal lookup, and the free
 * tier's quota is small enough that this matters.
 */
const TLDS_PELIGROSOS = ['.xyz', '.zip', '.mov', '.tk', '.fit', '.icu', '.top'];

/** A URL far longer than this is not a link a human is about to click. */
const MAX_URL_LENGTH = 2048;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

/**
 * Every verdict carries both `nivel`, which the UI styles on, and the older `seguro`
 * boolean, so a caller that only understands safe-or-not still behaves correctly.
 * Caution counts as not-safe there: erring toward the warning is the right default for
 * a tool people consult before clicking a link.
 */
const veredicto = (nivel, motivo) => ({ nivel, seguro: nivel === 'seguro', motivo });

/**
 * VirusTotal identifies a URL by its base64 encoding with the padding stripped, using
 * the URL-safe alphabet. Plain base64 produces "+" and "/", which are not valid in a
 * path segment, so any URL whose encoding contained them used to 404 here.
 */
const virusTotalId = (url) => Buffer.from(url).toString('base64url').replace(/=/g, '');

/**
 * VirusTotal aggregates around ninety engines of very uneven quality, and a handful of
 * detections on an established domain is routinely noise rather than signal: google.com
 * itself reports 2 malicious against 61 harmless. Treating "at least one engine" as
 * dangerous — as this code originally did — therefore labels most of the web a threat.
 *
 * So the verdict has three levels instead of two. Only a detection count high enough to
 * outrun the usual false positives is called dangerous; a low count is surfaced honestly
 * as caution, with the numbers shown, rather than being hidden or overstated.
 */
const UMBRAL_PELIGRO = 3;

async function consultarVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY ?? import.meta.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${virusTotalId(url)}`,
      { headers: { 'x-apikey': apiKey } },
    );

    // 404 means VirusTotal has never been asked about this URL. That is not an error and
    // not a clean bill of health either — it just leaves the decision to the later layers.
    if (response.status === 404) return null;
    if (!response.ok) return null;

    const data = await response.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) return null;

    // last_analysis_stats reports harmless / malicious / suspicious / undetected /
    // timeout. An earlier version read stats.phishing, which does not exist, so the
    // engine count rendered as "NaN motores" on every malicious verdict.
    const maliciosos = stats.malicious ?? 0;
    const sospechosos = stats.suspicious ?? 0;
    const total = Object.values(stats).reduce((suma, n) => suma + (n ?? 0), 0);
    const motores = (n) => `${n} de ${total} motores`;

    if (maliciosos >= UMBRAL_PELIGRO) {
      return veredicto(
        'peligroso',
        `VirusTotal confirma riesgo: ${motores(maliciosos)} de seguridad clasifican este enlace como malicioso.`,
      );
    }

    if (maliciosos > 0 || sospechosos >= 2) {
      return veredicto(
        'precaucion',
        `Detecciones minoritarias: ${motores(
          maliciosos + sospechosos,
        )} marcan este enlace. Esa proporción suele ser un falso positivo, pero conviene revisarlo antes de abrirlo.`,
      );
    }

    return veredicto(
      'seguro',
      `Análisis global completado: ninguno de los ${total} motores de seguridad detectó amenazas.`,
    );
  } catch {
    // A VirusTotal outage must not take the scanner down with it; the local layers and
    // the protocol heuristic still produce a usable verdict.
    return null;
  }
}

export const POST = async ({ request }) => {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: true, motivo: 'Solicitud malformada.' }, 400);
  }

  const raw = typeof payload?.url === 'string' ? payload.url.trim() : '';

  if (!raw) {
    return json({ error: true, motivo: 'Falta el enlace a analizar.' }, 400);
  }

  if (raw.length > MAX_URL_LENGTH) {
    return json({ error: true, motivo: 'El enlace es demasiado largo para analizarlo.' }, 400);
  }

  // The client validates the format too, for instant feedback, but that check is a
  // convenience and not a guarantee — anything reaching this endpoint is revalidated.
  let urlObj;
  try {
    urlObj = new URL(raw.toLowerCase());
  } catch {
    return json({ error: true, motivo: 'URL no válida. Revisa la ortografía del enlace.' }, 400);
  }

  if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
    return json(
      {
        error: true,
        motivo: 'Formato no válido. Asegúrate de incluir http:// o https:// (Ej: https://google.com)',
      },
      400,
    );
  }

  const urlLimpia = urlObj.href;
  const host = urlObj.hostname;

  // 1. Heuristic block, before spending any API quota.
  const tldPeligroso = TLDS_PELIGROSOS.find((tld) => host.endsWith(tld));
  if (tldPeligroso) {
    return json(
      veredicto(
        'peligroso',
        `Bloqueo preventivo: la extensión ${tldPeligroso} se utiliza frecuentemente para campañas de phishing y distribución de malware.`,
      ),
    );
  }

  const supabase = getSupabase();

  // 2 and 3. Local reputation cache. A hit here answers without touching VirusTotal.
  if (supabase) {
    const { data: blanca, error: errorBlanca } = await supabase
      .from('lista_blanca')
      .select('url_segura')
      .eq('url_segura', urlLimpia)
      .maybeSingle();

    // A failed lookup must not block the scan — the later layers still produce a verdict —
    // but it must not pass unnoticed either. A wrong or missing key looks exactly like an
    // empty cache from the outside, so every lookup silently spends VirusTotal quota.
    if (errorBlanca) console.error('[scan] lista_blanca:', errorBlanca.message);

    if (blanca) {
      return json(veredicto('seguro', 'Enlace verificado en nuestra lista de confianza.'));
    }

    const { data: negra, error: errorNegra } = await supabase
      .from('lista_negra')
      .select('motivo')
      .eq('url_maliciosa', urlLimpia)
      .maybeSingle();

    if (errorNegra) console.error('[scan] lista_negra:', errorNegra.message);

    if (negra) {
      return json(veredicto('peligroso', `Amenaza confirmada: ${negra.motivo}`));
    }
  } else {
    console.error(
      '[scan] Supabase no configurado: faltan SUPABASE_URL o SUPABASE_SECRET_KEY. ' +
        'El escaneo funciona, pero sin caché cada consulta gasta cuota de VirusTotal.',
    );
  }

  // 4. Global engines.
  const resultadoVT = await consultarVirusTotal(urlLimpia);

  // 5. Persist the verdict so the same URL never costs a second lookup. Only confident
  // verdicts are cached: a "precaución" is a judgement call about ambiguous evidence, and
  // writing it into either list would harden a maybe into a yes or a no. A failed write
  // only costs quota next time, so it must not change the answer the user gets.
  if (resultadoVT && resultadoVT.nivel !== 'precaucion' && supabase) {
    try {
      if (resultadoVT.seguro) {
        await supabase
          .from('lista_blanca')
          .upsert({ url_segura: urlLimpia }, { onConflict: 'url_segura' });
      } else {
        await supabase
          .from('lista_negra')
          .upsert(
            { url_maliciosa: urlLimpia, motivo: resultadoVT.motivo },
            { onConflict: 'url_maliciosa' },
          );
      }
    } catch (e) {
      // The verdict stands whether or not it was cached; only the quota saving is lost.
      console.error('[scan] no se pudo cachear el veredicto:', e?.message ?? e);
    }
  }

  if (resultadoVT) return json(resultadoVT);

  // 6. Last resort: no reputation data anywhere, so fall back to the transport.
  if (urlObj.protocol !== 'https:') {
    return json(
      veredicto(
        'peligroso',
        'Inseguro: el sitio no utiliza cifrado SSL (HTTPS), facilitando el robo de datos.',
      ),
    );
  }

  return json(veredicto('seguro', 'Análisis básico finalizado: no se hallaron riesgos conocidos.'));
};
