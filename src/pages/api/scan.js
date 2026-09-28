import { getDomain } from 'tldts';

import { getSql } from '../../utils/db.server.js';
import { guardarAnalisis, hashUrl, leerAnalisis } from '../../utils/analisis/cache.server.js';
import { TLDS_PELIGROSOS } from '../../utils/analisis/datos.js';
import { investigar } from '../../utils/analisis/investigar.server.js';
import { consumirCupo } from '../../utils/analisis/limite.server.js';
import { rdapDominio, rdapIp } from '../../utils/analisis/rdap.server.js';
import { generarSenales } from '../../utils/analisis/senales.js';
import { decidirVeredicto } from '../../utils/analisis/veredicto.js';
import { consultarVirusTotal } from '../../utils/analisis/virusTotal.server.js';
import { normalizarEntrada } from '../../utils/normalizarEntrada.js';

/**
 * Astro's default output is static. Without this line the route is built as a plain
 * asset that answers POST with 405 — which is exactly what silently disabled the
 * VirusTotal layer in production while the UI kept reporting a verdict.
 */
export const prerender = false;

/** A URL far longer than this is not a link a human is about to click. */
const MAX_URL_LENGTH = 2048;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const valor = (resultado) => (resultado.status === 'fulfilled' ? resultado.value : null);
const sinQuery = (url) => `${url.origin}${url.pathname}`;
const tldDeRiesgo = (host) => TLDS_PELIGROSOS.some((tld) => host.endsWith(tld));

/**
 * The investigation. Every source is independent, so they all run at once: VirusTotal's
 * reputation, a visit to the link itself, and the domain's registration record. The IP's
 * registry lookup waits only for the visit that discovers the IP.
 *
 * If the link lands on another registrable domain — a shortener, a redirect — that
 * destination is what the user will actually see, so it gets its own reputation and
 * registration check. One extra VirusTotal lookup at most.
 */
async function analizar(url) {
  const dominio = getDomain(url.hostname);
  // A high-risk TLD is called dangerous without spending VirusTotal quota on it. The free
  // sources still run, so the report explains more than the extension.
  const riesgo = tldDeRiesgo(url.hostname);

  const [rVt, rRed, rRdap] = await Promise.allSettled([
    riesgo ? null : consultarVirusTotal(url.href),
    investigar(url.href).then(async (red) => ({ ...red, registroIp: red.ip ? await rdapIp(red.ip) : null })),
    dominio ? rdapDominio(dominio) : null,
  ]);
  const vt = valor(rVt);
  const red = valor(rRed);
  const rdap = valor(rRdap);

  const final = red?.urlFinal ?? (vt?.estado === 'conocido' ? vt.urlFinal : null);
  const hostFinal = final ? new URL(final).hostname : null;
  const dominioFinal = hostFinal ? getDomain(hostFinal) : null;

  let vtDestino = null;
  let rdapDestino = null;
  if (dominio && dominioFinal && dominioFinal !== dominio) {
    [vtDestino, rdapDestino] = (
      await Promise.allSettled([tldDeRiesgo(hostFinal) ? null : consultarVirusTotal(final), rdapDominio(dominioFinal)])
    ).map(valor);
  }

  const senales = generarSenales({ url, vt, vtDestino, red, rdap, rdapDestino });
  const { nivel, certeza, motivo } = decidirVeredicto(senales, { vt });

  const reputacion = (v) =>
    v?.estado === 'conocido'
      ? {
          estado: 'conocido',
          maliciosos: v.maliciosos,
          sospechosos: v.sospechosos,
          inofensivos: v.inofensivos,
          total: v.total,
          detecciones: v.detecciones,
          categorias: v.categorias,
          votos: v.votos,
          primerEnvio: v.primerEnvio,
          ultimoAnalisis: v.ultimoAnalisis,
        }
      : { estado: v?.estado ?? (riesgo ? 'omitido' : 'error') };

  // Every URL in the report has its query stripped: it is stored, and a query can carry a
  // token. The verdict itself was reached with the full URL.
  return {
    nivel,
    seguro: nivel === 'seguro',
    certeza,
    motivo,
    senales,
    detalles: {
      url: sinQuery(url),
      dominio: dominio
        ? {
            nombre: dominio,
            creado: rdap?.creado ?? null,
            expira: rdap?.expira ?? null,
            registrador: rdap?.registrador ?? null,
          }
        : null,
      destino: {
        saltos: red?.saltos ?? [],
        urlFinal: final,
        dominioFinal: dominioFinal !== dominio ? dominioFinal : null,
        redireccionesConocidas: vt?.estado === 'conocido' ? vt.redirecciones : [],
      },
      certificado: red?.certificado ?? null,
      servidor: red?.ip
        ? {
            ip: red.ip,
            red: red.registroIp?.red ?? null,
            organizacion: red.registroIp?.organizacion ?? null,
            pais: red.registroIp?.pais ?? null,
          }
        : null,
      reputacion: reputacion(vt),
      reputacionDestino: vtDestino ? reputacion(vtDestino) : null,
      pagina: red?.pagina ? { ...red.pagina, titulo: red.pagina.titulo ?? (vt?.titulo || null) } : null,
      visita: {
        visitado: red?.visitado ?? false,
        prudente: red?.prudente ?? false,
        bloqueado: red?.bloqueado ?? null,
        error: red?.error ?? null,
      },
    },
  };
}

export const POST = async (context) => {
  const { request } = context;

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: true, motivo: 'Solicitud malformada.' }, 400);
  }

  const raw = typeof payload?.url === 'string' ? payload.url.trim() : '';

  if (raw.length > MAX_URL_LENGTH) {
    return json({ error: true, motivo: 'El enlace es demasiado largo para analizarlo.' }, 400);
  }

  // The page validates too, for instant feedback, but that check is a convenience and not
  // a guarantee — anything reaching this endpoint is revalidated. A missing scheme is
  // taken as https. The URL is otherwise parsed as typed: the parser lowercases the scheme
  // and the host, the only parts that are case-insensitive. Lowercasing the whole string,
  // as this used to, made bit.ly/AbC and bit.ly/abc one cache entry — so a harmless short
  // link, once cleared, vouched for a different one that pointed anywhere.
  const entrada = normalizarEntrada(raw);
  if (entrada.error) {
    return json({ error: true, motivo: entrada.error }, 400);
  }
  const urlObj = entrada.url;
  const conEsquema = (informe) => (entrada.esquemaAsumido ? { ...informe, esquemaAsumido: true } : informe);

  // The fragment never reaches the server the link points to, so it cannot change what the
  // link does; dropping it keeps page.html#a and page.html#b from being scanned twice.
  urlObj.hash = '';
  const urlLimpia = urlObj.href;
  const hash = hashUrl(urlLimpia);

  const sql = getSql();
  if (!sql) {
    console.error(
      '[scan] DATABASE_URL no está definida. El escaneo funciona, pero sin caché ni límite ' +
        'cada consulta gasta cuota de VirusTotal.',
    );
  }

  // 1. Cache. A fresh report answers without any lookup. A failed read must not block the
  // scan, but it must not pass unnoticed either: from the outside it looks exactly like
  // an empty cache, and every lookup would silently spend quota.
  if (sql) {
    try {
      const guardado = await leerAnalisis(sql, hash);
      if (guardado) return json(conEsquema(guardado));
    } catch (error) {
      console.error('[scan] lectura de caché falló:', error.message);
    }
  }

  // 2. Per-client budget, checked only now that a fresh analysis would actually run.
  // Like the cache, a failure here is logged and let through.
  if (sql) {
    // On Vercel this comes from x-forwarded-for, which the platform overwrites with the
    // real client address, so it cannot be spoofed. Astro throws when it is missing.
    let ip;
    try {
      ip = context.clientAddress;
    } catch {
      ip = 'desconocida';
    }

    try {
      const excedido = await consumirCupo(sql, ip);
      if (excedido) {
        return json(
          {
            error: true,
            limite: true,
            motivo:
              excedido === 'dia'
                ? 'Alcanzaste el límite diario de análisis nuevos. Los enlaces ya analizados siguen respondiendo; vuelve mañana para el resto.'
                : 'Demasiados análisis nuevos en poco tiempo. Espera un minuto e inténtalo de nuevo.',
          },
          429,
        );
      }
    } catch (error) {
      console.error('[scan] control de cupo falló:', error.message);
    }
  }

  // 3. The investigation itself, then the report is stored. A failed write only costs a
  // repeat analysis next time, so it must not change the answer the user gets.
  const informe = await analizar(urlObj);

  if (sql) {
    try {
      await guardarAnalisis(sql, hash, informe);
    } catch (error) {
      console.error('[scan] no se pudo guardar el análisis:', error.message);
    }
  }

  return json(conEsquema(informe));
};
