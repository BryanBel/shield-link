import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';

/**
 * Visits the link from the server: follows its redirects, reads the TLS certificate and
 * looks at the HTML it serves — without ever executing it.
 *
 * Fetching a URL someone else chose is a server-side request forgery risk: pointed at
 * 127.0.0.1, 169.254.169.254 or a private range, the scanner would be probing its own
 * infrastructure on the attacker's behalf. So every connection goes through
 * `lookupSeguro`, which resolves the host and refuses any address that is not public. The
 * check runs at connect time, inside the socket's own DNS lookup, so a hostname cannot
 * resolve to a public address when checked and a private one when used (DNS rebinding).
 */

const UA = 'ShieldLink/2.0 (+https://shield-link.vercel.app)';
const MAX_SALTOS = 8;
const MAX_CUERPO = 512 * 1024;
const TIEMPO_SALTO_MS = 4000;
const TIEMPO_TOTAL_MS = 7000;
const PUERTOS = new Set(['', '80', '443', '8080', '8443']);

// Two lists, not one: a BlockList also matches IPv4 addresses against IPv4-mapped IPv6
// rules, so the ::ffff:0:0/96 entry below would block every IPv4 address on the internet.
const bloqueadasV4 = new net.BlockList();
for (const [red, prefijo] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) bloqueadasV4.addSubnet(red, prefijo, 'ipv4');

const bloqueadasV6 = new net.BlockList();
for (const [red, prefijo] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7],
  ['fe80::', 10], ['ff00::', 8],
]) bloqueadasV6.addSubnet(red, prefijo, 'ipv6');

/** True only for a routable, public unicast address. Anything unparseable is not public. */
export function esIpPublica(ip) {
  const version = net.isIP(ip);
  if (version === 4) return !bloqueadasV4.check(ip, 'ipv4');
  if (version === 6) return !bloqueadasV6.check(ip, 'ipv6');
  return false;
}

function errorBloqueo(direccion) {
  const e = new Error(`La dirección ${direccion} no es pública`);
  e.code = 'IP_NO_PUBLICA';
  e.direccion = direccion;
  return e;
}

/**
 * Drop-in for dns.lookup. If any address the name resolves to is private, the whole name
 * is refused: a host that answers with a mix is exactly what a rebinding attack looks like.
 */
function lookupSeguro(hostname, opciones, callback) {
  dns.lookup(hostname, { ...opciones, all: true }, (error, direcciones) => {
    if (error) return callback(error);
    const privada = direcciones.find((d) => !esIpPublica(d.address));
    if (privada || direcciones.length === 0) return callback(errorBloqueo(privada?.address ?? hostname));
    if (opciones.all) return callback(null, direcciones);
    callback(null, direcciones[0].address, direcciones[0].family);
  });
}

/**
 * A link that looks single-use — a password reset, a confirmation, an unsubscribe — can be
 * consumed just by opening it. Those are never opened in full; only the server is checked.
 */
const PARAMETROS_SENSIBLES = /^(token|code|codigo|reset|confirm|confirmation|verify|verification|unsubscribe|otp|session|sid|key|auth|signature|sig|magic|invite|activation)$/i;

export function pareceDeUnSoloUso(url) {
  for (const nombre of url.searchParams.keys()) if (PARAMETROS_SENSIBLES.test(nombre)) return true;
  return url.pathname.split('/').some((segmento) => segmento.length >= 24 && /[A-Za-z]/.test(segmento) && /\d/.test(segmento));
}

const sinQuery = (url) => `${url.origin}${url.pathname}`;

function resumirCertificado(socket, host) {
  const c = socket.getPeerCertificate();
  if (!c || !c.valid_to) return null;
  return {
    emisor: c.issuer?.O ?? c.issuer?.CN ?? null,
    sujeto: c.subject?.CN ?? null,
    nombres: (c.subjectaltname ?? '').split(', ').filter(Boolean).map((n) => n.replace(/^DNS:/, '')).slice(0, 20),
    desde: new Date(c.valid_from).toISOString(),
    hasta: new Date(c.valid_to).toISOString(),
    valido: socket.authorized,
    error: socket.authorized ? null : String(socket.authorizationError ?? 'desconocido'),
    host,
  };
}

function descomprimir(respuesta) {
  const codificacion = String(respuesta.headers['content-encoding'] ?? '').toLowerCase();
  if (codificacion === 'gzip' || codificacion === 'x-gzip') return respuesta.pipe(zlib.createGunzip());
  if (codificacion === 'br') return respuesta.pipe(zlib.createBrotliDecompress());
  if (codificacion === 'deflate') return respuesta.pipe(zlib.createInflate());
  return respuesta;
}

/** One request, one hop. Never follows redirects on its own and never keeps the socket. */
function pedir(url, { metodo, leerCuerpo, tiempoMs }) {
  return new Promise((resolverOriginal, rechazarOriginal) => {
    // `timeout` below only fires on an idle socket; a server that drips its answer a byte at
    // a time would never trip it. This caps the whole hop.
    let reloj;
    const resolve = (valor) => { clearTimeout(reloj); resolverOriginal(valor); };
    const reject = (error) => { clearTimeout(reloj); rechazarOriginal(error); };
    const modulo = url.protocol === 'https:' ? https : http;
    const peticion = modulo.request(
      url,
      {
        method: metodo,
        agent: false,
        lookup: lookupSeguro,
        timeout: tiempoMs,
        // Invalid certificates are something to report, not a reason to stop looking.
        // socket.authorized still says whether the chain and the hostname checked out.
        rejectUnauthorized: false,
        headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5', 'accept-language': 'es,en;q=0.8' },
      },
      (respuesta) => {
        const socket = respuesta.socket;
        const base = {
          estado: respuesta.statusCode,
          ubicacion: respuesta.headers.location ?? null,
          tipo: String(respuesta.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase(),
          ip: socket.remoteAddress ?? null,
          certificado: url.protocol === 'https:' ? resumirCertificado(socket, url.hostname) : null,
          cuerpo: null,
        };

        if (!leerCuerpo || base.tipo !== 'text/html' || (base.estado >= 300 && base.estado < 400)) {
          respuesta.resume();
          return resolve(base);
        }

        const trozos = [];
        let total = 0;
        const flujo = descomprimir(respuesta);
        const terminar = () => resolve({ ...base, cuerpo: Buffer.concat(trozos).toString('utf8') });
        flujo.on('data', (trozo) => {
          total += trozo.length;
          if (total > MAX_CUERPO) {
            trozos.push(trozo.subarray(0, trozo.length - (total - MAX_CUERPO)));
            respuesta.destroy();
            return terminar();
          }
          trozos.push(trozo);
        });
        flujo.on('end', terminar);
        flujo.on('error', terminar);
        // If the hop is cut short mid-body, keep what arrived rather than losing all of it.
        respuesta.on('close', terminar);
      },
    );
    const agotar = () => peticion.destroy(Object.assign(new Error('Tiempo agotado'), { code: 'TIEMPO' }));
    reloj = setTimeout(agotar, tiempoMs);
    peticion.on('timeout', agotar);
    peticion.on('error', reject);
    peticion.end();
  });
}

const atributos = (etiqueta) => {
  const mapa = {};
  for (const m of etiqueta.matchAll(/([^\s=<>"'/]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    mapa[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return mapa;
};

const ENTIDADES = {
  quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ', amp: '&',
  aacute: 'á', eacute: 'é', iacute: 'í', oacute: 'ó', uacute: 'ú', ntilde: 'ñ', uuml: 'ü',
  Aacute: 'Á', Eacute: 'É', Iacute: 'Í', Oacute: 'Ó', Uacute: 'Ú', Ntilde: 'Ñ', iquest: '¿', iexcl: '¡',
};

const decodificar = (texto) =>
  texto
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&([a-z]+);/gi, (entidad, nombre) => ENTIDADES[nombre] ?? entidad)
    .replace(/\s+/g, ' ')
    .trim();

const hostDe = (valor, base) => {
  try {
    return new URL(valor, base).hostname;
  } catch {
    return null;
  }
};

/**
 * Reads what a page is, not what it says it is: its title, how it redirects, and above all
 * whether it asks for a password and where that password would be sent. Pure text
 * matching — nothing from the page is ever executed.
 */
export function analizarHtml(html, urlBase) {
  const titulo = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);

  let metaRefresh = null;
  for (const [etiqueta] of html.matchAll(/<meta\b[^>]*>/gi)) {
    const a = atributos(etiqueta);
    if ((a['http-equiv'] ?? '').toLowerCase() === 'refresh') {
      const destino = (a.content ?? '').match(/url\s*=\s*['"]?([^'";]+)/i);
      if (destino && hostDe(destino[1].trim(), urlBase)) metaRefresh = sinQuery(new URL(destino[1].trim(), urlBase));
    }
  }

  const formularios = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)(?:<\/form>|$)/gi)) {
    const a = atributos(`<form ${m[1]}>`);
    formularios.push({
      destino: a.action ? hostDe(a.action, urlBase) : new URL(urlBase).hostname,
      conClave: /<input\b[^>]*type\s*=\s*['"]?password/i.test(m[2]),
    });
  }

  const scriptsExternos = new Set();
  for (const [etiqueta] of html.matchAll(/<script\b[^>]*\bsrc\s*=[^>]*>/gi)) {
    const host = hostDe(atributos(etiqueta).src ?? '', urlBase);
    if (host && host !== new URL(urlBase).hostname) scriptsExternos.add(host);
  }

  return {
    titulo: titulo ? decodificar(titulo[1]).slice(0, 200) || null : null,
    metaRefresh,
    redireccionJs: /\b(?:window|document|top|self)?\.?location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(/i.test(html),
    formularios: formularios.length,
    formulariosConClave: formularios.filter((f) => f.conClave).length,
    destinosDeClave: [...new Set(formularios.filter((f) => f.conClave && f.destino).map((f) => f.destino))],
    camposClave: (html.match(/<input\b[^>]*type\s*=\s*['"]?password/gi) ?? []).length,
    iframes: (html.match(/<iframe\b/gi) ?? []).length,
    scriptsExternos: [...scriptsExternos].slice(0, 20),
  };
}

const describirError = (error) => {
  if (error.code === 'IP_NO_PUBLICA') return { tipo: 'bloqueado', motivo: `apunta a una dirección interna o reservada (${error.direccion})` };
  if (error.code === 'ENOTFOUND') return { tipo: 'error', motivo: 'el dominio no existe o no resuelve' };
  if (error.code === 'TIEMPO') return { tipo: 'error', motivo: 'el sitio no respondió a tiempo' };
  if (error.code === 'ECONNREFUSED') return { tipo: 'error', motivo: 'el servidor rechazó la conexión' };
  return { tipo: 'error', motivo: 'no se pudo conectar con el sitio' };
};

/**
 * Follows the link hop by hop and reports what it found. Never throws: every failure is
 * part of the report, because a link that points at a private address or a domain that
 * does not exist says something too.
 */
export async function investigar(urlTexto) {
  const inicio = Date.now();
  const original = new URL(urlTexto);
  const prudente = pareceDeUnSoloUso(original);

  // Credentials in the URL would be sent as an Authorization header. Never forward them.
  let actual = new URL(prudente ? original.origin : original.href);
  actual.username = '';
  actual.password = '';

  const informe = {
    visitado: false,
    prudente,
    bloqueado: null,
    error: null,
    saltos: [],
    urlFinal: null,
    degradaHttps: false,
    ip: null,
    certificado: null,
    pagina: null,
  };

  for (let salto = 0; salto <= MAX_SALTOS; salto++) {
    if (actual.protocol !== 'http:' && actual.protocol !== 'https:') {
      informe.error = `redirige a un esquema que no es web (${actual.protocol})`;
      break;
    }
    if (!PUERTOS.has(actual.port)) {
      informe.bloqueado = `usa el puerto ${actual.port}, que Shield Link no visita`;
      break;
    }
    const literal = actual.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(literal) && !esIpPublica(literal)) {
      informe.bloqueado = `apunta a una dirección interna o reservada (${literal})`;
      break;
    }

    const restante = TIEMPO_TOTAL_MS - (Date.now() - inicio);
    if (restante <= 0) {
      informe.error = 'demasiados saltos para el tiempo disponible';
      break;
    }

    let respuesta;
    try {
      respuesta = await pedir(actual, { metodo: prudente ? 'HEAD' : 'GET', leerCuerpo: !prudente, tiempoMs: Math.min(TIEMPO_SALTO_MS, restante) });
    } catch (error) {
      const { tipo, motivo } = describirError(error);
      informe[tipo === 'bloqueado' ? 'bloqueado' : 'error'] = motivo;
      break;
    }

    informe.visitado = true;
    informe.saltos.push({ url: sinQuery(actual), estado: respuesta.estado, host: actual.hostname, ip: respuesta.ip, https: actual.protocol === 'https:' });
    informe.urlFinal = sinQuery(actual);
    informe.ip = respuesta.ip;
    if (respuesta.certificado) informe.certificado = respuesta.certificado;
    else if (actual.protocol === 'http:') informe.certificado = null;

    if (respuesta.estado >= 300 && respuesta.estado < 400 && respuesta.ubicacion) {
      let siguiente;
      try {
        siguiente = new URL(respuesta.ubicacion, actual);
      } catch {
        informe.error = 'la redirección apunta a una dirección inválida';
        break;
      }
      if (actual.protocol === 'https:' && siguiente.protocol === 'http:') informe.degradaHttps = true;
      if (salto === MAX_SALTOS) informe.error = `más de ${MAX_SALTOS} redirecciones`;
      actual = siguiente;
      continue;
    }

    if (respuesta.cuerpo) informe.pagina = analizarHtml(respuesta.cuerpo, actual.href);
    break;
  }

  return informe;
}
