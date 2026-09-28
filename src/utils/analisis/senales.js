import { domainToUnicode } from 'node:url';
import { getDomain, getSubdomain } from 'tldts';

import { marcaDeclarada, marcaEnTexto, RIESGOS } from './contraste.js';
import { ACORTADORES, MARCAS, PLATAFORMAS_ABIERTAS, TLDS_PELIGROSOS } from './datos.js';
import { interpretarDetecciones, SITIO_POPULAR } from './detecciones.js';

/**
 * Turns everything the sources found into signals: short, explained facts about the link,
 * each one good, neutral, a warning or a danger. The verdict is decided from these and the
 * page shows them, so the user sees not just what Shield Link concluded but why.
 *
 * Pure: no network, no clock unless one is passed in. Every source may be missing — a
 * failed lookup simply contributes no signal, or an informational one saying so.
 *
 * A signal is { id, tipo: 'peligro' | 'alerta' | 'bien' | 'info', titulo, detalle }.
 * Titles are written to also read as a clause, because the verdict quotes them.
 */

const DIA = 86_400_000;
const ORDEN = { peligro: 0, alerta: 1, bien: 2, info: 3 };

export const diasDesde = (iso, ahora) => (iso ? Math.floor((ahora - new Date(iso)) / DIA) : null);

export function edad(dias) {
  if (dias < 1) return 'menos de un día';
  if (dias < 31) return dias === 1 ? '1 día' : `${dias} días`;
  if (dias < 365) {
    const meses = Math.floor(dias / 30);
    return meses === 1 ? '1 mes' : `${meses} meses`;
  }
  const anios = Math.floor(dias / 365);
  return anios === 1 ? '1 año' : `${anios} años`;
}

const fechaLarga = (iso) => new Date(iso).toLocaleDateString('es', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
/** A brand whose name appears as a label of the host — or runs into one, for long names. */
function marcaEnHost(host) {
  const partes = host.split(/[.-]/);
  return (
    MARCAS.find((m) =>
      m.claves.some((c) => {
        const clave = c.replace(/\s+/g, '');
        return partes.some((p) => p === clave || (clave.length >= 6 && (p.startsWith(clave) || p.endsWith(clave))));
      }),
    ) ?? null
  );
}

const hostDe = (texto) => {
  try {
    return new URL(texto).hostname;
  } catch {
    return null;
  }
};

const listar = (detecciones) =>
  detecciones
    .slice(0, 5)
    .map((d) => `${d.motor} (${d.resultado ?? d.categoria})`)
    .join(', ') + (detecciones.length > 5 ? ` y ${detecciones.length - 5} más` : '');

/**
 * `lectura` is the interpretation from detecciones.js. It supplies the explanation, and
 * decides the one case where a minority detection stops being a warning: a very popular,
 * long-lived domain that is not an open publishing platform, flagged by one or two engines.
 */
function senalesReputacion(vt, ahora, add, prefijo = '', lectura = null) {
  if (!vt) return;
  if (vt.estado === 'desconocido') {
    if (!prefijo) add('vt-desconocido', 'info', 'VirusTotal no tiene análisis de este enlace', 'Nadie lo ha enviado a analizar todavía, así que el veredicto se apoya en las demás señales.');
    return;
  }
  if (vt.estado !== 'conocido') {
    if (!prefijo && vt.estado === 'error') add('vt-error', 'info', 'No se pudo consultar VirusTotal', `Motivo: ${vt.motivo}.`);
    return;
  }

  const id = prefijo ? 'destino-' : 'vt-';
  const sujeto = prefijo ? `el destino (${prefijo})` : 'lo';
  const falsoPositivo = !prefijo && lectura?.interpretacion === 'falso-positivo';
  if (vt.maliciosos >= 3) {
    add(`${id}malicioso`, 'peligro', `${vt.maliciosos} de ${vt.total} motores de VirusTotal marcan ${prefijo ? sujeto : 'este enlace'} como malicioso`, lectura?.texto ?? `Detecciones: ${listar(vt.detecciones)}.`);
  } else if (vt.maliciosos > 0 || vt.sospechosos >= 2) {
    const n = vt.maliciosos + vt.sospechosos;
    const marcan = n === 1 ? 'marca' : 'marcan';
    if (falsoPositivo) {
      add('vt-falso-positivo', 'info', `${n} de ${vt.total} motores lo ${marcan}, casi seguro por error`, lectura.texto);
    } else if (lectura?.interpretacion === 'prediccion') {
      add(`${id}minoritario`, 'alerta', `${vt.detecciones.map((d) => d.motor).join(' y ')} ${prefijo ? `marca ${sujeto}` : 'lo marca'} como posible riesgo futuro (${n} de ${vt.total} motores)`, lectura.texto);
    } else {
      add(`${id}minoritario`, 'alerta', `${n} de ${vt.total} motores de VirusTotal ${prefijo ? `${marcan} ${sujeto}` : `lo ${marcan}`}`, lectura?.texto ?? `Una proporción tan baja suele ser un falso positivo, pero conviene revisarlo. Detecciones: ${listar(vt.detecciones)}.`);
    }
  } else if (!prefijo) {
    const sospechoso = vt.sospechosos === 1 ? ' Uno solo lo considera sospechoso, lo que no alcanza para preocuparse.' : '';
    const cuando = vt.ultimoAnalisis ? ` Último análisis: ${fechaLarga(vt.ultimoAnalisis)}.` : '';
    add('vt-limpio', 'bien', `Ninguno de los ${vt.total} motores de VirusTotal lo marca`, `${sospechoso}${cuando}`.trim() || 'Ningún motor lo considera malicioso.');
  }

  if (prefijo) return;
  if (vt.votos.malicioso >= 3 && vt.votos.malicioso > vt.votos.inofensivo) {
    add('vt-comunidad', 'alerta', `La comunidad de VirusTotal lo vota como malicioso`, `${vt.votos.malicioso} votos maliciosos contra ${vt.votos.inofensivo} inofensivos.`);
  }
  const conocidoHace = diasDesde(vt.primerEnvio, ahora);
  if (conocidoHace >= 365 && (vt.maliciosos === 0 || falsoPositivo)) {
    add('vt-antiguo', 'bien', `VirusTotal lo conoce desde ${new Date(vt.primerEnvio).getUTCFullYear()}`, 'Un enlace con años de historial y sin detecciones es difícil de falsificar.');
  }
  // Categories are not a signal: the card shows them where they belong, under "what this
  // site is".
}

function senalesDominio(rdap, dominio, ahora, add, prefijo = '', plataforma = null) {
  if (!dominio || !rdap) return;
  const quien = prefijo ? `El dominio de destino (${dominio})` : 'Dominio';
  const id = prefijo ? 'destino-dominio' : 'dominio';
  if (!rdap.disponible || !rdap.creado) {
    if (!prefijo) add('dominio-sin-registro', 'info', `No se pudo consultar el registro de ${dominio}`, 'Algunas extensiones no publican sus datos de registro (RDAP).');
    return;
  }
  const dias = diasDesde(rdap.creado, ahora);
  const titulo = `${quien} ${prefijo ? 'fue registrado' : 'registrado'} hace ${edad(dias)}`;
  const registro = `Registrado el ${fechaLarga(rdap.creado)}${rdap.registrador ? ` a través de ${rdap.registrador}` : ''}.`;
  if (dias < 7) add(`${id}-nuevo`, 'peligro', titulo, `${registro} Los sitios de phishing usan dominios de días de vida; uno legítimo rara vez es tan nuevo.`);
  else if (dias < 30) add(`${id}-nuevo`, 'alerta', titulo, `${registro} Un dominio de semanas merece desconfianza, sobre todo si pide datos.`);
  // On an open platform the domain's age belongs to the platform, not to the page.
  else if (!prefijo && plataforma && dias >= 365) add('dominio-plataforma', 'info', `La plataforma ${plataforma} existe hace ${edad(dias)}`, 'Esa antigüedad es de la plataforma, no de esta página: cualquiera pudo publicarla ayer.');
  else if (!prefijo && dias >= 365) add('dominio-antiguo', 'bien', titulo, registro);
  else if (!prefijo) add('dominio-reciente', 'info', titulo, registro);

  const vence = rdap.expira ? -diasDesde(rdap.expira, ahora) : null;
  if (!prefijo && vence !== null && vence >= 0 && vence < 30) add('dominio-vence', 'info', `El dominio vence en ${edad(vence)}`, 'Un dominio a punto de vencer puede cambiar de dueño.');
}

const ERRORES_CERTIFICADO = {
  CERT_HAS_EXPIRED: 'El certificado está vencido',
  ERR_TLS_CERT_ALTNAME_INVALID: 'El certificado no corresponde a este dominio',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'El certificado es autofirmado',
  SELF_SIGNED_CERT_IN_CHAIN: 'El certificado es autofirmado',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'No se pudo verificar quién emitió el certificado',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'No se pudo verificar quién emitió el certificado',
};

function senalesTransporte(url, red, ahora, add) {
  const ultimo = red?.saltos.at(-1);
  const cifrado = ultimo ? ultimo.https : url.protocol === 'https:';
  if (!cifrado) add('sin-https', 'alerta', 'El sitio no usa cifrado (HTTPS)', 'Lo que escribas en él viaja sin cifrar y puede leerse o alterarse en el camino.');
  if (red?.degradaHttps) add('degrada-https', 'alerta', 'Pasa de HTTPS a HTTP al redirigir', 'Empieza cifrado y termina sin cifrar: una conexión segura no debería degradarse.');

  const c = red?.certificado;
  if (!c) return;
  if (c.valido) {
    add('certificado-valido', 'bien', `Certificado válido emitido por ${c.emisor ?? 'una autoridad reconocida'}`, `Vigente hasta el ${fechaLarga(c.hasta)}. El navegador no mostraría ninguna advertencia.`);
    const emitido = diasDesde(c.desde, ahora);
    if (emitido !== null && emitido < 7) add('certificado-reciente', 'info', `Certificado emitido hace ${edad(emitido)}`, 'Es habitual en sitios que renuevan cada pocas semanas; solo pesa si el dominio también es nuevo.');
  } else {
    add('certificado-invalido', 'alerta', ERRORES_CERTIFICADO[c.error] ?? 'El certificado no es válido', `El navegador mostraría una advertencia de seguridad (${c.error}).`);
  }
}

function senalesDestino(url, dominio, red, vt, vtDestino, add) {
  const final = red?.urlFinal ?? vt?.urlFinal ?? null;
  const hostFinal = final ? hostDe(final) : null;
  const dominioFinal = hostFinal ? getDomain(hostFinal) : null;
  const acortador = ACORTADORES.has(url.hostname) || (dominio && ACORTADORES.has(dominio));

  if (dominioFinal && dominio && dominioFinal !== dominio) {
    const destinoLimpio = vtDestino?.estado === 'conocido' && vtDestino.maliciosos === 0 && vtDestino.sospechosos < 2;
    if (acortador) add('acortador', 'info', `Enlace acortado de ${url.hostname} que lleva a ${hostFinal}`, 'Un enlace acortado no dice adónde va; el veredicto tiene en cuenta el destino real.');
    else if (destinoLimpio) add('redirige-otro-dominio', 'info', `Redirige a ${hostFinal}`, `El enlace es de ${dominio}, pero termina en otro dominio. VirusTotal no marca ese destino.`);
    else add('redirige-otro-dominio', 'alerta', `Redirige a otro dominio: ${hostFinal}`, `El enlace dice ir a ${dominio}, pero termina en ${dominioFinal}.`);
  } else if (acortador && !final) {
    add('acortador', 'alerta', `Enlace acortado de ${url.hostname} con destino desconocido`, 'No se pudo averiguar adónde lleva, y un enlace acortado no lo dice por sí mismo.');
  }

  const estadoFinal = red?.saltos.at(-1)?.estado;
  if (estadoFinal >= 400) {
    add('respuesta-error', 'info', `La página responde con un error (${estadoFinal})`, estadoFinal === 404 || estadoFinal === 410 ? 'El destino no existe o fue retirado: el enlace está roto o ya lo dieron de baja.' : 'El servidor no entregó la página; el análisis se apoya en lo demás.');
  }

  const redirecciones = (red?.saltos.length ?? 1) - 1;
  if (redirecciones >= 3) add('cadena-larga', 'alerta', `Pasa por ${redirecciones} redirecciones`, 'Las cadenas largas de redirección se usan para esconder el destino real.');

  const p = red?.pagina;
  if (p?.metaRefresh) add('redireccion-pagina', 'info', `La página redirige por su cuenta a ${hostDe(p.metaRefresh)}`, 'Lo hace con una etiqueta meta refresh, un salto que el navegador sigue sin preguntar.');
  else if (p?.redireccionJs) add('redireccion-pagina', 'info', 'La página contiene código que puede redirigir', 'Shield Link no ejecuta JavaScript, así que no sigue ese salto; si ocurre, el destino puede ser otro.');
}

function senalesPagina(red, add) {
  const p = red?.pagina;
  if (!p) return;
  const hostFinal = red.urlFinal ? hostDe(red.urlFinal) : null;
  const dominioFinal = hostFinal ? getDomain(hostFinal) ?? hostFinal : null;

  const externo = p.destinosDeClave.find((h) => (getDomain(h) ?? h) !== dominioFinal);
  if (externo) {
    add('clave-a-otro-dominio', 'peligro', 'Pide una contraseña y la envía a otro dominio', `El formulario manda lo que escribas a ${externo}, no a ${dominioFinal}.`);
  }
  if (p.camposClave > 0) {
    const marca = marcaEnTexto(p.titulo);
    if (marca && !marca.dominios.includes(dominioFinal)) {
      add('suplanta-marca', 'peligro', `Pide una contraseña y se presenta como ${marca.nombre}`, `Pero ${dominioFinal} no pertenece a ${marca.nombre}. Así se ve un intento de robar credenciales.`);
    } else if (!externo) {
      add('pide-clave', 'info', 'La página pide una contraseña', `Escríbela solo si reconoces el dominio: ${dominioFinal}.`);
    }
  }
}

function senalesUrl(url, dominio, add) {
  const host = url.hostname;
  const tld = TLDS_PELIGROSOS.find((t) => host.endsWith(t));
  if (tld) add('tld-riesgo', 'peligro', `Usa la extensión ${tld}, de alto riesgo`, 'Se usa con tanta frecuencia en phishing y malware que Shield Link la bloquea de entrada.');

  const literal = host.replace(/^\[|\]$/g, '');
  if (/^[\d.]+$/.test(literal) || literal.includes(':')) {
    add('ip-como-dominio', 'alerta', 'Usa una dirección IP en lugar de un dominio', 'Los sitios legítimos casi nunca se enlazan así: oculta quién está detrás.');
  }
  if (host.split('.').some((etiqueta) => etiqueta.startsWith('xn--'))) {
    add('punycode', 'alerta', `Dominio con caracteres internacionales: ${domainToUnicode(host)}`, `En realidad se escribe ${host}. Letras de otros alfabetos pueden imitar a un dominio conocido.`);
  }
  if (url.username) {
    add('arroba', 'alerta', `Tiene texto antes de una @: "${decodeURIComponent(url.username)}"`, `El navegador lo ignora y va a ${host}; es un truco para que leas otro dominio primero.`);
  }

  const sub = getSubdomain(host);
  if (sub && sub.split('.').length >= 4) add('muchos-subdominios', 'alerta', `Tiene ${sub.split('.').length} niveles de subdominio`, `Tantos niveles sirven para que el principio del enlace parezca otro sitio. El dominio real es ${dominio}.`);

  const marca = marcaEnHost(host);
  if (marca && dominio && !marca.dominios.includes(dominio)) {
    const oficial = sub && marca.dominios.find((d) => sub.includes(d));
    if (oficial) add('marca-en-subdominio', 'peligro', `Imita a ${marca.nombre}: empieza con ${oficial}`, `Pero el dominio real es ${dominio}, que no pertenece a ${marca.nombre}.`);
    else add('marca-en-dominio', 'alerta', `Usa el nombre de ${marca.nombre} sin ser de ${marca.nombre}`, `El dominio real es ${dominio}.`);
  }

  if (url.port && url.port !== '80' && url.port !== '443') add('puerto', 'alerta', `Usa el puerto ${url.port}`, 'Los sitios web normales usan los puertos 80 y 443.');
  if (url.href.length > 200) add('url-larga', 'info', `Enlace muy largo (${url.href.length} caracteres)`, 'Los enlaces largos pueden esconder el destino real al final.');
}

function senalesVisita(red, add) {
  if (!red) return;
  if (red.bloqueado?.includes('interna')) add('red-interna', 'alerta', 'Apunta a una dirección interna o reservada', `Shield Link no lo visitó porque ${red.bloqueado}. Un enlace público no debería llevar a una red privada.`);
  else if (red.bloqueado) add('no-visitado', 'info', 'Shield Link no visitó el enlace', `Porque ${red.bloqueado}.`);
  else if (red.error) add('visita-fallida', 'info', `No se pudo visitar el sitio: ${red.error}`, 'El resto del análisis sigue siendo válido.');
  if (red.prudente) add('modo-prudente', 'info', 'Solo se revisó el servidor, no la página', 'El enlace parece de un solo uso (restablecer contraseña, confirmar, desuscribir). Abrirlo podría activarlo, así que Shield Link no lo cargó.');
}

/**
 * Popularity from the Tranco ranking. Only the top ten thousand counts in the link's
 * favour; a rank does not vouch for a page on an open platform, where the fame belongs to
 * the platform. Not being ranked says nothing either way — most legitimate sites are not.
 */
function senalesPopularidad(tranco, dominio, plataforma, add) {
  if (plataforma) {
    add('plataforma-abierta', 'info', `Publicado en ${plataforma}, donde cualquiera puede publicar`, `${dominio} es conocido, pero su fama no respalda esta página: la pudo subir cualquiera. Lo que importa es quién la hizo.`);
    return;
  }
  const rank = tranco?.disponible ? tranco.rank : null;
  if (!rank) return;
  const puesto = rank.toLocaleString('es');
  if (rank === 1) add('popular', 'bien', `${dominio} es el sitio más visitado del mundo`, 'Según el ranking Tranco, que combina varias fuentes de tráfico y resiste manipulaciones.');
  else if (rank <= SITIO_POPULAR) add('popular', 'bien', `${dominio} está entre los sitios más visitados del mundo (#${puesto})`, 'Según el ranking Tranco, que combina varias fuentes de tráfico y resiste manipulaciones.');
  else if (rank <= 100_000) add('conocido', 'info', `${dominio} es un sitio conocido: puesto #${puesto} en el mundo`, 'Está entre los 100.000 sitios más visitados según el ranking Tranco.');
}

export function generarSenales({ url, vt = null, vtDestino = null, red = null, rdap = null, rdapDestino = null, tranco = null, ahora = new Date() }) {
  const senales = [];
  const vistos = new Set();
  const add = (id, tipo, titulo, detalle) => {
    if (vistos.has(id)) return;
    vistos.add(id);
    senales.push({ id, tipo, titulo, detalle });
  };

  const dominio = getDomain(url.hostname);
  const hostFinal = red?.urlFinal ? hostDe(red.urlFinal) : vt?.urlFinal ? hostDe(vt.urlFinal) : null;
  const dominioFinal = hostFinal ? getDomain(hostFinal) : null;
  const otroDestino = Boolean(dominioFinal && dominioFinal !== dominio);

  // The page the user lands on decides popularity and whether it is an open platform.
  const hostPagina = otroDestino ? hostFinal : url.hostname;
  const plataforma = PLATAFORMAS_ABIERTAS.find((p) => hostPagina === p || hostPagina.endsWith(`.${p}`)) ?? null;
  const edadDe = (registro, v) => (registro?.creado ? diasDesde(registro.creado, ahora) : v?.primerEnvio ? diasDesde(v.primerEnvio, ahora) : null);
  const lectura = interpretarDetecciones({ vt, host: url.hostname, dominio, rank: otroDestino ? null : tranco?.rank ?? null, diasDominio: edadDe(rdap, vt) });
  const lecturaDestino = otroDestino
    ? interpretarDetecciones({ vt: vtDestino, host: hostFinal, dominio: dominioFinal, rank: tranco?.rank ?? null, diasDominio: edadDe(rdapDestino, vtDestino) })
    : null;

  // Popularity first: it is the context every other signal is read in.
  senalesPopularidad(tranco, otroDestino ? dominioFinal : dominio, plataforma, add);
  senalesReputacion(vt, ahora, add, '', lectura);
  if (otroDestino) {
    senalesReputacion(vtDestino, ahora, add, hostFinal, lecturaDestino);
    senalesDominio(rdapDestino, dominioFinal, ahora, add, 'destino');
  }
  senalesDominio(rdap, dominio, ahora, add, '', otroDestino ? null : plataforma);
  senalesTransporte(url, red, ahora, add);
  senalesDestino(url, dominio, red, vt, vtDestino, add);
  senalesPagina(red, add);

  // What the page claims to be, and how vendors classify it — the same checks the
  // "what this site is" contrast shows, so the verdict and that conclusion never disagree.
  const dominioPagina = dominioFinal ?? dominio;
  const declarada = marcaDeclarada(red?.pagina);
  if (declarada && dominioPagina && !declarada.dominios.includes(dominioPagina) && !vistos.has('suplanta-marca')) {
    add('dice-ser-marca', 'alerta', `Se presenta como ${declarada.nombre} sin serlo`, `La página dice ser ${declarada.nombre}, pero ${dominioPagina} no le pertenece.`);
  }
  const vtPagina = dominioFinal && dominioFinal !== dominio ? vtDestino : vt;
  const riesgosas = vtPagina?.estado === 'conocido' ? vtPagina.categorias.filter((c) => RIESGOS.some((r) => c.includes(r))) : [];
  if (riesgosas.length && !vistos.has('vt-malicioso') && !vistos.has('destino-malicioso')) {
    add('categoria-riesgo', 'alerta', `Clasificado como ${riesgosas.slice(0, 2).join(' y ')}`, 'Al menos una empresa de seguridad lo clasifica así, aunque los motores no lo marquen como malicioso.');
  }

  senalesUrl(url, dominio, add);
  senalesVisita(red, add);

  return senales.map((s, i) => ({ s, i })).sort((a, b) => ORDEN[a.s.tipo] - ORDEN[b.s.tipo] || a.i - b.i).map(({ s }) => s);
}
