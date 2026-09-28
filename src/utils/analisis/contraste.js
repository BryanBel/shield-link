import { MARCAS } from './datos.js';

/**
 * Checks what a site says about itself against evidence it does not control.
 *
 * A page's description is written by whoever runs it — on a phishing page, by the
 * attacker. So it is never taken at its word, and never fed to anything that could be
 * talked into repeating it: these are fixed rules over independent facts. The claim is
 * compared with who owns the domain, how security vendors classify the site, and how long
 * the domain has existed, and the conclusion says whether the claim holds up.
 *
 * Pure: no network. A point is { tipo: 'bien' | 'alerta' | 'peligro' | 'info', texto }.
 */

const normalizar = (texto) => texto.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const escapar = (texto) => texto.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const tiene = (texto, clave) => new RegExp(`\\b${escapar(normalizar(clave))}`).test(texto);

export function marcaEnTexto(texto) {
  if (!texto) return null;
  const t = normalizar(texto);
  return MARCAS.find((m) => m.claves.some((c) => new RegExp(`\\b${escapar(normalizar(c))}\\b`).test(t))) ?? null;
}

/**
 * The brand a page claims to be — not one it merely mentions. og:site_name is an explicit
 * claim; in a title only a short segment counts ("PayPal: Inicia sesión", "Banesco
 * Online"), so a headline like "Apple lanza un iPhone | El País" is not mistaken for one.
 */
export function marcaDeclarada(pagina) {
  if (!pagina) return null;
  const propia = marcaEnTexto(pagina.nombreSitio);
  if (propia) return propia;
  for (const segmento of (pagina.titulo ?? '').split(/\s[|\-–—·:]\s|:\s/)) {
    if (segmento.trim().split(/\s+/).length <= 3) {
      const marca = marcaEnTexto(segmento);
      if (marca) return marca;
    }
  }
  return null;
}

/** What a text is about, in broad strokes: the same themes for a description and for vendor categories. */
const TEMAS = [
  { nombre: 'banca y finanzas', claves: ['bank', 'banco', 'banca', 'financ', 'pago', 'payment', 'wallet', 'billetera', 'crypto', 'cripto', 'exchange', 'broker', 'invest', 'inversion'] },
  { nombre: 'compras', claves: ['shop', 'tienda', 'store', 'compra', 'ecommerce', 'marketplace', 'retail', 'venta'] },
  { nombre: 'redes sociales', claves: ['social', 'community', 'comunidad', 'chat', 'messag', 'mensajer'] },
  { nombre: 'noticias', claves: ['news', 'noticia', 'periodic', 'diario', 'magazine', 'revista', 'prensa'] },
  { nombre: 'tecnología', claves: ['technolog', 'tecnolog', 'software', 'developer', 'desarroll', 'programa', 'code', 'codigo', 'computer', 'cloud', 'hosting', 'web applications', 'open source'] },
  { nombre: 'educación', claves: ['educat', 'educacion', 'universi', 'curso', 'course', 'learn', 'aprend', 'escuela', 'school', 'reference', 'encyclop', 'enciclop'] },
  { nombre: 'búsqueda', claves: ['search engine', 'buscador', 'portal'] },
  { nombre: 'video y música', claves: ['video', 'streaming', 'music', 'musica', 'movie', 'pelicula', 'entertainment', 'entretenimiento'] },
  { nombre: 'gobierno', claves: ['government', 'gobierno', 'ministerio'] },
  { nombre: 'correo', claves: ['email', 'e-mail', 'correo', 'webmail'] },
  { nombre: 'juegos', claves: ['game', 'juego', 'gaming'] },
  { nombre: 'salud', claves: ['health', 'salud', 'medic', 'hospital', 'clinic'] },
  { nombre: 'viajes', claves: ['travel', 'viaje', 'hotel', 'flight', 'vuelo'] },
];

/** Vendor categories that are a verdict in themselves. */
export const RIESGOS = ['phishing', 'malware', 'malicious', 'fraud', 'scam', 'suspicious', 'spam', 'parked', 'newly registered', 'compromised', 'botnet', 'spyware', 'cryptomining'];

const temasDe = (texto) => {
  if (!texto) return [];
  const t = normalizar(texto);
  return TEMAS.filter((tema) => tema.claves.some((c) => tiene(t, c))).map((tema) => tema.nombre);
};

const DIA = 86_400_000;
function edad(dias) {
  if (dias < 31) return dias === 1 ? '1 día' : `${dias} días`;
  if (dias < 365) return `${Math.floor(dias / 30)} ${Math.floor(dias / 30) === 1 ? 'mes' : 'meses'}`;
  const anios = Math.floor(dias / 365);
  return anios === 1 ? '1 año' : `${anios} años`;
}

const lista = (partes) => (partes.length < 2 ? partes.join('') : `${partes.slice(0, -1).join(', ')} y ${partes.at(-1)}`);

export function contrastar({ dominio = null, pagina = null, vt = null, rdap = null, ahora = new Date() }) {
  const categorias = vt?.estado === 'conocido' ? vt.categorias : [];
  const dice = pagina?.descripcion ?? null;
  const nombre = pagina?.nombreSitio ?? null;
  // Without a description, the title is still how the page presents itself.
  const titulo = pagina?.titulo ?? null;
  const puntos = [];

  // Identity: who it says it is, against who owns the domain.
  const marca = marcaDeclarada(pagina);
  if (marca && dominio) {
    const pideClave = (pagina?.camposClave ?? 0) > 0;
    if (marca.dominios.includes(dominio)) {
      puntos.push({ tipo: 'bien', texto: `Dice ser ${marca.nombre}, y ${dominio} sí es un dominio de ${marca.nombre}.` });
    } else {
      puntos.push({ tipo: 'peligro', texto: `Dice ser ${marca.nombre}, pero ${dominio} no pertenece a ${marca.nombre}${pideClave ? ', y pide una contraseña' : ''}.` });
    }
  }

  // Activity: what it says it does, against how security vendors classify it.
  const riesgos = categorias.filter((c) => RIESGOS.some((r) => normalizar(c).includes(r)));
  const temasDice = temasDe([nombre, pagina?.titulo, dice].filter(Boolean).join(' '));
  const temasCategorias = temasDe(categorias.join(' '));
  if (riesgos.length) {
    puntos.push({ tipo: 'peligro', texto: `Empresas de seguridad lo clasifican como ${lista(riesgos)}.` });
  } else if (temasDice.length && temasCategorias.length) {
    const comunes = temasDice.filter((t) => temasCategorias.includes(t));
    if (comunes.length) {
      puntos.push({ tipo: 'bien', texto: `Lo que dice hacer (${lista(comunes)}) coincide con cómo lo clasifican las empresas de seguridad.` });
    } else {
      puntos.push({ tipo: 'alerta', texto: `Dice dedicarse a ${lista(temasDice)}, pero lo clasifican como ${lista(categorias.slice(0, 3))}.` });
    }
  } else if (categorias.length) {
    puntos.push({ tipo: 'info', texto: `Las empresas de seguridad lo clasifican como ${lista(categorias.slice(0, 3))}.` });
  }

  // Track record: how long there has been for anyone to notice if it were lying.
  const dias = rdap?.creado ? Math.floor((ahora - new Date(rdap.creado)) / DIA) : null;
  const conocido = vt?.primerEnvio ? Math.floor((ahora - new Date(vt.primerEnvio)) / DIA) : null;
  if (dias !== null && dias < 30) {
    puntos.push({ tipo: 'alerta', texto: `El dominio tiene apenas ${edad(dias)}: no hay historia que respalde lo que dice.` });
  } else if (dias !== null && dias >= 365) {
    puntos.push({ tipo: 'bien', texto: `El dominio tiene ${edad(dias)} de historia.` });
  } else if (dias === null && conocido !== null && conocido >= 365) {
    puntos.push({ tipo: 'bien', texto: `VirusTotal lo conoce desde hace ${edad(conocido)}.` });
  }

  const hay = (tipo) => puntos.some((p) => p.tipo === tipo);
  let estado;
  let conclusion;
  if (hay('peligro')) {
    estado = 'no-cuadra';
    conclusion = 'Lo que dice de sí mismo no cuadra con la evidencia: no te fíes de su descripción.';
  } else if (hay('alerta')) {
    estado = 'dudoso';
    conclusion = 'Parte de lo que dice no se puede confirmar o no coincide con la evidencia.';
  } else if (hay('bien')) {
    estado = 'coherente';
    conclusion = dice || nombre || titulo ? 'Lo que dice de sí mismo cuadra con la evidencia independiente.' : 'La evidencia independiente respalda al sitio, aunque no dice nada de sí mismo.';
  } else {
    estado = 'sin-datos';
    conclusion = 'No hay suficiente evidencia independiente para confirmar lo que dice.';
  }

  return { nombre, dice, titulo, categorias, puntos, estado, conclusion };
}
