/**
 * Builds the result card in the browser.
 *
 * Layout, top to bottom: the verdict and which link it is about; one sentence of why; a
 * compact grid of the six facts that matter most; the warnings in full, with the good
 * news folded into a single line; and the technical detail behind one button.
 *
 * Everything is created with createElement and text nodes, never innerHTML. The report
 * carries text that ultimately came from somewhere else — a page title, a registrar's
 * name, an engine's label — and none of it may ever be interpreted as markup.
 */

const NIVELES = {
  seguro: { clase: 'seguro', icono: '✅', titulo: 'Enlace seguro' },
  precaucion: { clase: 'precaucion', icono: '⚠️', titulo: 'Requiere precaución' },
  peligroso: { clase: 'peligroso', icono: '❌', titulo: 'Enlace peligroso' },
};
const ICONOS = { peligro: '✕', alerta: '!', bien: '✓', info: 'i' };
const TIPOS = { peligro: 'Peligro', alerta: 'Alerta', bien: 'A favor', info: 'Dato' };
const PESO = { peligro: 3, alerta: 2, bien: 1, info: 0 };

function el(etiqueta, props = {}, ...hijos) {
  const nodo = document.createElement(etiqueta);
  for (const [clave, valor] of Object.entries(props)) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (clave === 'class') nodo.className = valor;
    else nodo.setAttribute(clave, valor);
  }
  // Children can arrive nested (a list of [dt, dd] pairs), so flatten all the way down —
  // a single level turned each pair into the text "[object HTMLElement],[object …]".
  for (const hijo of hijos.flat(Infinity)) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    nodo.append(hijo instanceof Node ? hijo : String(hijo));
  }
  return nodo;
}

const fecha = (iso) => (iso ? new Date(iso).toLocaleDateString('es', { day: 'numeric', month: 'long', year: 'numeric' }) : null);

function edad(iso) {
  if (!iso) return null;
  const dias = Math.floor((Date.now() - new Date(iso)) / 86_400_000);
  if (dias < 1) return 'menos de un día';
  if (dias < 31) return `${dias} ${dias === 1 ? 'día' : 'días'}`;
  if (dias < 365) return `${Math.floor(dias / 30)} ${Math.floor(dias / 30) === 1 ? 'mes' : 'meses'}`;
  const anios = Math.floor(dias / 365);
  return `${anios} ${anios === 1 ? 'año' : 'años'}`;
}

const conEdad = (iso) => (iso ? `${fecha(iso)} (hace ${edad(iso)})` : null);
const hostDe = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
};

/* ---------- Ficha: the six facts at a glance ---------- */

/**
 * Each tile takes its colour from the worst signal about that subject, so the grid and
 * the "why" list can never disagree.
 */
const TEMAS = {
  motores: (id) => id.startsWith('vt-') || id.startsWith('destino-malicioso') || id.startsWith('destino-minoritario'),
  dominio: (id) => id.startsWith('dominio-') || id.startsWith('destino-dominio') || id === 'tld-riesgo' || id === 'punycode' || id.startsWith('marca-'),
  certificado: (id) => id === 'sin-https' || id === 'degrada-https' || id.startsWith('certificado-'),
  destino: (id) => ['redirige-otro-dominio', 'acortador', 'cadena-larga', 'redireccion-pagina', 'respuesta-error'].includes(id),
  servidor: (id) => id === 'red-interna' || id === 'ip-como-dominio' || id === 'puerto',
  pagina: (id) => ['clave-a-otro-dominio', 'suplanta-marca', 'pide-clave'].includes(id),
};

function estadoDe(tema, senales) {
  const relevantes = senales.filter((s) => TEMAS[tema](s.id) && s.tipo !== 'info');
  if (!relevantes.length) return 'neutro';
  return relevantes.reduce((peor, s) => (PESO[s.tipo] > PESO[peor] ? s.tipo : peor), 'bien');
}

function datosFicha(res) {
  const d = res.detalles;
  const r = d.reputacion;
  const v = d.visita;
  const saltos = d.destino.saltos.length;

  const motores =
    r.estado === 'conocido' ? `${r.maliciosos + r.sospechosos} / ${r.total}` : r.estado === 'desconocido' ? 'Sin análisis' : r.estado === 'omitido' ? 'No consultado' : 'Sin datos';

  const dominio = d.dominio?.creado ? edad(d.dominio.creado) : d.dominio ? 'Sin registro público' : 'Es una IP';

  const certificado = d.certificado
    ? d.certificado.valido ? 'Válido' : 'No válido'
    : res.senales.some((s) => s.id === 'sin-https') ? 'Sin HTTPS' : 'Sin datos';

  const destino = d.destino.dominioFinal
    ? `→ ${hostDe(d.destino.urlFinal) ?? d.destino.dominioFinal}`
    : saltos > 1 ? `${saltos - 1} ${saltos === 2 ? 'salto' : 'saltos'}, mismo sitio` : v.visitado ? 'Sin redirecciones' : 'No visitado';

  const servidor = v.bloqueado?.includes('interna')
    ? 'Red interna'
    : d.servidor ? [d.servidor.red ?? d.servidor.ip, d.servidor.pais ? `(${d.servidor.pais})` : null].filter(Boolean).join(' ') : 'Sin datos';

  const pagina = v.prudente
    ? 'No se abrió'
    : d.pagina ? (d.pagina.formulariosConClave || d.pagina.camposClave ? 'Pide contraseña' : 'No pide contraseña') : 'Sin datos';

  return [
    ['motores', 'Motores', motores],
    ['dominio', 'Antigüedad', dominio],
    ['certificado', 'Certificado', certificado],
    ['destino', 'Destino', destino],
    ['servidor', 'Servidor', servidor],
    ['pagina', 'Página', pagina],
  ];
}

function ficha(res) {
  return el(
    'dl',
    { class: 'ficha' },
    datosFicha(res).map(([tema, etiqueta, valor]) =>
      el('div', { class: `ficha-dato ficha-${estadoDe(tema, res.senales)}` }, el('dt', {}, etiqueta), el('dd', {}, valor)),
    ),
  );
}

/* ---------- Por qué: warnings in full, the rest folded ---------- */

const itemSenal = (s) =>
  el(
    'li',
    { class: `senal senal-${s.tipo}` },
    el('span', { class: 'senal-icono', title: TIPOS[s.tipo], 'aria-label': TIPOS[s.tipo] }, ICONOS[s.tipo]),
    el('div', {}, el('strong', {}, s.titulo), s.detalle ? el('p', {}, s.detalle) : null),
  );

function plegado(senales, icono, clase, texto) {
  if (!senales.length) return null;
  return el(
    'details',
    { class: `senales-plegadas ${clase}` },
    el('summary', {}, el('span', { class: 'senal-icono', 'aria-hidden': 'true' }, icono), texto),
    el('ul', { class: 'senales' }, senales.map(itemSenal)),
  );
}

function porQue(senales) {
  const graves = senales.filter((s) => s.tipo === 'peligro' || s.tipo === 'alerta');
  const bienes = senales.filter((s) => s.tipo === 'bien');
  const datos = senales.filter((s) => s.tipo === 'info');
  if (!senales.length) return null;

  return el(
    'section',
    { class: 'informe-porque', 'aria-label': 'Por qué' },
    el('h3', {}, 'Por qué'),
    graves.length ? el('ul', { class: 'senales' }, graves.map(itemSenal)) : null,
    plegado(bienes, ICONOS.bien, 'senal-bien', `${bienes.length} ${bienes.length === 1 ? 'señal' : 'señales'} a favor`),
    plegado(datos, ICONOS.info, 'senal-info', `${datos.length} ${datos.length === 1 ? 'dato más' : 'datos más'}`),
  );
}

/* ---------- Detalles técnicos: everything, behind one button ---------- */

function bloque(titulo, filas) {
  const visibles = filas.filter(([, valor]) => valor !== null && valor !== undefined && valor !== '' && !(Array.isArray(valor) && !valor.length));
  if (!visibles.length) return null;
  return el(
    'section',
    { class: 'tecnico-bloque' },
    el('h4', {}, titulo),
    el(
      'dl',
      {},
      visibles.map(([etiqueta, valor]) => [
        el('dt', {}, etiqueta),
        el('dd', {}, Array.isArray(valor) ? el('ul', {}, valor.map((v) => el('li', {}, v))) : valor),
      ]),
    ),
  );
}

function filasReputacion(r, prefijo = '') {
  if (!r) return [];
  const e = (texto) => `${prefijo}${texto}`;
  if (r.estado === 'desconocido') return [[e('VirusTotal'), 'Sin análisis previos de este enlace']];
  if (r.estado === 'omitido') return [[e('VirusTotal'), 'No se consultó: la extensión ya es de alto riesgo']];
  if (r.estado !== 'conocido') return [[e('VirusTotal'), 'No disponible en este momento']];
  return [
    [e('Motores'), `${r.maliciosos} maliciosos · ${r.sospechosos} sospechosos · ${r.inofensivos} inofensivos, de ${r.total}`],
    [e('Detecciones'), r.detecciones.map((d) => `${d.motor}: ${d.resultado ?? d.categoria}`)],
    [e('Categorías'), r.categorias.join(', ')],
    [e('Votos de la comunidad'), r.votos.inofensivo || r.votos.malicioso ? `${r.votos.inofensivo} inofensivo · ${r.votos.malicioso} malicioso` : null],
    [e('Primer análisis'), conEdad(r.primerEnvio)],
    [e('Último análisis'), conEdad(r.ultimoAnalisis)],
  ];
}

function tecnico(d) {
  const saltos = d.destino.saltos;
  const bloques = [
    bloque('Destino', [
      ['Enlace analizado', d.url],
      ['Recorrido', saltos.length > 1 ? saltos.map((s) => `${s.estado} · ${s.url}`) : null],
      ['Destino final', d.destino.urlFinal && d.destino.urlFinal !== d.url ? d.destino.urlFinal : null],
      // VirusTotal often lists the analysed URL itself, sometimes twice; only show hops that add something.
      ['Redirecciones vistas por VirusTotal', [...new Set(d.destino.redireccionesConocidas)].filter((u) => u !== d.url)],
    ]),
    bloque('Dominio', d.dominio ? [
      ['Dominio', d.dominio.nombre],
      ['Registrado', conEdad(d.dominio.creado)],
      ['Vence', fecha(d.dominio.expira)],
      ['Registrador', d.dominio.registrador],
    ] : []),
    bloque('Certificado', d.certificado ? [
      ['Emitido por', d.certificado.emisor],
      ['Para', d.certificado.sujeto],
      ['Válido desde', fecha(d.certificado.desde)],
      ['Válido hasta', fecha(d.certificado.hasta)],
      ['Estado', d.certificado.valido ? 'Válido' : `No válido (${d.certificado.error})`],
    ] : []),
    bloque('Servidor', d.servidor ? [
      ['IP', d.servidor.ip],
      ['Red', d.servidor.red],
      ['Organización', d.servidor.organizacion],
      ['País', d.servidor.pais],
    ] : []),
    bloque('Reputación', [...filasReputacion(d.reputacion), ...filasReputacion(d.reputacionDestino, 'Destino · ')]),
    bloque('Página', d.pagina ? [
      ['Título', d.pagina.titulo],
      ['Formularios', d.pagina.formularios ? `${d.pagina.formularios} (${d.pagina.formulariosConClave} piden contraseña)` : 'Ninguno'],
      ['Envía contraseñas a', d.pagina.destinosDeClave],
      ['Iframes', d.pagina.iframes || null],
      ['Scripts de otros dominios', d.pagina.scriptsExternos],
    ] : []),
  ].filter(Boolean);

  if (!bloques.length) return null;
  return el('details', { class: 'informe-tecnico' }, el('summary', {}, 'Ver detalles técnicos'), el('div', { class: 'tecnico-cuerpo' }, bloques));
}

/* ---------- The card ---------- */

/** Which link the verdict is about: the host first, since that is who you would be talking to. */
function enlace(url) {
  const host = url ? hostDe(url) : null;
  if (!host) return null;
  return el('p', { class: 'informe-enlace' }, el('strong', {}, host), el('span', {}, url));
}

function nota(res) {
  const v = res.detalles?.visita;
  const partes = [];
  if (v?.prudente) partes.push('El enlace parecía de un solo uso, así que solo se revisó su servidor, sin abrir la página.');
  else if (v?.visitado) partes.push('Shield Link visitó el enlace desde sus servidores, sin tus datos ni cookies, y sin ejecutar su código.');
  else if (v?.bloqueado || v?.error) partes.push(`No se visitó el enlace: ${v.bloqueado ?? v.error}.`);
  if (res.desdeCache && res.analizadoEn) partes.push(`Resultado de un análisis del ${fecha(res.analizadoEn)}.`);
  return partes.length ? el('p', { class: 'informe-nota' }, partes.join(' ')) : null;
}

/** The full report for a verdict. */
export function renderInforme(res) {
  const nivel = NIVELES[res.nivel] ?? (res.seguro ? NIVELES.seguro : NIVELES.peligroso);
  const senales = res.senales ?? [];
  const completo = Boolean(res.detalles);

  // Two groups: what you read first (verdict, link, reason, the facts) and what you open
  // if you want more. On a wide screen they sit side by side so the card fits the window.
  const extra = [porQue(senales), completo ? tecnico(res.detalles) : null].filter(Boolean);

  return el(
    'article',
    { class: `informe informe-${nivel.clase}` },
    el(
      'div',
      { class: 'informe-principal' },
      el(
        'header',
        { class: 'informe-cabecera' },
        el('span', { class: 'informe-icono', 'aria-hidden': 'true' }, nivel.icono),
        el('div', {}, el('h2', {}, nivel.titulo), res.certeza ? el('span', { class: `certeza certeza-${res.certeza}` }, `Certeza ${res.certeza}`) : null),
      ),
      enlace(res.detalles?.url),
      el('p', { class: 'informe-motivo' }, res.motivo),
      completo ? ficha({ ...res, senales }) : null,
      nota(res),
      el('button', { class: 'secondary-btn', id: 'resetBtn', type: 'button' }, 'Escanear otro enlace'),
    ),
    extra.length ? el('div', { class: 'informe-extra' }, extra) : null,
  );
}

/** A format error or a rate limit: no verdict, just what to do next. */
export function renderAviso(res) {
  return el(
    'article',
    { class: 'informe informe-aviso' },
    el(
      'header',
      { class: 'informe-cabecera' },
      el('span', { class: 'informe-icono', 'aria-hidden': 'true' }, res.limite ? '⏳' : 'ℹ️'),
      el('div', {}, el('h2', {}, res.limite ? 'Límite alcanzado' : 'Formato incorrecto')),
    ),
    el('p', { class: 'informe-motivo' }, res.motivo),
    el('button', { class: 'secondary-btn', id: 'resetBtn', type: 'button' }, res.limite ? 'Volver' : 'Corregir enlace'),
  );
}
