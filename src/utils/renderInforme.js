/**
 * Builds the result card in the browser.
 *
 * Organised around the question the user actually has — "can I open this?" — and around
 * saying each thing once:
 *
 *   left   the answer in plain words, the link, one sentence of why, and a way to open it;
 *          what the site is and whether that holds up; four facts at a glance.
 *   right  why engines flag it, when they do; what counts against it; what counts in its
 *          favour and the remaining facts, folded; the technical detail, folded.
 *
 * Everything is created with createElement and text nodes, never innerHTML. The report
 * carries text that ultimately came from somewhere else — a page title, a description, an
 * engine's label — and none of it may ever be interpreted as markup.
 */

const NIVELES = {
  seguro: { clase: 'seguro', icono: '✅', abrir: 'Abrir sitio' },
  precaucion: { clase: 'precaucion', icono: '⚠️', abrir: 'Abrir con cuidado' },
  peligroso: { clase: 'peligroso', icono: '⛔', abrir: 'Abrir de todos modos' },
};
const ICONOS = { peligro: '✕', alerta: '!', bien: '✓', info: 'i' };
const TIPOS = { peligro: 'Peligro', alerta: 'Alerta', bien: 'A favor', info: 'Dato' };
const PESO = { peligro: 3, alerta: 2, bien: 1, info: 0 };
/** Signals the "why engines flag it" block already explains in full. */
const EXPLICADAS = new Set(['vt-malicioso', 'vt-minoritario', 'vt-falso-positivo', 'destino-malicioso', 'destino-minoritario']);

function el(etiqueta, props = {}, ...hijos) {
  const nodo = document.createElement(etiqueta);
  for (const [clave, valor] of Object.entries(props)) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (clave === 'class') nodo.className = valor;
    else nodo.setAttribute(clave, valor);
  }
  // Children can arrive nested (a list of [dt, dd] pairs), so flatten all the way down.
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

/* ---------- Opening the site, with a confirmation that matches the verdict ---------- */

function dialogoAbrir(res, urlAbrir) {
  const host = hostDe(urlAbrir) ?? urlAbrir;
  const riesgo = (res.senales ?? []).find((s) => s.tipo === 'peligro') ?? (res.senales ?? []).find((s) => s.tipo === 'alerta');
  const confirmar = el('button', { type: 'button', class: `boton-abrir boton-${res.nivel}` }, 'Abrir ↗');
  const cancelar = el('button', { type: 'button', class: 'secondary-btn', autofocus: '' }, 'Cancelar');

  const cuerpo = [];
  if (res.nivel === 'seguro') {
    cuerpo.push(el('p', {}, `Se abrirá ${host} en una pestaña nueva.`));
  } else if (res.nivel === 'precaucion') {
    cuerpo.push(
      el('p', {}, riesgo ? `Shield Link encontró esto: ${riesgo.titulo}.` : 'Shield Link encontró motivos para tener cuidado.'),
      el('p', {}, 'Ábrelo solo si confías en quien te lo envió, y no escribas contraseñas ni datos de pago en él.'),
    );
  } else {
    const casilla = el('input', { type: 'checkbox', id: 'entiendo-riesgo' });
    confirmar.disabled = true;
    casilla.addEventListener('change', () => (confirmar.disabled = !casilla.checked));
    cuerpo.push(
      el('p', {}, riesgo ? `${riesgo.titulo}.` : 'Este enlace es peligroso.'),
      el('p', {}, 'Abrirlo puede exponerte al robo de tus cuentas o a software malicioso. Si alguien te lo envió pidiéndote que entres rápido, es una señal más de engaño.'),
      el('label', { class: 'dialogo-casilla', for: 'entiendo-riesgo' }, casilla, 'Entiendo el riesgo y quiero abrirlo igual'),
    );
  }

  const titulo = { seguro: 'Vas a salir de Shield Link', precaucion: 'Antes de abrirlo', peligroso: 'Este enlace es peligroso' }[res.nivel];
  const dialogo = el(
    'dialog',
    { class: `dialogo dialogo-${res.nivel}`, 'aria-labelledby': 'dialogo-titulo' },
    el('h3', { id: 'dialogo-titulo' }, titulo),
    el('p', { class: 'dialogo-url' }, urlAbrir),
    cuerpo,
    el('div', { class: 'dialogo-acciones' }, cancelar, confirmar),
  );
  cancelar.addEventListener('click', () => dialogo.close());
  confirmar.addEventListener('click', () => {
    // noopener: the opened page gets no handle back to this one.
    window.open(urlAbrir, '_blank', 'noopener,noreferrer');
    dialogo.close();
  });
  dialogo.addEventListener('close', () => dialogo.remove());
  return dialogo;
}

/* ---------- Left: the answer ---------- */

function cabecera(res, nivel, urlAbrir) {
  const host = hostDe(res.detalles?.url ?? '');
  const abrir = urlAbrir
    ? el('button', { type: 'button', class: `boton-abrir boton-${res.nivel}` }, `${nivel.abrir} ↗`)
    : null;
  abrir?.addEventListener('click', () => {
    const dialogo = dialogoAbrir(res, urlAbrir);
    document.body.append(dialogo);
    dialogo.showModal();
  });

  return el(
    'section',
    { class: 'respuesta' },
    el(
      'header',
      { class: 'informe-cabecera' },
      el('span', { class: 'informe-icono', 'aria-hidden': 'true' }, nivel.icono),
      el('div', {}, el('h2', {}, res.recomendacion ?? res.nivel), res.certeza ? el('span', { class: `certeza certeza-${res.certeza}` }, `Certeza ${res.certeza}`) : null),
    ),
    host ? el('p', { class: 'informe-enlace' }, el('strong', {}, host), el('span', {}, res.detalles.url)) : null,
    el('p', { class: 'informe-motivo' }, res.motivo),
    el('div', { class: 'acciones' }, abrir, el('button', { class: 'secondary-btn', id: 'resetBtn', type: 'button' }, 'Escanear otro enlace')),
  );
}

const ICONO_CONCLUSION = { coherente: '✓', dudoso: '!', 'no-cuadra': '✕', 'sin-datos': 'i' };

/** What the site says it is, and whether independent evidence backs it up. */
function queEs(res) {
  const s = res.sitio;
  if (!s || (!s.dice && !s.titulo && !s.puntos.length && !s.categorias.length)) return null;
  const quien = s.dice
    ? el('p', { class: 'sitio-dice' }, el('span', { class: 'sitio-fuente' }, `Según ${s.nombre ? `${s.nombre}, ` : 'la propia página, '}`), `“${s.dice}”`)
    : s.titulo
      ? el('p', { class: 'sitio-dice' }, el('span', { class: 'sitio-fuente' }, 'Se presenta como '), `“${s.titulo}”`)
      : null;

  return el(
    'section',
    { class: 'sitio', 'aria-label': 'Qué es este sitio' },
    el('h3', {}, 'Qué es este sitio'),
    quien,
    el('p', { class: `sitio-conclusion sitio-${s.estado}` }, el('span', { class: 'senal-icono', 'aria-hidden': 'true' }, ICONO_CONCLUSION[s.estado]), s.conclusion),
    s.puntos.length || s.categorias.length
      ? el(
          'details',
          { class: 'sitio-comprobacion' },
          el('summary', {}, 'Cómo se comprobó'),
          s.puntos.length ? el('ul', { class: 'sitio-puntos' }, s.puntos.map((p) => el('li', { class: `punto-${p.tipo}` }, p.texto))) : null,
          s.categorias.length ? el('p', { class: 'sitio-categorias' }, s.categorias.map((c) => el('span', { class: 'etiqueta' }, c))) : null,
        )
      : null,
  );
}

/* ---------- The four facts ---------- */

const TEMAS = {
  popularidad: (id) => ['popular', 'conocido', 'plataforma-abierta'].includes(id),
  antiguedad: (id) => id.startsWith('dominio-') || id.startsWith('destino-dominio') || id === 'vt-antiguo',
  conexion: (id) => id === 'sin-https' || id === 'degrada-https' || id.startsWith('certificado-'),
  motores: (id) => id.startsWith('vt-') || id.startsWith('destino-malicioso') || id.startsWith('destino-minoritario'),
  destino: (id) => ['redirige-otro-dominio', 'acortador', 'cadena-larga'].includes(id),
  pagina: (id) => ['clave-a-otro-dominio', 'suplanta-marca', 'pide-clave', 'dice-ser-marca'].includes(id),
};

function estadoDe(tema, senales) {
  const relevantes = senales.filter((s) => TEMAS[tema](s.id) && s.tipo !== 'info');
  if (!relevantes.length) return 'neutro';
  return relevantes.reduce((peor, s) => (PESO[s.tipo] > PESO[peor] ? s.tipo : peor), 'bien');
}

function ficha(res) {
  const d = res.detalles;
  const r = d.reputacion;
  const pop = d.popularidad;
  const senales = res.senales;
  const plataforma = senales.some((s) => s.id === 'plataforma-abierta');

  const popularidad = plataforma
    ? 'Plataforma abierta'
    : !pop ? 'Sin datos' : pop.rank === 1 ? '#1 mundial' : pop.rank ? `#${pop.rank.toLocaleString('es')} mundial` : 'Poco conocido';
  const antiguedad = d.dominio?.creado ? edad(d.dominio.creado) : r.primerEnvio ? `Visto hace ${edad(r.primerEnvio)}` : d.dominio ? 'Sin registro público' : 'Es una IP';
  const conexion = d.certificado ? (d.certificado.valido ? 'Cifrada' : 'Certificado inválido') : senales.some((s) => s.id === 'sin-https') ? 'Sin cifrar' : 'Sin datos';
  const motores = r.estado === 'conocido' ? `${r.maliciosos + r.sospechosos} / ${r.total}` : r.estado === 'desconocido' ? 'Sin análisis' : r.estado === 'omitido' ? 'No consultado' : 'Sin datos';

  const datos = [
    ['popularidad', 'Popularidad', popularidad],
    ['antiguedad', 'Antigüedad', antiguedad],
    ['conexion', 'Conexión', conexion],
    ['motores', 'Motores', motores],
  ];
  // Only when they add something: where it really goes, and whether it asks for a password.
  if (d.destino.dominioFinal) datos.push(['destino', 'Lleva a', hostDe(d.destino.urlFinal) ?? d.destino.dominioFinal]);
  if (d.pagina?.camposClave || d.visita?.prudente) datos.push(['pagina', 'Página', d.visita?.prudente ? 'No se abrió' : 'Pide contraseña']);

  return el(
    'dl',
    { class: 'ficha' },
    datos.map(([tema, etiqueta, valor]) => el('div', { class: `ficha-dato ficha-${estadoDe(tema, senales)}` }, el('dt', {}, etiqueta), el('dd', {}, valor))),
  );
}

/* ---------- Right: the explanation ---------- */

const METODO = { blacklist: 'por lista', 'pattern-matching': 'por patrón', heuristic: 'heurístico' };

function porQueLoMarcan(res) {
  const d = res.detecciones;
  if (!d) return null;
  return el(
    'section',
    { class: `detecciones detecciones-${d.interpretacion}`, 'aria-label': 'Detecciones' },
    el('h3', {}, d.titulo),
    el('p', {}, d.texto),
    el(
      'ul',
      { class: 'detecciones-motores' },
      d.motores.map((m) => el('li', {}, el('strong', {}, m.motor), ` · ${m.resultado ?? m.categoria}${METODO[m.metodo] ? ` · ${METODO[m.metodo]}` : ''}`)),
    ),
  );
}

const itemSenal = (s, conDetalle = true) =>
  el(
    'li',
    { class: `senal senal-${s.tipo}` },
    el('span', { class: 'senal-icono', title: TIPOS[s.tipo], 'aria-label': TIPOS[s.tipo] }, ICONOS[s.tipo]),
    el('div', {}, el('strong', {}, s.titulo), conDetalle && s.detalle ? el('p', {}, s.detalle) : null),
  );

function plegado(senales, icono, clase, texto) {
  if (!senales.length) return null;
  return el(
    'details',
    { class: `senales-plegadas ${clase}` },
    el('summary', {}, el('span', { class: 'senal-icono', 'aria-hidden': 'true' }, icono), texto),
    el('ul', { class: 'senales' }, senales.map((s) => itemSenal(s))),
  );
}

function hallazgos(res) {
  const senales = res.senales ?? [];
  const explicadas = res.detecciones ? EXPLICADAS : new Set();
  const enContra = senales.filter((s) => (s.tipo === 'peligro' || s.tipo === 'alerta') && !explicadas.has(s.id));
  const aFavor = senales.filter((s) => s.tipo === 'bien');
  const datos = senales.filter((s) => s.tipo === 'info' && !explicadas.has(s.id));
  if (!enContra.length && !aFavor.length && !datos.length) return null;

  return el(
    'section',
    { class: 'hallazgos', 'aria-label': 'Hallazgos' },
    enContra.length ? [el('h3', {}, `En contra (${enContra.length})`), el('ul', { class: 'senales' }, enContra.map((s) => itemSenal(s)))] : el('h3', {}, 'En contra (0)'),
    plegado(aFavor, ICONOS.bien, 'senal-bien', `A favor (${aFavor.length})`),
    plegado(datos, ICONOS.info, 'senal-info', `Otros datos (${datos.length})`),
  );
}

/* ---------- Technical detail ---------- */

function bloque(titulo, filas) {
  const visibles = filas.filter(([, valor]) => valor !== null && valor !== undefined && valor !== '' && !(Array.isArray(valor) && !valor.length));
  if (!visibles.length) return null;
  return el(
    'section',
    { class: 'tecnico-bloque' },
    el('h4', {}, titulo),
    el('dl', {}, visibles.map(([etiqueta, valor]) => [el('dt', {}, etiqueta), el('dd', {}, Array.isArray(valor) ? el('ul', {}, valor.map((v) => el('li', {}, v))) : valor)])),
  );
}

function tecnico(res) {
  const d = res.detalles;
  const saltos = d.destino.saltos;
  const r = d.reputacion;
  const bloques = [
    bloque('Recorrido del enlace', [
      ['Enlace analizado', d.url],
      ['Saltos', saltos.length > 1 ? saltos.map((s) => `${s.estado} · ${s.url}`) : null],
      ['Destino final', d.destino.urlFinal && d.destino.urlFinal !== d.url ? d.destino.urlFinal : null],
    ]),
    bloque('Registro del dominio', d.dominio ? [
      ['Dominio', d.dominio.nombre],
      ['Registrado', conEdad(d.dominio.creado)],
      ['Vence', fecha(d.dominio.expira)],
      ['Registrador', d.dominio.registrador],
    ] : []),
    bloque('Certificado', d.certificado ? [
      ['Emitido por', d.certificado.emisor],
      ['Para', d.certificado.sujeto],
      ['Vigencia', `${fecha(d.certificado.desde)} al ${fecha(d.certificado.hasta)}`],
      ['Estado', d.certificado.valido ? 'Válido' : `No válido (${d.certificado.error})`],
    ] : []),
    bloque('Servidor', d.servidor ? [
      ['IP', d.servidor.ip],
      ['Red', [d.servidor.red, d.servidor.organizacion].filter(Boolean).join(' · ') || null],
      ['País', d.servidor.pais],
    ] : []),
    bloque('VirusTotal', r.estado === 'conocido' ? [
      ['Resultado', `${r.maliciosos} maliciosos · ${r.sospechosos} sospechosos · ${r.inofensivos} inofensivos, de ${r.total}`],
      ['Primer análisis', conEdad(r.primerEnvio)],
      ['Último análisis', conEdad(r.ultimoAnalisis)],
      ['Votos de la comunidad', r.votos.inofensivo || r.votos.malicioso ? `${r.votos.inofensivo} inofensivo · ${r.votos.malicioso} malicioso` : null],
    ] : []),
    bloque('Página', d.pagina ? [
      ['Título', d.pagina.titulo],
      ['Formularios', d.pagina.formularios ? `${d.pagina.formularios} (${d.pagina.formulariosConClave} piden contraseña)` : 'Ninguno'],
      ['Envía contraseñas a', d.pagina.destinosDeClave],
      ['Scripts de otros dominios', d.pagina.scriptsExternos.length ? `${d.pagina.scriptsExternos.length}: ${d.pagina.scriptsExternos.slice(0, 5).join(', ')}` : null],
    ] : []),
  ].filter(Boolean);

  const virustotal = el(
    'a',
    { class: 'enlace-externo', href: `https://www.virustotal.com/gui/search/${encodeURIComponent(d.url)}`, target: '_blank', rel: 'noopener noreferrer' },
    'Ver en VirusTotal ↗',
  );
  return el(
    'details',
    { class: 'informe-tecnico' },
    el('summary', {}, 'Detalles técnicos'),
    el('div', { class: 'tecnico-cuerpo' }, bloques, virustotal),
  );
}

function nota(res) {
  const v = res.detalles?.visita;
  const partes = [];
  if (res.esquemaAsumido) partes.push('Analizado como https://.');
  if (v?.prudente) partes.push('Enlace de un solo uso: solo se revisó su servidor.');
  else if (v?.visitado) partes.push('Visitado desde los servidores de Shield Link, sin tus datos y sin ejecutar su código.');
  else if (v?.bloqueado || v?.error) partes.push(`No se visitó: ${v.bloqueado ?? v.error}.`);
  if (res.desdeCache && res.analizadoEn) partes.push(`Análisis del ${fecha(res.analizadoEn)}.`);
  return partes.length ? el('p', { class: 'informe-nota' }, partes.join(' ')) : null;
}

/* ---------- The card ---------- */

/** The full report. `urlAbrir` is the link exactly as entered, for the open button. */
export function renderInforme(res, { urlAbrir = null } = {}) {
  const nivel = NIVELES[res.nivel] ?? (res.seguro ? NIVELES.seguro : NIVELES.peligroso);
  const completo = Boolean(res.detalles);
  const extra = [porQueLoMarcan(res), hallazgos(res), completo ? tecnico(res) : null, nota(res)].filter(Boolean);

  return el(
    'article',
    { class: `informe informe-${nivel.clase}` },
    el('div', { class: 'informe-principal' }, cabecera(res, nivel, urlAbrir), queEs(res), completo ? ficha(res) : null),
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
      el('div', {}, el('h2', {}, res.limite ? 'Límite alcanzado' : 'Revisa el enlace')),
    ),
    el('p', { class: 'informe-motivo' }, res.motivo),
    el('button', { class: 'secondary-btn', id: 'resetBtn', type: 'button' }, res.limite ? 'Volver' : 'Corregir enlace'),
  );
}
