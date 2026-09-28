/**
 * Builds the result card in the browser.
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

function el(etiqueta, props = {}, ...hijos) {
  const nodo = document.createElement(etiqueta);
  for (const [clave, valor] of Object.entries(props)) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (clave === 'class') nodo.className = valor;
    else nodo.setAttribute(clave, valor);
  }
  for (const hijo of hijos.flat()) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    nodo.append(hijo instanceof Node ? hijo : String(hijo));
  }
  return nodo;
}

const fecha = (iso) => (iso ? new Date(iso).toLocaleDateString('es', { day: 'numeric', month: 'long', year: 'numeric' }) : null);

function hace(iso) {
  if (!iso) return null;
  const dias = Math.floor((Date.now() - new Date(iso)) / 86_400_000);
  if (dias < 1) return 'hoy';
  if (dias < 31) return `hace ${dias} ${dias === 1 ? 'día' : 'días'}`;
  if (dias < 365) return `hace ${Math.floor(dias / 30)} ${Math.floor(dias / 30) === 1 ? 'mes' : 'meses'}`;
  const anios = Math.floor(dias / 365);
  return `hace ${anios} ${anios === 1 ? 'año' : 'años'}`;
}

const conEdad = (iso) => (iso ? `${fecha(iso)} (${hace(iso)})` : null);

/** A collapsible section of label/value rows. Rows without a value are left out. */
function seccion(titulo, filas, abierta = false) {
  const visibles = filas.filter(([, valor]) => valor !== null && valor !== undefined && valor !== '' && !(Array.isArray(valor) && !valor.length));
  if (!visibles.length) return null;
  return el(
    'details',
    { class: 'informe-seccion', open: abierta ? '' : null },
    el('summary', {}, titulo),
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

function reputacion(r) {
  if (!r) return [];
  if (r.estado === 'desconocido') return [['VirusTotal', 'Sin análisis previos de este enlace']];
  if (r.estado === 'omitido') return [['VirusTotal', 'No se consultó: la extensión ya es de alto riesgo']];
  if (r.estado !== 'conocido') return [['VirusTotal', 'No disponible en este momento']];
  return [
    ['Motores', `${r.maliciosos} maliciosos · ${r.sospechosos} sospechosos · ${r.inofensivos} inofensivos, de ${r.total}`],
    ['Detecciones', r.detecciones.map((d) => `${d.motor}: ${d.resultado ?? d.categoria}`)],
    ['Categorías', r.categorias.join(', ')],
    ['Votos de la comunidad', r.votos.inofensivo || r.votos.malicioso ? `${r.votos.inofensivo} inofensivo · ${r.votos.malicioso} malicioso` : null],
    ['Primer análisis', conEdad(r.primerEnvio)],
    ['Último análisis', conEdad(r.ultimoAnalisis)],
  ];
}

function detalles(d) {
  const saltos = d.destino.saltos;
  const secciones = [
    seccion('Destino', [
      ['Enlace analizado', d.url],
      ['Recorrido', saltos.length > 1 ? saltos.map((s) => `${s.estado} · ${s.url}`) : null],
      ['Destino final', d.destino.urlFinal && d.destino.urlFinal !== d.url ? d.destino.urlFinal : null],
      ['Cambia de dominio a', d.destino.dominioFinal],
      ['Redirecciones vistas por VirusTotal', d.destino.redireccionesConocidas],
    ]),
    seccion('Dominio', d.dominio ? [
      ['Dominio', d.dominio.nombre],
      ['Registrado', conEdad(d.dominio.creado)],
      ['Vence', fecha(d.dominio.expira)],
      ['Registrador', d.dominio.registrador],
    ] : []),
    seccion('Certificado', d.certificado ? [
      ['Emitido por', d.certificado.emisor],
      ['Para', d.certificado.sujeto],
      ['Válido desde', fecha(d.certificado.desde)],
      ['Válido hasta', fecha(d.certificado.hasta)],
      ['Estado', d.certificado.valido ? 'Válido' : `No válido (${d.certificado.error})`],
    ] : []),
    seccion('Servidor', d.servidor ? [
      ['IP', d.servidor.ip],
      ['Red', d.servidor.red],
      ['Organización', d.servidor.organizacion],
      ['País', d.servidor.pais],
    ] : []),
    seccion('Reputación', [...reputacion(d.reputacion), ...reputacion(d.reputacionDestino).map(([e, v]) => [`Destino · ${e}`, v])]),
    seccion('Página', d.pagina ? [
      ['Título', d.pagina.titulo],
      ['Formularios', d.pagina.formularios ? `${d.pagina.formularios} (${d.pagina.formulariosConClave} piden contraseña)` : 'Ninguno'],
      ['Envía contraseñas a', d.pagina.destinosDeClave],
      ['Iframes', d.pagina.iframes || null],
      ['Scripts de otros dominios', d.pagina.scriptsExternos],
    ] : []),
  ];
  return secciones.filter(Boolean);
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

  return el(
    'article',
    { class: `informe informe-${nivel.clase}` },
    el(
      'header',
      { class: 'informe-cabecera' },
      el('span', { class: 'informe-icono', 'aria-hidden': 'true' }, nivel.icono),
      el('div', {}, el('h2', {}, nivel.titulo), res.certeza ? el('span', { class: `certeza certeza-${res.certeza}` }, `Certeza ${res.certeza}`) : null),
    ),
    el('p', { class: 'informe-motivo' }, res.motivo),
    senales.length
      ? el(
          'section',
          { class: 'informe-porque', 'aria-label': 'Por qué' },
          el('h3', {}, 'Por qué'),
          el(
            'ul',
            { class: 'senales' },
            senales.map((s) =>
              el(
                'li',
                { class: `senal senal-${s.tipo}` },
                el('span', { class: 'senal-icono', title: TIPOS[s.tipo], 'aria-label': TIPOS[s.tipo] }, ICONOS[s.tipo]),
                el('div', {}, el('strong', {}, s.titulo), s.detalle ? el('p', {}, s.detalle) : null),
              ),
            ),
          ),
        )
      : null,
    res.detalles ? el('div', { class: 'informe-detalles' }, detalles(res.detalles)) : null,
    nota(res),
    el('button', { class: 'secondary-btn', id: 'resetBtn', type: 'button' }, 'Escanear otro enlace'),
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
