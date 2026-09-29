import { ESTILOS } from '../styles/estilos/registro.js';

/**
 * Style and colour-mode switching in the browser.
 *
 * The page wears one of the styles in registro.js, set as data-estilo / data-modo on
 * <html>. A tiny inline script in Layout.astro applies the saved choice before first paint;
 * this module handles everything after:
 *
 * - The dice. Pressing it grows the next style out of the button in a circle, then the
 *   button hops to a random free spot on the screen. On a phone it stays put, centred under
 *   the card (base.css): there is no free room beside the card to hop to.
 * - The easter egg. The Konami code (↑↑↓↓←→←→BA), or seven taps on the shield on a phone,
 *   opens a chest in the middle of the screen. The prize: a style bar that takes the dice's
 *   place, bottom centre — current style, the full list, and light mode, which does not
 *   exist until then. The prize lasts for the visit: after a reload the page is dark again,
 *   the dice is back and the bar needs the code.
 *
 * Only the chosen style is remembered. localStorage can be unavailable (private windows,
 * blocked storage); every access is guarded, so the page still works and simply forgets.
 */

const CLAVES = { estilo: 'shieldlink:estilo' };
const KONAMI = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];
const TOQUES = 7;
const VENTANA_TOQUES_MS = 3000;
const DURACION_ONDA_MS = 750;
const MARGEN = 16;

const raiz = document.documentElement;
const menosMovimiento = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const leer = (clave) => {
  try {
    return localStorage.getItem(clave);
  } catch {
    return null;
  }
};
const guardar = (clave, valor) => {
  try {
    localStorage.setItem(clave, valor);
  } catch {
    /* sin almacenamiento: el cambio vale solo para esta visita */
  }
};
let premiado = false;
const nombreDe = (id) => ESTILOS.find((e) => e.id === id)?.nombre ?? id;

/* ---------- Applying ---------- */

function aplicarEstilo(id) {
  if (!ESTILOS.some((e) => e.id === id)) return;
  raiz.dataset.estilo = id;
  guardar(CLAVES.estilo, id);
  actualizarBarra();
}

function aplicarModo(modo) {
  // Light mode is part of the prize.
  if (modo === 'claro' && !premiado) return;
  raiz.dataset.modo = modo;
  actualizarBarra();
}

/**
 * Runs `cambio` inside a view transition whose new state grows out of `origen` as a circle.
 * Without the View Transitions API, or for anyone who asked for reduced motion, the change
 * simply happens.
 */
async function ondaDesde(origen, cambio) {
  if (!document.startViewTransition || menosMovimiento()) {
    cambio();
    return;
  }
  const caja = origen.getBoundingClientRect();
  const x = caja.left + caja.width / 2;
  const y = caja.top + caja.height / 2;
  const radio = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));

  const transicion = document.startViewTransition(cambio);
  try {
    await transicion.ready;
    raiz.animate(
      { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radio}px at ${x}px ${y}px)`] },
      { duration: DURACION_ONDA_MS, easing: 'cubic-bezier(0.65, 0, 0.35, 1)', pseudoElement: '::view-transition-new(root)' },
    );
    await transicion.finished;
  } catch {
    /* una transición interrumpida igual deja aplicado el cambio */
  }
}

/* ---------- The dice ---------- */

/** Where the dice sits, as fractions of the free width and height, so a resize keeps it in place. */
let posicionDado = null;

const solapa = (a, b, holgura) =>
  a.x < b.right + holgura && a.x + a.lado > b.left - holgura && a.y < b.bottom + holgura && a.y + a.lado > b.top - holgura;

/**
 * A random spot that does not cover the card and lands far enough from the previous one
 * that the hop is obvious. No grid: every hop is a fresh throw. If only near spots are
 * free, the first free one wins. If the card leaves no room at all — a long report in a
 * narrow window — the dice goes to a corner, where a floating button is expected, rather
 * than anywhere on top of the text.
 */
function lugarAlAzar(dado) {
  const lado = dado.offsetWidth || 52;
  const ancho = innerWidth - lado - 2 * MARGEN;
  const alto = innerHeight - lado - 2 * MARGEN;
  const obstaculos = [document.querySelector('main')].filter(Boolean).map((e) => e.getBoundingClientRect());
  const anterior = posicionDado ? { x: MARGEN + posicionDado.fx * ancho, y: MARGEN + posicionDado.fy * alto } : null;
  const distanciaMinima = Math.min(innerWidth, innerHeight) * 0.35;

  let mejor = null;
  for (let intento = 0; intento < 80; intento++) {
    const punto = { x: MARGEN + Math.random() * ancho, y: MARGEN + Math.random() * alto, lado };
    const libre = !obstaculos.some((o) => solapa(punto, o, 12));
    const lejos = !anterior || Math.hypot(punto.x - anterior.x, punto.y - anterior.y) >= distanciaMinima;
    if (libre && lejos) return punto;
    if (libre && !mejor) mejor = punto;
  }
  if (mejor) return mejor;
  const esquinas = [[MARGEN + ancho, MARGEN + alto], [MARGEN, MARGEN + alto], [MARGEN + ancho, MARGEN]];
  const [x, y] = esquinas[Math.floor(Math.random() * esquinas.length)];
  return { x, y, lado };
}

function colocarDado(punto) {
  const dado = document.getElementById('btnDado');
  if (!dado) return;
  const ancho = Math.max(1, innerWidth - punto.lado - 2 * MARGEN);
  const alto = Math.max(1, innerHeight - punto.lado - 2 * MARGEN);
  posicionDado = { fx: (punto.x - MARGEN) / ancho, fy: (punto.y - MARGEN) / alto };
  dado.style.setProperty('--x', `${punto.x}px`);
  dado.style.setProperty('--y', `${punto.y}px`);
}

function saltarDado() {
  const dado = document.getElementById('btnDado');
  if (dado) colocarDado(lugarAlAzar(dado));
}

/** On resize, keep the same relative spot; if the card now covers it, throw again. */
function reubicarDado() {
  const dado = document.getElementById('btnDado');
  if (!dado || !posicionDado) return;
  const lado = dado.offsetWidth || 52;
  const punto = {
    x: MARGEN + posicionDado.fx * (innerWidth - lado - 2 * MARGEN),
    y: MARGEN + posicionDado.fy * (innerHeight - lado - 2 * MARGEN),
    lado,
  };
  const main = document.querySelector('main')?.getBoundingClientRect();
  colocarDado(main && solapa(punto, main, 12) ? lugarAlAzar(dado) : punto);
}

async function tirarDado() {
  const dado = document.getElementById('btnDado');
  if (!dado || dado.disabled) return;
  dado.disabled = true;
  const otros = ESTILOS.filter((e) => e.id !== raiz.dataset.estilo);
  const elegido = otros[Math.floor(Math.random() * otros.length)];
  await ondaDesde(dado, () => aplicarEstilo(elegido.id));
  saltarDado();
  // Let the hop finish before it can be pressed again.
  setTimeout(() => (dado.disabled = false), menosMovimiento() ? 0 : 500);
}

/* ---------- The style bar (the prize) ---------- */

let barra = null;

function crearBarra() {
  const contenedor = document.createElement('div');
  contenedor.className = 'barra-estilos';

  const boton = document.createElement('button');
  boton.type = 'button';
  boton.className = 'barra-boton';
  boton.setAttribute('aria-expanded', 'false');
  boton.setAttribute('aria-controls', 'panel-estilos');
  const etiqueta = document.createElement('span');
  etiqueta.textContent = 'Estilo';
  const actual = document.createElement('strong');
  actual.className = 'barra-actual';
  const flecha = document.createElement('span');
  flecha.className = 'barra-flecha';
  flecha.setAttribute('aria-hidden', 'true');
  flecha.textContent = '▴'; // the list opens upwards
  boton.append(etiqueta, actual, flecha);

  const panel = document.createElement('div');
  panel.className = 'panel-estilos';
  panel.id = 'panel-estilos';
  panel.hidden = true;

  const lista = document.createElement('ul');
  for (const estilo of ESTILOS) {
    const opcion = document.createElement('button');
    opcion.type = 'button';
    opcion.className = 'opcion-estilo';
    opcion.dataset.estilo = estilo.id;
    const nombre = document.createElement('span');
    nombre.textContent = estilo.nombre;
    const muestras = document.createElement('span');
    muestras.className = 'muestras';
    muestras.setAttribute('aria-hidden', 'true');
    for (const color of estilo.muestras) {
      const punto = document.createElement('span');
      punto.className = 'muestra';
      // Through the CSSOM, which the Content-Security-Policy allows; a style="" attribute
      // in markup would be blocked.
      punto.style.background = color;
      muestras.append(punto);
    }
    opcion.append(nombre, muestras);
    opcion.addEventListener('click', () => ondaDesde(opcion, () => aplicarEstilo(estilo.id)));
    const item = document.createElement('li');
    item.append(opcion);
    lista.append(item);
  }

  const modos = document.createElement('div');
  modos.className = 'menu-modo';
  modos.setAttribute('role', 'group');
  modos.setAttribute('aria-label', 'Modo');
  for (const [modo, texto] of [['oscuro', '☾ Oscuro'], ['claro', '☀ Claro']]) {
    const opcion = document.createElement('button');
    opcion.type = 'button';
    opcion.className = 'secondary-btn';
    opcion.dataset.modo = modo;
    opcion.textContent = texto;
    opcion.addEventListener('click', () => ondaDesde(opcion, () => aplicarModo(modo)));
    modos.append(opcion);
  }

  panel.append(lista, modos);
  contenedor.append(boton, panel);

  const abrir = (abierta) => {
    panel.hidden = !abierta;
    boton.setAttribute('aria-expanded', String(abierta));
  };
  boton.addEventListener('click', () => abrir(panel.hidden));
  document.addEventListener('click', (e) => {
    if (!contenedor.contains(e.target)) abrir(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !panel.hidden) {
      abrir(false);
      boton.focus();
    }
  });

  // Where the dice was, so on a phone it sits in the same spot under the card.
  const dado = document.getElementById('btnDado');
  if (dado) dado.after(contenedor);
  else document.body.append(contenedor);
  document.body.classList.add('con-barra');
  return contenedor;
}

function actualizarBarra() {
  if (!barra) return;
  barra.querySelector('.barra-actual').textContent = nombreDe(raiz.dataset.estilo);
  for (const b of barra.querySelectorAll('.opcion-estilo')) b.setAttribute('aria-pressed', String(b.dataset.estilo === raiz.dataset.estilo));
  for (const b of barra.querySelectorAll('.menu-modo button')) b.setAttribute('aria-pressed', String(b.dataset.modo === raiz.dataset.modo));
}

function mostrarBarra({ entrando = false } = {}) {
  barra ??= crearBarra();
  actualizarBarra();
  if (entrando) {
    barra.classList.remove('entrando');
    void barra.offsetWidth; // restart the entrance animation
    barra.classList.add('entrando');
    // On a phone it sits at the end of the page, maybe below a long report.
    barra.scrollIntoView({ block: 'nearest', behavior: menosMovimiento() ? 'auto' : 'smooth' });
  }
}

/* ---------- The chest ---------- */

const SVG = 'http://www.w3.org/2000/svg';
function svg(etiqueta, atributos, ...hijos) {
  const nodo = document.createElementNS(SVG, etiqueta);
  for (const [clave, valor] of Object.entries(atributos)) nodo.setAttribute(clave, valor);
  nodo.append(...hijos);
  return nodo;
}

/** A wooden chest with gold bands; the lid is its own group so it can swing open. */
function dibujarCofre() {
  const madera = '#8a4b1f';
  const maderaOscura = '#5c2f10';
  const oro = '#f5c542';
  return svg(
    'svg',
    { viewBox: '0 0 200 170', class: 'cofre-svg', 'aria-hidden': 'true' },
    svg('rect', { x: '36', y: '74', width: '128', height: '14', fill: '#fff4b8', class: 'cofre-luz' }),
    svg('rect', { x: '30', y: '80', width: '140', height: '72', rx: '8', fill: madera }),
    svg('rect', { x: '30', y: '80', width: '140', height: '72', rx: '8', fill: 'none', stroke: maderaOscura, 'stroke-width': '3' }),
    svg('rect', { x: '44', y: '80', width: '12', height: '72', fill: oro }),
    svg('rect', { x: '144', y: '80', width: '12', height: '72', fill: oro }),
    svg('rect', { x: '30', y: '80', width: '140', height: '9', fill: oro }),
    svg('rect', { x: '88', y: '92', width: '24', height: '28', rx: '4', fill: oro, stroke: '#b8860b', 'stroke-width': '2' }),
    svg('circle', { cx: '100', cy: '103', r: '4', fill: maderaOscura }),
    svg('rect', { x: '98', y: '105', width: '4', height: '8', fill: maderaOscura }),
    svg(
      'g',
      { class: 'cofre-tapa' },
      svg('path', { d: 'M30 82 V62 Q30 30 100 30 Q170 30 170 62 V82 Z', fill: madera, stroke: maderaOscura, 'stroke-width': '3' }),
      svg('path', { d: 'M44 82 V58 Q46 38 56 35 V82 Z', fill: oro }),
      svg('path', { d: 'M156 82 V58 Q154 38 144 35 V82 Z', fill: oro }),
      svg('rect', { x: '30', y: '74', width: '140', height: '8', fill: oro }),
    ),
  );
}

function abrirCofre() {
  const dialogo = document.createElement('dialog');
  dialogo.className = 'cofre';
  dialogo.setAttribute('aria-labelledby', 'cofre-titulo');

  const titulo = document.createElement('h2');
  titulo.id = 'cofre-titulo';
  titulo.className = 'cofre-titulo';
  titulo.textContent = '¡Descubriste el easter egg!';

  const escena = document.createElement('div');
  escena.className = 'cofre-escena';
  const rayos = document.createElement('div');
  rayos.className = 'cofre-rayos';
  const destello = document.createElement('div');
  destello.className = 'cofre-destello';
  // Rays behind the chest, the flash in front of its opening.
  escena.append(rayos, dibujarCofre(), destello);

  const premio = document.createElement('p');
  premio.className = 'cofre-premio';
  premio.textContent = 'Desbloqueaste la barra de estilos y el modo claro.';

  const seguir = document.createElement('button');
  seguir.type = 'button';
  seguir.className = 'cofre-seguir';
  seguir.textContent = 'Ver mis estilos';

  dialogo.append(titulo, escena, premio, seguir);
  document.body.append(dialogo);
  dialogo.showModal();

  const cerrar = () => dialogo.close();
  seguir.addEventListener('click', cerrar);
  dialogo.addEventListener('close', () => {
    dialogo.remove();
    mostrarBarra({ entrando: true });
    barra?.querySelector('.barra-boton')?.click();
  });
}

function descubrir() {
  if (document.querySelector('dialog.cofre')) return;
  if (!premiado) console.log('%c🎉 Easter egg descubierto: barra de estilos y modo claro desbloqueados.', 'font-weight:bold');
  premiado = true;
  abrirCofre();
}

/* ---------- Unlocking ---------- */

function escucharKonami() {
  let paso = 0;
  document.addEventListener('keydown', (evento) => {
    // Typing a link that happens to contain "ba" must not count.
    if (evento.target instanceof HTMLInputElement) return;
    const tecla = evento.key.length === 1 ? evento.key.toLowerCase() : evento.key;
    paso = tecla === KONAMI[paso] ? paso + 1 : tecla === KONAMI[0] ? 1 : 0;
    if (paso === KONAMI.length) {
      paso = 0;
      descubrir();
    }
  });
}

function escucharToques() {
  const logo = document.querySelector('.logo');
  let toques = [];
  logo?.addEventListener('click', () => {
    const ahora = Date.now();
    toques = [...toques.filter((t) => ahora - t < VENTANA_TOQUES_MS), ahora];
    if (toques.length >= TOQUES) {
      toques = [];
      descubrir();
    }
  });
}

/* ---------- Start ---------- */

export function iniciarTemas() {
  // The inline script only checks the saved id's shape; a style removed from the registry
  // falls back to the first one here.
  if (!ESTILOS.some((e) => e.id === raiz.dataset.estilo)) aplicarEstilo(ESTILOS[0].id);
  raiz.dataset.modo = 'oscuro';

  const dado = document.getElementById('btnDado');
  if (dado) colocarDado(lugarAlAzar(dado));
  // Placed before it becomes visible, so it does not slide in from a corner on load.
  requestAnimationFrame(() => dado?.classList.add('listo'));
  dado?.addEventListener('click', tirarDado);
  addEventListener('resize', reubicarDado);
  // The card grows when a report appears; if it now covers the dice, the dice moves.
  const main = document.querySelector('main');
  if (main && 'ResizeObserver' in window) new ResizeObserver(reubicarDado).observe(main);

  escucharKonami();
  escucharToques();
  console.log('%c🛡️ Shield Link', 'font-size:14px;font-weight:bold', '\n¿Buscas algo más? Cada diseño esconde una pista. 🎲');
}
