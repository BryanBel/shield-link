import { ESTILOS } from '../styles/estilos/registro.js';

/**
 * Style and colour-mode switching in the browser.
 *
 * The page wears one of the styles in registro.js, in light or dark mode, set as
 * data-estilo / data-modo on <html>. A tiny inline script in Layout.astro applies the saved
 * choice before first paint; this module handles everything after: the random-style
 * button, the mode toggle, and the secret menu that lets you pick a style by hand.
 *
 * The menu is an easter egg. It unlocks with the Konami code (↑↑↓↓←→←→BA) or, on a phone,
 * seven taps on the shield — and each style hides a piece of the hint. Once unlocked it
 * stays unlocked in that browser.
 *
 * localStorage can be unavailable (private windows, blocked storage); every access is
 * wrapped so the page still works, it just forgets on reload.
 */

const CLAVES = { estilo: 'shieldlink:estilo', modo: 'shieldlink:modo', menu: 'shieldlink:menu' };
const KONAMI = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];
const TOQUES = 7;
const VENTANA_TOQUES_MS = 3000;

const raiz = document.documentElement;
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

let menu = null;

function aplicarEstilo(id) {
  if (!ESTILOS.some((e) => e.id === id)) return;
  raiz.dataset.estilo = id;
  guardar(CLAVES.estilo, id);
  marcarMenu();
}

/** Paints a mode without remembering it — used for the system default. */
function pintarModo(modo) {
  raiz.dataset.modo = modo;
  const oscuro = modo === 'oscuro';
  const boton = document.getElementById('btnModo');
  boton?.setAttribute('aria-label', oscuro ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro');
  boton?.setAttribute('title', oscuro ? 'Modo claro' : 'Modo oscuro');
  document.getElementById('iconoSol')?.toggleAttribute('hidden', !oscuro);
  document.getElementById('iconoLuna')?.toggleAttribute('hidden', oscuro);
  marcarMenu();
}

/** The visitor's own choice: painted and remembered, so the system setting stops applying. */
function aplicarModo(modo) {
  pintarModo(modo);
  guardar(CLAVES.modo, modo);
}

/** Any style but the current one, so every press visibly changes something. */
function estiloAlAzar() {
  const otros = ESTILOS.filter((e) => e.id !== raiz.dataset.estilo);
  aplicarEstilo(otros[Math.floor(Math.random() * otros.length)].id);
}

/* ---------- Secret menu ---------- */

function crearMenu() {
  const dialogo = document.createElement('dialog');
  dialogo.className = 'menu-estilos';
  dialogo.setAttribute('aria-labelledby', 'menu-estilos-titulo');

  const titulo = document.createElement('h3');
  titulo.id = 'menu-estilos-titulo';
  titulo.textContent = 'Elige tu diseño';
  const lista = document.createElement('ul');

  for (const estilo of ESTILOS) {
    const boton = document.createElement('button');
    boton.type = 'button';
    boton.className = 'opcion-estilo';
    boton.dataset.estilo = estilo.id;
    const nombre = document.createElement('span');
    nombre.textContent = estilo.nombre;
    const muestras = document.createElement('span');
    muestras.className = 'muestras';
    muestras.setAttribute('aria-hidden', 'true');
    for (const color of estilo.muestras) {
      const punto = document.createElement('span');
      punto.className = 'muestra';
      // Set through the CSSOM, which the Content-Security-Policy allows; a style=""
      // attribute in markup would be blocked.
      punto.style.background = color;
      muestras.append(punto);
    }
    boton.append(nombre, muestras);
    boton.addEventListener('click', () => aplicarEstilo(estilo.id));
    const item = document.createElement('li');
    item.append(boton);
    lista.append(item);
  }

  const modos = document.createElement('div');
  modos.className = 'menu-modo';
  for (const [modo, texto] of [['claro', '☀ Claro'], ['oscuro', '☾ Oscuro']]) {
    const boton = document.createElement('button');
    boton.type = 'button';
    boton.className = 'secondary-btn';
    boton.dataset.modo = modo;
    boton.textContent = texto;
    boton.addEventListener('click', () => aplicarModo(modo));
    modos.append(boton);
  }

  const cerrar = document.createElement('button');
  cerrar.type = 'button';
  cerrar.className = 'secondary-btn';
  cerrar.textContent = 'Listo';
  cerrar.addEventListener('click', () => dialogo.close());
  const acciones = document.createElement('div');
  acciones.className = 'dialogo-acciones';
  acciones.append(cerrar);

  dialogo.append(titulo, lista, modos, acciones);
  document.body.append(dialogo);
  return dialogo;
}

function marcarMenu() {
  if (!menu) return;
  for (const b of menu.querySelectorAll('.opcion-estilo')) b.setAttribute('aria-pressed', String(b.dataset.estilo === raiz.dataset.estilo));
  for (const b of menu.querySelectorAll('.menu-modo button')) b.setAttribute('aria-pressed', String(b.dataset.modo === raiz.dataset.modo));
}

function abrirMenu() {
  menu ??= crearMenu();
  marcarMenu();
  if (!menu.open) menu.showModal();
}

function desbloquear() {
  const primeraVez = leer(CLAVES.menu) !== '1';
  guardar(CLAVES.menu, '1');
  document.getElementById('btnMenu')?.removeAttribute('hidden');
  if (primeraVez) console.log('%c🎉 Menú de diseños desbloqueado. Queda disponible en el botón 🎨.', 'font-weight:bold');
  abrirMenu();
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
      desbloquear();
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
      desbloquear();
    }
  });
}

/* ---------- Start ---------- */

export function iniciarTemas() {
  // The inline script only checks the saved id's shape; a style that was removed from the
  // registry falls back to the first one here.
  if (!ESTILOS.some((e) => e.id === raiz.dataset.estilo)) aplicarEstilo(ESTILOS[0].id);
  pintarModo(raiz.dataset.modo === 'claro' ? 'claro' : 'oscuro');

  document.getElementById('btnDiseno')?.addEventListener('click', estiloAlAzar);
  document.getElementById('btnModo')?.addEventListener('click', () => aplicarModo(raiz.dataset.modo === 'oscuro' ? 'claro' : 'oscuro'));
  document.getElementById('btnMenu')?.addEventListener('click', abrirMenu);
  if (leer(CLAVES.menu) === '1') document.getElementById('btnMenu')?.removeAttribute('hidden');

  // Follow the system's light/dark setting until the visitor picks one themselves.
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!leer(CLAVES.modo)) pintarModo(e.matches ? 'claro' : 'oscuro');
  });

  escucharKonami();
  escucharToques();
  console.log('%c🛡️ Shield Link', 'font-size:14px;font-weight:bold', '\n¿Buscas algo más? Cada diseño esconde una pista. 🎲');
}
