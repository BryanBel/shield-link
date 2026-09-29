/**
 * The styles the page can wear. Each entry needs a matching src/styles/estilos/<id>.css that
 * fulfils the contract in _contrato.css — `pnpm test` checks both.
 *
 * `muestras` are the swatches shown in the style menu, in the order they appear.
 * The first entry is the style a first visit gets.
 */
export const ESTILOS = [
  { id: 'clasico', nombre: 'Clásico', muestras: ['#0f172a', '#1e293b', '#2563eb', '#2ecc71'] },
  { id: 'y2k', nombre: 'Y2K', muestras: ['#ff69b4', '#00ffff', '#c0c0c0', '#9400d3'] },
  { id: 'cyberpunk', nombre: 'Cyberpunk', muestras: ['#05070d', '#00ff9c', '#ff2e88', '#22d3ee'] },
  { id: 'clay', nombre: 'Clay', muestras: ['#f4f1fa', '#a78bfa', '#7c3aed', '#db2777'] },
  { id: 'vaporwave', nombre: 'Vaporwave', muestras: ['#ff71ce', '#01cdfe', '#05ffa1', '#b967ff'] },
];

export const ESTILO_INICIAL = ESTILOS[0].id;
