/**
 * Decides the verdict from the signals, and says how sure it is.
 *
 * Signals decide, in order of weight: any danger makes the link dangerous; otherwise any
 * warning calls for caution; otherwise it is safe. What changes is the certainty, which
 * depends on how much evidence backs the verdict — a safe link VirusTotal has never seen
 * is "safe, low certainty", and the page says so rather than implying more than it knows.
 *
 * The verdict comes with a recommendation in plain words, because "precaución, certeza
 * media" answers a question nobody asked; "ábrelo con cuidado" answers the one they did.
 *
 * Pure: signals in, verdict out.
 */

const RECOMENDACION = { seguro: 'Puedes abrirlo', precaucion: 'Ábrelo con cuidado', peligroso: 'No lo abras' };

/**
 * Lowercases the first letter so a title reads as a clause — but only when the first word
 * is an ordinary capitalised word. "VirusTotal", "DHL" or "google.com" stay as they are.
 */
const comoClausula = (titulo) => {
  const primera = titulo.split(/\s/)[0];
  return /^\p{Lu}\p{Ll}*$/u.test(primera) ? titulo[0].toLowerCase() + titulo.slice(1) : titulo;
};

/** Capitalises a sentence's first letter, unless it starts with a domain or a brand. */
const comoOracion = (texto) => {
  const primera = texto.split(/\s/)[0];
  return /^\p{Ll}+$/u.test(primera) ? texto[0].toUpperCase() + texto.slice(1) : texto;
};

const enumerar = (partes) => (partes.length < 2 ? partes.join('') : `${partes.slice(0, -1).join(', ')} y ${partes.at(-1)}`);

export function decidirVeredicto(senales, { vt = null } = {}) {
  const de = (tipo) => senales.filter((s) => s.tipo === tipo);
  const tiene = (id) => senales.some((s) => s.id === id);
  const peligros = de('peligro');
  const alertas = de('alerta');
  const conocido = vt?.estado === 'conocido';
  const falsoPositivo = senales.find((s) => s.id === 'vt-falso-positivo');

  let nivel;
  let certeza;
  let razones;

  if (peligros.length) {
    nivel = 'peligroso';
    certeza = (conocido && vt.maliciosos >= 3) || peligros.length >= 2 ? 'alta' : 'media';
    razones = peligros;
  } else if (alertas.length) {
    nivel = 'precaucion';
    certeza = 'media';
    razones = alertas;
  } else {
    nivel = 'seguro';
    const historia = tiene('dominio-antiguo') || tiene('vt-antiguo') || tiene('popular');
    const cifrado = tiene('certificado-valido');
    certeza = !conocido ? 'baja' : historia && cifrado && !falsoPositivo ? 'alta' : 'media';
    razones = de('bien');
  }

  const frases = razones.slice(0, 3).map((s) => comoClausula(s.titulo));
  let motivo = frases.length ? `${comoOracion(enumerar(frases))}.` : 'No se encontraron señales de riesgo.';
  if (nivel === 'seguro' && falsoPositivo) {
    const n = falsoPositivo.titulo.match(/^\d+/)?.[0] ?? '';
    motivo += ` ${n === '1' ? 'La detección es' : `Las ${n} detecciones son`} casi seguro un falso positivo.`;
  }
  if (nivel === 'seguro' && certeza === 'baja') {
    motivo += ' Nadie lo ha reportado, pero tampoco tiene una reputación que lo respalde.';
  }

  return { nivel, certeza, recomendacion: RECOMENDACION[nivel], motivo };
}
