/**
 * Decides the verdict from the signals, and says how sure it is.
 *
 * Signals decide, in order of weight: any danger makes the link dangerous; otherwise any
 * warning calls for caution; otherwise it is safe. What changes is the certainty, which
 * depends on how much evidence backs the verdict — a safe link VirusTotal has never seen
 * is "safe, low certainty", and the page says so rather than implying more than it knows.
 *
 * Pure: signals in, verdict out.
 */

const NOMBRE = { seguro: 'Seguro', precaucion: 'Requiere precaución', peligroso: 'Peligroso' };

/**
 * Lowercases the first letter so a title reads as a clause — but only when the first word
 * is an ordinary capitalised word. "VirusTotal", "DHL" or "PayPal" stay as they are.
 */
const comoClausula = (titulo) => {
  const primera = titulo.split(/\s/)[0];
  return /^\p{Lu}\p{Ll}*$/u.test(primera) ? titulo[0].toLowerCase() + titulo.slice(1) : titulo;
};

const enumerar = (partes) => (partes.length < 2 ? partes.join('') : `${partes.slice(0, -1).join(', ')} y ${partes.at(-1)}`);

export function decidirVeredicto(senales, { vt = null } = {}) {
  const de = (tipo) => senales.filter((s) => s.tipo === tipo);
  const peligros = de('peligro');
  const alertas = de('alerta');
  const conocido = vt?.estado === 'conocido';

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
    const antiguo = senales.some((s) => s.id === 'dominio-antiguo' || s.id === 'vt-antiguo');
    const cifrado = senales.some((s) => s.id === 'certificado-valido');
    certeza = !conocido ? 'baja' : antiguo && cifrado ? 'alta' : 'media';
    razones = de('bien');
  }

  const frases = razones.slice(0, 3).map((s) => comoClausula(s.titulo));
  let motivo = frases.length
    ? `${NOMBRE[nivel]}, certeza ${certeza}: ${enumerar(frases)}.`
    : `${NOMBRE[nivel]}, certeza ${certeza}: no se encontraron señales de riesgo.`;
  if (nivel === 'seguro' && certeza === 'baja') {
    motivo += ' Nadie lo ha reportado, pero tampoco tiene una reputación que lo respalde.';
  }

  return { nivel, certeza, motivo };
}
