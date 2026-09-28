/**
 * Turns what someone pasted into a URL to analyse — or explains why it cannot be one.
 *
 * People paste "google.com", "www.banco.com/login" or "//cdn.example.com/a" as often as a
 * full URL, and should not have to type the scheme. A missing one is taken as https, which
 * is what browsers try first today; the report says when that happened.
 *
 * Shared by the page, for instant feedback, and by /api/scan, which decides. Pure.
 */

const CON_ESQUEMA = /^[a-z][a-z0-9+.-]*:\/\//i;
const OTROS_ESQUEMAS = /^(javascript|data|vbscript|file|blob|about|mailto|tel|sms|ftp|ws|wss|chrome|intent):/i;
const CORREO = /^[^\s/@:]+@[^\s/@:]+\.[a-z]{2,}$/i;

export function normalizarEntrada(texto) {
  const limpio = typeof texto === 'string' ? texto.trim() : '';
  if (!limpio) return { error: 'Falta el enlace a analizar.' };

  if (CORREO.test(limpio)) return { error: 'Eso parece un correo electrónico, no un enlace. Pega la dirección de una página web.' };

  let candidato = limpio;
  let esquemaAsumido = false;
  if (!CON_ESQUEMA.test(limpio)) {
    if (OTROS_ESQUEMAS.test(limpio)) return { error: 'Solo se analizan enlaces web (http o https).' };
    candidato = `https://${limpio.replace(/^\/\//, '')}`;
    esquemaAsumido = true;
  }

  let url;
  try {
    url = new URL(candidato);
  } catch {
    return { error: 'Eso no parece un enlace. Revisa cómo está escrito.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: 'Solo se analizan enlaces web (http o https).' };
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host.includes('.') && !host.includes(':')) {
    return { error: 'Eso no parece un enlace: falta el dominio, como en google.com.' };
  }

  return { url, esquemaAsumido };
}
