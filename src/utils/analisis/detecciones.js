import { NOTAS_MOTORES, PLATAFORMAS_ABIERTAS } from './datos.js';

/**
 * Makes sense of VirusTotal detections, especially the awkward minority case — two engines
 * out of ninety flagging google.com.
 *
 * Nothing here is invented. It uses what the engines themselves report (their label and
 * their method — "blacklist" means the URL is on a list someone fed, not that the engine
 * analysed the page), how many others call it clean, and measured context: the domain's
 * popularity rank and age, and whether it is a platform where anyone can publish. Engines
 * are only described when their own vendor documents how they work (datos.js).
 *
 * Pure. Returns null when there is nothing to explain.
 */

export const SITIO_POPULAR = 10_000;
const ANTIGUO_DIAS = 5 * 365;

export const esPlataformaAbierta = (host) => PLATAFORMAS_ABIERTAS.some((p) => host === p || host.endsWith(`.${p}`));

const ETIQUETAS = { malicious: 'sitio malicioso', phishing: 'phishing', malware: 'malware', suspicious: 'sospechoso', spam: 'spam', 'malicious site': 'sitio malicioso', 'phishing site': 'phishing', 'malware site': 'malware' };
const enumerar = (partes) => (partes.length < 2 ? partes.join('') : `${partes.slice(0, -1).join(', ')} y ${partes.at(-1)}`);
const anios = (dias) => Math.floor(dias / 365);

export function interpretarDetecciones({ vt, host, dominio, rank = null, diasDominio = null }) {
  if (vt?.estado !== 'conocido' || !vt.detecciones?.length) return null;

  const det = vt.detecciones;
  const n = det.length;
  const limpios = vt.total - n;
  const nombres = enumerar(det.map((d) => d.motor));
  const etiquetas = enumerar([...new Set(det.map((d) => ETIQUETAS[String(d.resultado ?? d.categoria).toLowerCase()] ?? String(d.resultado ?? d.categoria)))]);
  const porLista = det.every((d) => d.metodo === 'blacklist');
  const plataforma = esPlataformaAbierta(host);
  const popular = rank !== null && rank <= SITIO_POPULAR;
  const antiguo = diasDominio !== null && diasDominio >= ANTIGUO_DIAS;
  const predictivos = det.every((d) => NOTAS_MOTORES[d.motor]?.includes('predictivo'));

  const como = porLista
    ? `${n === 1 ? 'lo tiene' : 'lo tienen'} en su lista de ${etiquetas}: ese veredicto sale de la lista, no de analizar el sitio ahora.`
    : `${n === 1 ? 'lo clasifica' : 'lo clasifican'} como ${etiquetas}.`;
  const destacados = vt.limpiosDestacados ?? [];
  const otros = `Los otros ${limpios}${destacados.length ? `, entre ellos ${enumerar(destacados.slice(0, 3))},` : ''} no lo marcan.`;
  const notas = det.filter((d) => NOTAS_MOTORES[d.motor]).map((d) => `${d.motor} ${NOTAS_MOTORES[d.motor]}`);
  const motores = det.map((d) => ({ ...d, nota: NOTAS_MOTORES[d.motor] ?? null }));

  let interpretacion;
  let texto;
  if (vt.maliciosos >= 3) {
    interpretacion = 'amenaza';
    texto = `${nombres} ${como} Cuando ${n} motores independientes coinciden, rara vez es un error. ${otros}`;
  } else if (plataforma) {
    interpretacion = 'plataforma';
    texto = `${nombres} ${como} ${otros} Pero ${host} es una plataforma donde cualquiera publica: la fama de ${dominio} no respalda esta página en particular, así que estas detecciones sí pesan.`;
  } else if (popular && antiguo) {
    interpretacion = 'falso-positivo';
    texto = `${nombres} ${como} ${otros} ${dominio} está entre los sitios más visitados del mundo (#${rank.toLocaleString('es')}) y tiene ${anios(diasDominio)} años: si fuera malicioso, lo detectaría la gran mayoría, no ${n} de ${vt.total}. Es casi seguro un falso positivo; suele pasarles a dominios enormes que alojan contenido de terceros.`;
  } else if (predictivos) {
    interpretacion = 'prediccion';
    texto = `${notas.join(' ')} ${otros}`;
  } else {
    interpretacion = 'minoritaria';
    const contexto = diasDominio !== null && diasDominio < 365 ? 'un sitio poco conocido y de menos de un año' : 'un sitio poco conocido';
    texto = `${nombres} ${como} ${otros}${notas.length ? ` ${notas.join(' ')}` : ''} Una proporción tan baja suele ser un falso positivo, pero en ${contexto} también puede ser una amenaza que los demás todavía no detectan.`;
  }

  const titulo =
    interpretacion === 'amenaza'
      ? `${n} de ${vt.total} motores lo marcan como ${etiquetas}`
      : interpretacion === 'falso-positivo'
        ? `Por qué lo ${n === 1 ? 'marca 1 motor' : `marcan ${n} motores`}: casi seguro un error`
        : interpretacion === 'prediccion'
          ? `Por qué lo marca ${nombres}: es una predicción`
          : `Por qué lo ${n === 1 ? 'marca 1 motor' : `marcan ${n} motores`}`;

  return { interpretacion, titulo, texto, motores, limpios, porLista };
}
