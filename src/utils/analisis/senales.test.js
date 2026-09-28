import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { edad, generarSenales } from './senales.js';
import { decidirVeredicto } from './veredicto.js';

const AHORA = new Date('2026-09-28T12:00:00Z');
const haceDias = (n) => new Date(AHORA - n * 86_400_000).toISOString();

const vtLimpio = {
  estado: 'conocido', maliciosos: 0, sospechosos: 0, inofensivos: 70, total: 92, detecciones: [],
  categorias: ['search engines'], reputacion: 0, votos: { inofensivo: 10, malicioso: 0 },
  primerEnvio: haceDias(4000), ultimoAnalisis: haceDias(2), urlFinal: null, redirecciones: [],
};
const vtMalicioso = {
  ...vtLimpio, maliciosos: 7, primerEnvio: haceDias(3),
  detecciones: [{ motor: 'Fortinet', categoria: 'malicious', resultado: 'phishing' }],
};
const red = (extra = {}) => ({
  visitado: true, prudente: false, bloqueado: null, error: null, degradaHttps: false, ip: '140.82.112.3',
  saltos: [{ url: 'https://github.com/', estado: 200, host: 'github.com', ip: '140.82.112.3', https: true }],
  urlFinal: 'https://github.com/',
  certificado: { emisor: 'Sectigo Limited', desde: haceDias(60), hasta: haceDias(-300), valido: true, error: null },
  pagina: { titulo: 'GitHub', metaRefresh: null, redireccionJs: false, formularios: 0, formulariosConClave: 0, destinosDeClave: [], camposClave: 0, iframes: 0, scriptsExternos: [] },
  ...extra,
});
const rdapViejo = { disponible: true, creado: haceDias(6500), expira: haceDias(-400), registrador: 'MarkMonitor Inc.' };

const ids = (senales) => senales.map((s) => s.id);
const analizar = (entrada) => {
  const senales = generarSenales({ ahora: AHORA, ...entrada });
  return { senales, ...decidirVeredicto(senales, { vt: entrada.vt }) };
};

describe('generarSenales + decidirVeredicto', () => {
  it('an old, clean, encrypted site is safe with high certainty', () => {
    const r = analizar({ url: new URL('https://github.com/'), vt: vtLimpio, red: red(), rdap: rdapViejo });
    assert.equal(r.nivel, 'seguro');
    assert.equal(r.certeza, 'alta');
    assert.ok(ids(r.senales).includes('vt-limpio'));
    assert.ok(ids(r.senales).includes('dominio-antiguo'));
    assert.ok(ids(r.senales).includes('certificado-valido'));
    assert.match(r.motivo, /^Seguro, certeza alta: ninguno de los 92 motores/);
    // Brand-like first words keep their capitals when quoted as a clause.
    assert.match(r.motivo, /, VirusTotal lo conoce desde/);
  });

  it('a site VirusTotal has never seen is safe with low certainty, and says so', () => {
    const r = analizar({ url: new URL('https://github.com/'), vt: { estado: 'desconocido' }, red: red(), rdap: rdapViejo });
    assert.equal(r.nivel, 'seguro');
    assert.equal(r.certeza, 'baja');
    assert.match(r.motivo, /tampoco tiene una reputación/);
  });

  it('three or more engines make it dangerous with high certainty', () => {
    const r = analizar({ url: new URL('https://github.com/'), vt: vtMalicioso, red: red(), rdap: rdapViejo });
    assert.equal(r.nivel, 'peligroso');
    assert.equal(r.certeza, 'alta');
    assert.match(r.motivo, /7 de 92 motores/);
  });

  it('a domain registered days ago is dangerous even when VirusTotal is clean', () => {
    const r = analizar({ url: new URL('https://nuevo-sitio.com/'), vt: vtLimpio, red: red(), rdap: { ...rdapViejo, creado: haceDias(3) } });
    assert.equal(r.nivel, 'peligroso');
    assert.ok(ids(r.senales).includes('dominio-nuevo'));
  });

  it('plain http is caution, not danger', () => {
    const http = red({ saltos: [{ url: 'http://neverssl.com/', estado: 200, host: 'neverssl.com', https: false }], urlFinal: 'http://neverssl.com/', certificado: null });
    const r = analizar({ url: new URL('http://neverssl.com/'), vt: vtLimpio, red: http, rdap: rdapViejo });
    assert.equal(r.nivel, 'precaucion');
    assert.ok(ids(r.senales).includes('sin-https'));
  });

  it('a password form that posts to another domain is dangerous', () => {
    const pagina = { ...red().pagina, titulo: 'Acceso', formularios: 1, formulariosConClave: 1, camposClave: 1, destinosDeClave: ['recolector.com'] };
    const r = analizar({ url: new URL('https://github.com/'), vt: vtLimpio, red: red({ pagina }), rdap: rdapViejo });
    assert.equal(r.nivel, 'peligroso');
    assert.ok(ids(r.senales).includes('clave-a-otro-dominio'));
  });

  it('a login page titled as a bank on a domain the bank does not own is dangerous', () => {
    const pagina = { ...red().pagina, titulo: 'Banesco Online - Inicia sesión', formularios: 1, formulariosConClave: 1, camposClave: 1, destinosDeClave: ['banesco-seguro.com'] };
    const r = analizar({
      url: new URL('https://banesco-seguro.com/login'), vt: { estado: 'desconocido' },
      red: red({ pagina, urlFinal: 'https://banesco-seguro.com/login', saltos: [{ url: 'https://banesco-seguro.com/login', estado: 200, host: 'banesco-seguro.com', https: true }] }),
      rdap: { ...rdapViejo, creado: haceDias(200) },
    });
    assert.equal(r.nivel, 'peligroso');
    assert.ok(ids(r.senales).includes('suplanta-marca'));
    assert.ok(ids(r.senales).includes('marca-en-dominio'));
  });

  it('the same login page on the bank\'s own domain is not flagged', () => {
    const pagina = { ...red().pagina, titulo: 'Banesco Online', formularios: 1, formulariosConClave: 1, camposClave: 1, destinosDeClave: ['www.banesco.com'] };
    const r = analizar({
      url: new URL('https://www.banesco.com/'), vt: vtLimpio,
      red: red({ pagina, urlFinal: 'https://www.banesco.com/', saltos: [{ url: 'https://www.banesco.com/', estado: 200, host: 'www.banesco.com', https: true }] }),
      rdap: rdapViejo,
    });
    assert.ok(!ids(r.senales).includes('suplanta-marca'));
    assert.ok(!ids(r.senales).includes('marca-en-dominio'));
    assert.equal(r.nivel, 'seguro');
  });

  it('a page that names itself after a brand it is not calls for caution, even without a login form', () => {
    const pagina = { ...red().pagina, titulo: 'PayPal | Centro de ayuda', nombreSitio: 'PayPal' };
    const r = analizar({ url: new URL('https://ayuda-pagos.com/'), vt: vtLimpio, red: red({ pagina, urlFinal: 'https://ayuda-pagos.com/', saltos: [{ url: 'https://ayuda-pagos.com/', estado: 200, host: 'ayuda-pagos.com', https: true }] }), rdap: rdapViejo });
    assert.equal(r.nivel, 'precaucion');
    assert.ok(ids(r.senales).includes('dice-ser-marca'));
  });

  it('a vendor classifying the site as phishing calls for caution when the engines are silent', () => {
    const r = analizar({ url: new URL('https://github.com/'), vt: { ...vtLimpio, categorias: ['phishing and other frauds'] }, red: red(), rdap: rdapViejo });
    assert.equal(r.nivel, 'precaucion');
    assert.ok(ids(r.senales).includes('categoria-riesgo'));
  });

  it('an official domain buried in a subdomain is dangerous', () => {
    const r = analizar({ url: new URL('https://paypal.com.cuenta-verificada.net/'), vt: { estado: 'desconocido' }, red: null, rdap: rdapViejo });
    assert.equal(r.nivel, 'peligroso');
    assert.ok(ids(r.senales).includes('marca-en-subdominio'));
  });

  it('a shortener is judged by where it leads', () => {
    const acortado = red({
      saltos: [
        { url: 'https://bit.ly/abc', estado: 301, host: 'bit.ly', https: true },
        { url: 'https://github.com/', estado: 200, host: 'github.com', https: true },
      ],
    });
    const limpio = analizar({ url: new URL('https://bit.ly/abc'), vt: { estado: 'desconocido' }, vtDestino: vtLimpio, red: acortado, rdap: rdapViejo });
    assert.ok(ids(limpio.senales).includes('acortador'));
    assert.notEqual(limpio.nivel, 'peligroso');

    const malo = analizar({ url: new URL('https://bit.ly/abc'), vt: { estado: 'desconocido' }, vtDestino: vtMalicioso, red: acortado, rdap: rdapViejo });
    assert.equal(malo.nivel, 'peligroso');
    assert.ok(ids(malo.senales).includes('destino-malicioso'));
  });

  it('URL tricks are called out', () => {
    const arroba = analizar({ url: new URL('https://www.google.com@evil.com/'), vt: null, red: null, rdap: null });
    assert.ok(ids(arroba.senales).includes('arroba'));
    const ip = analizar({ url: new URL('http://45.33.32.156/login'), vt: null, red: null, rdap: null });
    assert.ok(ids(ip.senales).includes('ip-como-dominio'));
    const puny = analizar({ url: new URL('https://аpple.com/'), vt: null, red: null, rdap: null });
    assert.ok(ids(puny.senales).includes('punycode'));
    const tld = analizar({ url: new URL('https://algo.xyz/'), vt: null, red: null, rdap: null });
    assert.equal(tld.nivel, 'peligroso');
  });

  it('a link to a private address is caution, and the visit explains why it was skipped', () => {
    const r = analizar({ url: new URL('http://127.0.0.1/admin'), vt: { estado: 'desconocido' }, red: { ...red(), visitado: false, saltos: [], urlFinal: null, certificado: null, pagina: null, bloqueado: 'apunta a una dirección interna o reservada (127.0.0.1)' }, rdap: null });
    assert.equal(r.nivel, 'precaucion');
    assert.ok(ids(r.senales).includes('red-interna'));
  });

  it('dangers are listed before warnings, warnings before good news', () => {
    const r = analizar({ url: new URL('http://paypal.com.x.net/'), vt: vtMalicioso, red: null, rdap: rdapViejo });
    const orden = r.senales.map((s) => s.tipo);
    const peso = { peligro: 0, alerta: 1, bien: 2, info: 3 };
    assert.deepEqual(orden, [...orden].sort((a, b) => peso[a] - peso[b]));
  });
});

describe('edad', () => {
  it('reads naturally', () => {
    assert.equal(edad(0), 'menos de un día');
    assert.equal(edad(1), '1 día');
    assert.equal(edad(12), '12 días');
    assert.equal(edad(45), '1 mes');
    assert.equal(edad(200), '6 meses');
    assert.equal(edad(400), '1 año');
    assert.equal(edad(10000), '27 años');
  });
});
