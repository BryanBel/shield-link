import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { esPlataformaAbierta, interpretarDetecciones } from './detecciones.js';

const vt = (detecciones, extra = {}) => ({
  estado: 'conocido', total: 92, maliciosos: detecciones.filter((d) => d.categoria === 'malicious').length,
  sospechosos: detecciones.filter((d) => d.categoria === 'suspicious').length, detecciones, limpiosDestacados: ['Kaspersky', 'ESET', 'BitDefender'], ...extra,
});
const lista = (motor, resultado = 'phishing') => ({ motor, categoria: 'malicious', resultado, metodo: 'blacklist' });

describe('interpretarDetecciones', () => {
  it('returns nothing when no engine flags the link', () => {
    assert.equal(interpretarDetecciones({ vt: vt([]), host: 'github.com', dominio: 'github.com' }), null);
    assert.equal(interpretarDetecciones({ vt: { estado: 'desconocido' }, host: 'x.com', dominio: 'x.com' }), null);
  });

  it('explains blocklist hits on the most visited site as a false positive, citing what was measured', () => {
    const r = interpretarDetecciones({ vt: vt([lista('0xSI_f33d'), lista('Fortra')]), host: 'google.com', dominio: 'google.com', rank: 1, diasDominio: 10600 });
    assert.equal(r.interpretacion, 'falso-positivo');
    assert.match(r.texto, /0xSI_f33d y Fortra lo tienen en su lista de phishing: ese veredicto sale de la lista, no de analizar el sitio ahora\./);
    assert.match(r.texto, /Los otros 90, entre ellos Kaspersky, ESET y BitDefender, no lo marcan\./);
    assert.match(r.texto, /#1\) y tiene 29 años/);
    assert.match(r.titulo, /casi seguro un error/);
  });

  it('describes a predictive engine by what its vendor documents', () => {
    const r = interpretarDetecciones({
      vt: vt([{ motor: 'Bfore.Ai PreCrime', categoria: 'malicious', resultado: 'malicious', metodo: 'blacklist' }], { total: 98 }),
      host: 'darwinlozada.com', dominio: 'darwinlozada.com', rank: null, diasDominio: 300,
    });
    assert.equal(r.interpretacion, 'prediccion');
    assert.match(r.texto, /motor predictivo/);
    assert.match(r.titulo, /es una predicción/);
  });

  it('does not excuse detections on an open platform', () => {
    const r = interpretarDetecciones({ vt: vt([lista('Fortra')]), host: 'sites.google.com', dominio: 'google.com', rank: 1, diasDominio: 10600 });
    assert.equal(r.interpretacion, 'plataforma');
    assert.match(r.texto, /cualquiera publica/);
  });

  it('keeps a minority detection on an unknown, young site open to both readings', () => {
    const r = interpretarDetecciones({ vt: vt([lista('Fortra')]), host: 'tienda.com', dominio: 'tienda.com', rank: null, diasDominio: 100 });
    assert.equal(r.interpretacion, 'minoritaria');
    assert.match(r.texto, /menos de un año/);
  });

  it('calls three or more engines a threat', () => {
    const r = interpretarDetecciones({ vt: vt([lista('A'), lista('B'), lista('C', 'malware')]), host: 'x.com', dominio: 'x.com' });
    assert.equal(r.interpretacion, 'amenaza');
    assert.match(r.titulo, /3 de 92 motores lo marcan como phishing y malware/);
  });
});

describe('esPlataformaAbierta', () => {
  it('matches the platform and its subdomains, not look-alikes', () => {
    assert.equal(esPlataformaAbierta('usuario.github.io'), true);
    assert.equal(esPlataformaAbierta('sites.google.com'), true);
    assert.equal(esPlataformaAbierta('proyecto.vercel.app'), true);
    assert.equal(esPlataformaAbierta('google.com'), false);
    assert.equal(esPlataformaAbierta('notgithub.io'), false);
  });
});
