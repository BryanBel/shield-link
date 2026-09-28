import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { contrastar, marcaDeclarada } from './contraste.js';

const AHORA = new Date('2026-09-28T12:00:00Z');
const hace = (dias) => new Date(AHORA - dias * 86_400_000).toISOString();
const vt = (categorias, primerEnvio = hace(4000)) => ({ estado: 'conocido', categorias, primerEnvio });
const pagina = (extra) => ({ titulo: null, nombreSitio: null, descripcion: null, camposClave: 0, ...extra });

describe('contrastar', () => {
  it('a developer platform classified as technology, 18 years old, holds up', () => {
    const r = contrastar({
      dominio: 'github.com',
      pagina: pagina({ nombreSitio: 'GitHub', descripcion: 'The AI-powered developer platform where millions build software.' }),
      vt: vt(['information technology', 'computersandsoftware']),
      rdap: { creado: hace(6600) },
      ahora: AHORA,
    });
    assert.equal(r.estado, 'coherente');
    assert.equal(r.nombre, 'GitHub');
    assert.ok(r.puntos.some((p) => p.tipo === 'bien' && /tecnología/.test(p.texto)));
    assert.ok(r.puntos.some((p) => /18 años de historia/.test(p.texto)));
  });

  it('a page calling itself a bank on a domain the bank does not own does not hold up', () => {
    const r = contrastar({
      dominio: 'banesco-seguro.com',
      pagina: pagina({ nombreSitio: 'Banesco', descripcion: 'Banca en línea', camposClave: 1 }),
      vt: { estado: 'desconocido' },
      rdap: { creado: hace(4) },
      ahora: AHORA,
    });
    assert.equal(r.estado, 'no-cuadra');
    assert.match(r.puntos[0].texto, /Dice ser Banesco, pero banesco-seguro.com no pertenece a Banesco, y pide una contraseña/);
    assert.ok(r.puntos.some((p) => /apenas 4 días/.test(p.texto)));
  });

  it('the bank on its own domain is confirmed', () => {
    const r = contrastar({ dominio: 'banesco.com', pagina: pagina({ titulo: 'Banesco Online | Inicio' }), vt: vt(['financial services']), rdap: { creado: hace(9000) }, ahora: AHORA });
    assert.equal(r.estado, 'coherente');
    assert.match(r.puntos[0].texto, /sí es un dominio de Banesco/);
  });

  it('a phishing category overrides whatever the page claims', () => {
    const r = contrastar({ dominio: 'x.com', pagina: pagina({ descripcion: 'Tu banco de confianza' }), vt: vt(['phishing and other frauds']), ahora: AHORA });
    assert.equal(r.estado, 'no-cuadra');
  });

  it('a claim that does not match the classification is doubtful', () => {
    const r = contrastar({ dominio: 'zapatos.com', pagina: pagina({ descripcion: 'Tienda online de zapatos' }), vt: vt(['news and media']), rdap: { creado: hace(900) }, ahora: AHORA });
    assert.equal(r.estado, 'dudoso');
    assert.match(r.puntos.find((p) => p.tipo === 'alerta').texto, /Dice dedicarse a compras, pero lo clasifican como news and media/);
  });

  it('with nothing to compare against, it says so', () => {
    const r = contrastar({ dominio: 'algo.ve', pagina: pagina({ descripcion: 'Un sitio' }), vt: { estado: 'desconocido' }, rdap: { disponible: false }, ahora: AHORA });
    assert.equal(r.estado, 'sin-datos');
  });
});

describe('marcaDeclarada', () => {
  it('reads an explicit site name', () => {
    assert.equal(marcaDeclarada(pagina({ nombreSitio: 'PayPal' })).nombre, 'PayPal');
  });
  it('reads a short title segment', () => {
    assert.equal(marcaDeclarada(pagina({ titulo: 'PayPal: Inicia sesión' })).nombre, 'PayPal');
    assert.equal(marcaDeclarada(pagina({ titulo: 'Inicio | Banesco Online' })).nombre, 'Banesco');
  });
  it('does not mistake a headline that mentions a brand for a claim to be it', () => {
    assert.equal(marcaDeclarada(pagina({ titulo: 'Apple lanza un nuevo iPhone con más batería | El País' })), null);
    assert.equal(marcaDeclarada(pagina({ titulo: 'Cómo proteger tu cuenta de PayPal del phishing' })), null);
  });
});
