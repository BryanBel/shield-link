import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { analizarHtml, esIpPublica, pareceDeUnSoloUso } from './investigar.server.js';

describe('esIpPublica — the SSRF guard', () => {
  const privadas = [
    '127.0.0.1', '10.0.0.5', '172.16.3.4', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', 'ff02::1', '2001:db8::1',
  ];
  for (const ip of privadas) it(`refuses ${ip}`, () => assert.equal(esIpPublica(ip), false));

  const publicas = ['8.8.8.8', '1.1.1.1', '140.82.112.3', '2606:4700:4700::1111', '2a00:1450:4001:82a::200e'];
  for (const ip of publicas) it(`allows ${ip}`, () => assert.equal(esIpPublica(ip), true));

  it('refuses anything that is not an IP', () => {
    assert.equal(esIpPublica('localhost'), false);
    assert.equal(esIpPublica(''), false);
  });
});

describe('pareceDeUnSoloUso', () => {
  it('flags token-like parameters', () => {
    assert.equal(pareceDeUnSoloUso(new URL('https://a.com/reset?token=abc')), true);
    assert.equal(pareceDeUnSoloUso(new URL('https://a.com/x?Confirm=1')), true);
    assert.equal(pareceDeUnSoloUso(new URL('https://a.com/u?unsubscribe=me')), true);
  });
  it('flags long random path segments', () => {
    assert.equal(pareceDeUnSoloUso(new URL('https://a.com/verify/8f3kd92jf83nd82hf73kd92m')), true);
  });
  it('leaves ordinary links alone', () => {
    assert.equal(pareceDeUnSoloUso(new URL('https://github.com/BryanBel/shield-link')), false);
    assert.equal(pareceDeUnSoloUso(new URL('https://www.google.com/search?q=hola')), false);
    assert.equal(pareceDeUnSoloUso(new URL('https://en.wikipedia.org/wiki/Content_Security_Policy_header')), false);
  });
});

describe('analizarHtml', () => {
  const base = 'https://login.ejemplo.com/entrar';

  it('reads the title and decodes entities', () => {
    const p = analizarHtml('<html><head><title>  Inicia sesi&oacute;n &amp; m&#225;s </title></head></html>', base);
    assert.equal(p.titulo, 'Inicia sesión & más');
  });

  it('finds a password form posting to another domain', () => {
    const p = analizarHtml('<form action="https://recolector.xyz/g"><input name=u><input type="password" name=p></form>', base);
    assert.equal(p.formularios, 1);
    assert.equal(p.formulariosConClave, 1);
    assert.deepEqual(p.destinosDeClave, ['recolector.xyz']);
  });

  it('treats a form without action as posting to the page itself', () => {
    const p = analizarHtml("<form><input type='password'></form>", base);
    assert.deepEqual(p.destinosDeClave, ['login.ejemplo.com']);
  });

  it('detects meta refresh and strips its query', () => {
    const p = analizarHtml('<meta http-equiv="refresh" content="0; url=https://otro.com/a?t=secreto">', base);
    assert.equal(p.metaRefresh, 'https://otro.com/a');
  });

  it('detects JavaScript redirects without flagging comparisons', () => {
    assert.equal(analizarHtml('<script>window.location.href = "https://x.com"</script>', base).redireccionJs, true);
    assert.equal(analizarHtml('<script>location.replace("/x")</script>', base).redireccionJs, true);
    assert.equal(analizarHtml('<script>if (location == 1) {}</script>', base).redireccionJs, false);
  });

  it('lists external script hosts and counts iframes', () => {
    const p = analizarHtml('<script src="https://cdn.otro.com/a.js"></script><script src="/local.js"></script><iframe src="x"></iframe>', base);
    assert.deepEqual(p.scriptsExternos, ['cdn.otro.com']);
    assert.equal(p.iframes, 1);
  });
});
