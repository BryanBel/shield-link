import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { normalizarEntrada } from './normalizarEntrada.js';

const href = (texto) => normalizarEntrada(texto).url?.href;

describe('normalizarEntrada', () => {
  it('assumes https when the scheme is missing, and says so', () => {
    assert.deepEqual(
      { href: href('google.com'), asumido: normalizarEntrada('google.com').esquemaAsumido },
      { href: 'https://google.com/', asumido: true },
    );
    assert.equal(href('www.banco.com/login?x=1'), 'https://www.banco.com/login?x=1');
    assert.equal(href('//cdn.example.com/a.js'), 'https://cdn.example.com/a.js');
    assert.equal(href('  bit.ly/AbC  '), 'https://bit.ly/AbC');
    assert.equal(href('example.com:8080/panel'), 'https://example.com:8080/panel');
  });

  it('keeps an explicit scheme as typed', () => {
    const r = normalizarEntrada('http://neverssl.com');
    assert.equal(r.url.href, 'http://neverssl.com/');
    assert.equal(r.esquemaAsumido, false);
    assert.equal(href('HTTPS://GitHub.com/BryanBel'), 'https://github.com/BryanBel');
  });

  it('accepts IP addresses', () => {
    assert.equal(href('192.168.1.1/admin'), 'https://192.168.1.1/admin');
    assert.equal(href('http://[::1]/'), 'http://[::1]/');
  });

  it('refuses what is not a web link', () => {
    for (const texto of ['javascript:alert(1)', 'data:text/html,<b>x</b>', 'mailto:a@b.com', 'file:///etc/passwd', 'ftp://x.com/a']) {
      assert.ok(normalizarEntrada(texto).error, texto);
    }
  });

  it('refuses an email address pasted by mistake', () => {
    assert.match(normalizarEntrada('usuario@gmail.com').error, /correo/);
  });

  it('refuses text without a domain', () => {
    assert.ok(normalizarEntrada('').error);
    assert.ok(normalizarEntrada('hola').error);
    assert.ok(normalizarEntrada('localhost').error);
    assert.ok(normalizarEntrada('no es un enlace').error);
  });
});
