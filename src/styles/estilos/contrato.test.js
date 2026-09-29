import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { ESTILOS } from './registro.js';

/**
 * Every registered style must fulfil the contract in _contrato.css, in both modes, and be
 * readable. Adding a style that forgets a variable, or pairs text and background too close
 * in brightness, fails here with the exact variable and ratio — no browser needed.
 */

const carpeta = new URL('./', import.meta.url);
const leer = (archivo) => readFileSync(new URL(archivo, carpeta), 'utf8');

const declaraciones = (bloque) =>
  Object.fromEntries(
    bloque
      // Comments are allowed inside a style's blocks; they are not declarations.
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split(';')
      .map((d) => d.trim())
      .filter((d) => d.startsWith('--'))
      .map((d) => {
        const i = d.indexOf(':');
        return [d.slice(0, i).trim(), d.slice(i + 1).trim()];
      }),
  );

const contrato = Object.keys(declaraciones(leer('_contrato.css').match(/:root\s*\{([^}]*)\}/)[1]));

/** Colours the test measures, so they must be solid hex values. */
const SOLIDOS = ['--fondo', '--superficie', '--superficie-2', '--texto', '--texto-suave', '--texto-tenue', '--acento', '--acento-texto', '--enlace', '--seguro', '--precaucion', '--peligro', '--neutro', '--icono-texto'];

/** [foreground, background] pairs the page actually draws as text. */
const PARES = [
  ['--texto', '--superficie'],
  ['--texto-suave', '--superficie'],
  ['--texto-tenue', '--superficie'],
  ['--texto', '--superficie-2'],
  ['--texto-suave', '--superficie-2'],
  ['--texto-tenue', '--superficie-2'],
  ['--acento-texto', '--acento'],
  ['--enlace', '--superficie'],
  ['--enlace', '--superficie-2'],
  ['--seguro', '--superficie'],
  ['--precaucion', '--superficie'],
  ['--peligro', '--superficie'],
  ['--icono-texto', '--seguro'],
  ['--icono-texto', '--precaucion'],
  ['--icono-texto', '--peligro'],
  ['--icono-texto', '--neutro'],
];

function luminancia(hex) {
  const h = hex.replace('#', '');
  const completo = h.length === 3 ? [...h].map((c) => c + c).join('') : h;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(completo.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contraste(a, b) {
  const [l1, l2] = [luminancia(a), luminancia(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
}

describe('registro de estilos', () => {
  const archivos = readdirSync(carpeta).filter((f) => f.endsWith('.css') && !f.startsWith('_')).map((f) => f.replace(/\.css$/, ''));

  it('every registered style has its file, and every file is registered', () => {
    const ids = ESTILOS.map((e) => e.id);
    assert.deepEqual([...ids].sort(), [...archivos].sort());
  });

  it('ids are unique and every entry has a name and swatches', () => {
    assert.equal(new Set(ESTILOS.map((e) => e.id)).size, ESTILOS.length);
    for (const e of ESTILOS) {
      assert.ok(e.nombre, `${e.id}: falta nombre`);
      assert.ok(e.muestras?.length >= 2 && e.muestras.every((m) => /^#[0-9a-f]{3,6}$/i.test(m)), `${e.id}: muestras inválidas`);
    }
  });
});

for (const { id } of ESTILOS) {
  describe(`estilo ${id}`, () => {
    const css = leer(`${id}.css`);

    for (const modo of ['claro', 'oscuro']) {
      const bloque = css.match(new RegExp(`\\[data-estilo="${id}"\\]\\[data-modo="${modo}"\\]\\s*\\{([^}]*)\\}`));

      it(`${modo}: defines every variable of the contract`, () => {
        assert.ok(bloque, `${id}.css no tiene el bloque [data-estilo="${id}"][data-modo="${modo}"]`);
        const valores = declaraciones(bloque[1]);
        const faltan = contrato.filter((v) => !valores[v]);
        assert.deepEqual(faltan, [], `${id} (${modo}): faltan ${faltan.join(', ')}`);
      });

      it(`${modo}: measured colours are solid hex`, () => {
        const valores = declaraciones(bloque?.[1] ?? '');
        const malos = SOLIDOS.filter((v) => valores[v] && !/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(valores[v]));
        assert.deepEqual(malos, [], `${id} (${modo}): deben ser hex sólidos: ${malos.join(', ')}`);
      });

      it(`${modo}: every text pair reaches WCAG AA (4.5:1)`, () => {
        const valores = declaraciones(bloque?.[1] ?? '');
        const fallos = PARES.filter(([t, f]) => valores[t] && valores[f])
          .map(([t, f]) => ({ par: `${t} sobre ${f}`, ratio: contraste(valores[t], valores[f]) }))
          .filter((p) => p.ratio < 4.5)
          .map((p) => `${p.par}: ${p.ratio.toFixed(2)}`);
        assert.deepEqual(fallos, [], `${id} (${modo}) no llega a 4,5:1 en: ${fallos.join('; ')}`);
      });
    }
  });
}
