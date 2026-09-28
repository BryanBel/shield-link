import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { limpiarCategorias } from './virusTotal.server.js';

describe('limpiarCategorias', () => {
  it('keeps one label per family — the case from google.com', () => {
    assert.deepEqual(limpiarCategorias(['search engines/portals', 'search engines', 'search engines and portals']), ['search engines/portals']);
    assert.deepEqual(limpiarCategorias(['search engines/portals', 'searchengines']), ['search engines/portals']);
  });

  it('strips vendor attributions and merges singular and plural', () => {
    assert.deepEqual(limpiarCategorias(['information technology (alphamountain.ai)', 'information technology', 'search engine', 'search engines']), [
      'information technology',
      'search engine',
    ]);
  });

  it('keeps genuinely different categories, in order', () => {
    assert.deepEqual(limpiarCategorias(['phishing and other frauds', 'suspicious', 'hosted personal pages']), [
      'phishing and other frauds',
      'suspicious',
      'hosted personal pages',
    ]);
  });

  it('caps the list at five', () => {
    assert.equal(limpiarCategorias(['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7']).length, 5);
  });
});
