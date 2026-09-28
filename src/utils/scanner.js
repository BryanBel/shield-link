import { normalizarEntrada } from './normalizarEntrada.js';

/**
 * Browser-side entry point for a scan.
 *
 * Every decision happens in /api/scan on the server. This module only does the one check
 * worth doing locally — whether the text can be a web link at all — so an obvious typo
 * gets instant feedback instead of a network round trip. The server revalidates it
 * regardless, with the same rules.
 *
 * Earlier versions ran the whole cascade here, which meant the browser held a Supabase
 * key and wrote to the reputation tables directly. Anyone could then insert a malicious
 * URL into lista_blanca and have the scanner vouch for it.
 */
export async function analizarSeguridad(texto) {
  const entrada = normalizarEntrada(texto);
  if (entrada.error) return { error: true, motivo: entrada.error };

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: texto.trim() }),
    });

    const result = await response.json();

    // 4xx responses carry their own { error, motivo } and are already user-facing.
    if (!response.ok && !result?.motivo) {
      return { error: true, motivo: 'No se pudo completar el análisis. Inténtalo de nuevo.' };
    }

    return result;
  } catch {
    return {
      error: true,
      motivo: 'No se pudo contactar el servicio de análisis. Revisa tu conexión e inténtalo de nuevo.',
    };
  }
}
