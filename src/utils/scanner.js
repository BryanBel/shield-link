/**
 * Browser-side entry point for a scan.
 *
 * Every decision now happens in /api/scan on the server. This module only does the one
 * check worth doing locally — whether the string even looks like a URL — so an obvious
 * typo gets instant feedback instead of a network round trip. The server revalidates it
 * regardless.
 *
 * Earlier versions ran the whole cascade here, which meant the browser held a Supabase
 * key and wrote to the reputation tables directly. Anyone could then insert a malicious
 * URL into lista_blanca and have the scanner vouch for it.
 */
export async function analizarSeguridad(url) {
  const limpia = url.trim();

  if (!limpia.startsWith('http://') && !limpia.startsWith('https://')) {
    return {
      error: true,
      motivo: 'Formato no válido. Asegúrate de incluir http:// o https:// (Ej: https://google.com)',
    };
  }

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: limpia }),
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
