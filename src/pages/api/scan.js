export const POST = async ({ request }) => {
  try {
    const { url } = await request.json();
    // Usamos el nombre que tienes en tu .env
    const API_KEY = import.meta.env.PHISHTANK_API_KEY; 

    if (!url) return new Response(JSON.stringify({ error: 'URL requerida' }), { status: 400 });

    // Codificación segura para Node.js/Astro Server
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': API_KEY }
    });

    const data = await response.json();
    
    // Si VT no lo conoce (404), devolvemos un estado limpio en lugar de error
    if (response.status === 404) {
        return new Response(JSON.stringify({ clean: true, msg: 'No data' }), { status: 200 });
    }

    return new Response(JSON.stringify(data), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Error interno del servidor' }), { status: 500 });
  }
};