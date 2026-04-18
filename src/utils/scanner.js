import { supabase } from './client.js';

export async function analizarSeguridad(url) {
    try {
        // 1. VALIDACIÓN DE FORMATO (User Error check)
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return { 
                error: true, 
                motivo: 'Formato no válido. Asegúrate de incluir http:// o https:// (Ej: https://google.com)' 
            };
        }

        const urlObj = new URL(url.toLowerCase().trim());
        const urlLimpia = urlObj.href;
        const host = urlObj.hostname;

        // 2. CAPA HEURÍSTICA PROACTIVA (Bloqueo de extensiones peligrosas)
        // Bloqueamos .xyz, .zip, .mov, etc., antes de gastar recursos de API
        const tldsPeligrosos = ['.xyz', '.zip', '.mov', '.tk', '.fit', '.icu', '.top'];
        if (tldsPeligrosos.some(tld => host.endsWith(tld))) {
            const extension = host.split('.').pop();
            return { 
                seguro: false, 
                motivo: `Bloqueo Preventivo: La extensión .${extension} es utilizada frecuentemente para campañas de phishing y distribución de malware.` 
            };
        }

        // 3. CAPA DE REPUTACIÓN LOCAL (Lista Blanca)
        const { data: blanca } = await supabase
            .from('lista_blanca')
            .select('*')
            .eq('url_segura', urlLimpia)
            .maybeSingle();

        if (blanca) return { seguro: true, motivo: "Enlace verificado en nuestra lista de confianza." };

        // 4. CAPA DE REPUTACIÓN LOCAL (Lista Negra)
        const { data: negra } = await supabase
            .from('lista_negra')
            .select('*')
            .eq('url_maliciosa', urlLimpia)
            .maybeSingle();

        if (negra) return { seguro: false, motivo: `Amenaza confirmada: ${negra.motivo}` };

        // 5. CAPA GLOBAL (VirusTotal)
        let veredictoVT = null;
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlLimpia })
            });

            if (response.ok) {
                const result = await response.json();
                const stats = result.data?.attributes?.last_analysis_stats;

                if (stats) {
                    if (stats.malicious > 0 || stats.phishing > 0) {
                        veredictoVT = { 
                            seguro: false, 
                            motivo: `VirusTotal detectó riesgos confirmados (${stats.malicious + stats.phishing} motores).` 
                        };
                    } else {
                        veredictoVT = { seguro: true, motivo: "Análisis global completado: No se detectaron amenazas en motores de seguridad." };
                    }
                }
            }
        } catch (e) { console.error("Fallo en API global:", e); }

        // 6. PERSISTENCIA DE INTELIGENCIA
        if (veredictoVT) {
            if (veredictoVT.seguro) {
                await supabase.from('lista_blanca').insert([{ url_segura: urlLimpia }]);
            } else {
                await supabase.from('lista_negra').insert([{ 
                    url_maliciosa: urlLimpia, 
                    motivo: veredictoVT.motivo 
                }]);
            }
            return veredictoVT;
        }

        // 7. HEURÍSTICA DE PROTOCOLO (Último recurso)
        if (urlObj.protocol !== 'https:') {
            return { seguro: false, motivo: "Inseguro: El sitio no utiliza cifrado SSL (HTTPS), facilitando el robo de datos." };
        }

        return { seguro: true, motivo: "Análisis básico finalizado: No se hallaron riesgos conocidos." };

    } catch (e) {
        return { error: true, motivo: "URL no válida. Revisa la ortografía del enlace." };
    }
}