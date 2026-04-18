import { supabase } from './client.js';

export async function analizarSeguridad(url) {
    try {
        const urlObj = new URL(url.toLowerCase().trim());
        const host = urlObj.hostname;

        // 1. CAPA LOCAL: Supabase (Evita re-analizar lo que ya conocemos)
        const { data: localData } = await supabase
            .from('reportes_seguridad')
            .select('*')
            .eq('url_sospechosa', url)
            .maybeSingle();

        if (localData) {
            return { seguro: false, motivo: `Confirmado: ${localData.motivo}` };
        }

        let motivoEncontrado = "";

        // 2. CAPA GLOBAL: API Interna (VirusTotal)
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (response.ok) {
                const result = await response.json();
                const stats = result.data?.attributes?.last_analysis_stats;

                if (stats && (stats.malicious > 0 || stats.phishing > 0)) {
                    motivoEncontrado = `Amenaza detectada por motores globales (${stats.malicious + stats.phishing}).`;
                }
            }
        } catch (e) { console.error("Error en API:", e); }

        // 3. CAPA HEURÍSTICA (Si VirusTotal no falló, revisamos tus reglas)
        if (!motivoEncontrado) {
            if (urlObj.protocol !== 'https:') {
                motivoEncontrado = 'Conexión insegura (Falta HTTPS).';
            } else if (['.zip', '.mov', '.xyz'].some(tld => host.endsWith(tld))) {
                motivoEncontrado = 'Dominio de alto riesgo detectado.';
            }
        }

        // --- LÓGICA DE GUARDADO ---
        if (motivoEncontrado) {
            await supabase.from('reportes_seguridad').insert([
                { url_sospechosa: url, motivo: motivoEncontrado }
            ]);
            return { seguro: false, motivo: motivoEncontrado };
        }

        return { seguro: true, motivo: 'No se detectaron amenazas.' };

    } catch (e) {
        return { seguro: false, motivo: 'URL no válida.' };
    }
}