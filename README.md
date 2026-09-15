# 🛡️ Shield Link - Sistema de Análisis de Integridad de URLs

**Shield Link** es una herramienta de ciberseguridad desarrollada con el framework **Astro**, diseñada para proteger a los usuarios mediante el análisis profundo de enlaces sospechosos. El sistema utiliza una arquitectura de inspección en cascada para determinar la seguridad de una URL antes de que el usuario interactúe con ella.

---

## 🚀 Características Principales
- **Análisis Multi-Capa:** Consulta una base de datos local de reputación, motores globales y reglas heurísticas proactivas.
- **Seguridad Server-Side:** Integración con la API de VirusTotal protegida mediante *Astro API Routes* (BFF).
- **Caché de Inteligencia:** Registro automático de amenazas y sitios seguros en Supabase para optimizar tiempos de respuesta y cuotas de API.
- **Validación Heurística:** Bloqueo preventivo de TLDs de alto riesgo (`.xyz`, `.zip`, `.tk`) y protocolos inseguros.

---

## 🛠️ Stack Tecnológico
- **Frontend/Backend:** [Astro](https://astro.build/) v6 - Renderizado en el servidor (SSR).
- **Base de Datos:** [Supabase](https://supabase.com/) - PostgreSQL para gestión de listas blancas y negras.
- **Gestor de Paquetes:** [pnpm](https://pnpm.io/) - Gestión eficiente de dependencias.
- **API de Seguridad:** [VirusTotal v3 API](https://www.virustotal.com/).
- **Despliegue:** [Vercel](https://vercel.com/).

---

## 🧠 Arquitectura de Análisis (Flujo en Cascada)
El sistema opera bajo una estrategia de **Zero Trust**:

1.  **Filtro Heurístico:** Bloqueo inmediato de extensiones maliciosas conocidas.
2.  **Caché Local (Reputación):** Consulta en Supabase para evitar re-analizar sitios ya verificados en `lista_blanca` o `lista_negra`.
3.  **Escaneo Global:** Análisis en tiempo real mediante los ~90 motores de VirusTotal. El
    veredicto tiene tres niveles, no dos: hacen falta varios motores coincidentes para
    declarar un enlace peligroso, porque un puñado de detecciones sobre noventa suele ser
    un falso positivo — `google.com` mismo reporta 2.
4.  **Persistencia:** Almacenamiento automático del veredicto para optimizar futuras consultas.

---

## ⚙️ Configuración y Ejecución Local

### 1. Requisitos Previos
- **Node.js** (v18.0 o superior)
- **pnpm** instalado (`npm install -g pnpm`)

### 2. Instalación
```bash
git clone https://github.com/BryanBel/shield-link.git
cd shield-link
pnpm install 
```
### 3. Configuración de Base de Datos

Ejecute el contenido de `schema.sql` (en la raíz del proyecto) en el SQL Editor de Supabase. El
archivo es idempotente: crea las tablas si no existen y vuelve a aplicar las políticas de
seguridad sin borrar datos.

Las tablas quedan con RLS activado y **sin ninguna política**, de modo que PostgreSQL rechaza
toda consulta anónima. El único acceso es el de la ruta `/api/scan`, que corre en el servidor
con la *service role key*. Esto es deliberado: el escáner necesita escribir para cachear
veredictos, y cualquier política que permitiera escribir desde el navegador permitiría también
que un tercero insertara una URL maliciosa en `lista_blanca` y Shield Link la diera por segura.

### 4. Variables de Entorno

Copie `.env.example` a `.env` y complete los valores:

```bash
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_SERVICE_ROLE_KEY=tu-service-role-key
VIRUSTOTAL_API_KEY=tu-api-key-de-virustotal
```

Ninguna lleva el prefijo `PUBLIC_` a propósito: Astro expone las variables `PUBLIC_*` al
bundle del navegador, y la *service role key* omite el row-level security. Solo las lee
`src/utils/supabase.server.js`, que a su vez solo importa `/api/scan`.
### 5. Despliegue Local
```bash
pnpm dev
```
---

Desarrollado por: Bryan Andrés Belandria Viña

Propósito: Proyecto de Ciberseguridad — Ingeniería en Informática, Universidad Alejandro de Humboldt.