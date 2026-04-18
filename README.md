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
- **Frontend/Backend:** [Astro](https://astro.build/) (v4+) - Renderizado en el servidor (SSR).
- **Base de Datos:** [Supabase](https://supabase.com/) - PostgreSQL para gestión de listas blancas y negras.
- **Gestor de Paquetes:** [pnpm](https://pnpm.io/) - Gestión eficiente de dependencias.
- **API de Seguridad:** [VirusTotal v3 API](https://www.virustotal.com/).
- **Despliegue:** [Vercel](https://vercel.com/).

---

## 🧠 Arquitectura de Análisis (Flujo en Cascada)
El sistema opera bajo una estrategia de **Zero Trust**:

1.  **Filtro Heurístico:** Bloqueo inmediato de extensiones maliciosas conocidas.
2.  **Caché Local (Reputación):** Consulta en Supabase para evitar re-analizar sitios ya verificados en `lista_blanca` o `lista_negra`.
3.  **Escaneo Global:** Análisis en tiempo real mediante los 70+ motores de VirusTotal.
4.  **Persistencia:** Almacenamiento automático del veredicto para optimizar futuras consultas.

---

## ⚙️ Configuración y Ejecución Local

### 1. Requisitos Previos
- **Node.js** (v18.0 o superior)
- **pnpm** instalado (`npm install -g pnpm`)

### 2. Instalación
```bash
git clone [https://github.com/TU_USUARIO/shield-link.git](https://github.com/TU_USUARIO/shield-link.git)
cd shield-link
pnpm install 
```
### 3. Configuración de Base de Datos

Para configurar las tablas y políticas de seguridad (RLS), ejecute el contenido del archivo schema.sql (ubicado en la raíz) en el SQL Editor de su proyecto en Supabase.

### 4. Variables de Entorno

Cree un archivo .env en la raíz del proyecto con las siguientes credenciales:
```bash
PUBLIC_SUPABASE_URL=[https://tu-proyecto.supabase.co](https://tu-proyecto.supabase.co)
PUBLIC_SUPABASE_ANON_KEY=tu-llave-anonima
VIRUSTOTAL_API_KEY=tu-api-key-de-virustotal
```
### 5. Despliegue Local
```bash
pnpm dev
```
---

Desarrollado por: Bryan Andrés Belandria Viña

Propósito: Proyecto de Ciberseguridad - Ingeniería en Sistemas de la Universdidad Alejandro de Humboldt.