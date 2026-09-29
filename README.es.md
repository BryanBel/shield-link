[English](README.md) | **Español**

# Shield Link

Un escáner de seguridad de enlaces. Pegas un enlace y obtienes un veredicto antes de
abrirlo.

**En vivo en [shield-link.vercel.app](https://shield-link.vercel.app)**

![El escáner de Shield Link](docs/scanner.webp)

Proyecto de ciberseguridad para Ingeniería en Informática, Universidad Alejandro de
Humboldt.

## Cómo se llega a un veredicto

Una lista negra solo puede decir si alguien ya reportó un enlace. Shield Link lo investiga:
cuatro fuentes a la vez, cada hallazgo convertido en una señal, y el veredicto decidido a
partir de esas señales —que la página después muestra, para que la respuesta venga con sus
razones.

| Fuente | Qué aporta |
| ------ | ---------- |
| [VirusTotal API v3](https://www.virustotal.com) | La opinión de ~90 motores: cuáles marcaron el enlace y como qué, cómo clasifica la web ese sitio, desde cuándo lo conoce VirusTotal |
| Una visita al enlace | Adónde lleva de verdad, salto por salto; su certificado TLS; y qué es la página —su título, si pide una contraseña y adónde la enviaría |
| [RDAP](https://about.rdap.org), de los registros | Cuándo se registró el dominio y con quién; qué red es dueña de la IP del servidor |
| [Tranco](https://tranco-list.eu) | Qué tan popular es el dominio entre el millón de sitios más visitados: la escala con la que se leen las detecciones |
| La URL misma | Trucos en la dirección: una extensión de alto riesgo, imitaciones con punycode, una IP en vez de un nombre, texto antes de una `@`, el nombre de una marca en un dominio que no es suyo |

Cuando un enlace termina en otro dominio —un acortador, una redirección— el destino es lo
que el usuario va a ver de verdad, así que recibe su propia revisión de reputación y de
registro.

Un dominio suelto sirve igual que una URL completa: `google.com` se analiza como
`https://google.com`, el esquema que los navegadores prueban primero, y el informe avisa que
se asumió. Lo que no es un enlace web —`javascript:`, `data:`, `mailto:`, un correo pegado
por error— se rechaza antes de hacer cualquier trabajo.

Cada señal es a favor, un dato, una alerta o un peligro, y el veredicto las sigue:

- **Cualquier peligro → `peligroso`.** Tres motores o más; un dominio registrado hace días;
  un formulario de contraseña que envía a otro dominio; una página de acceso que se
  presenta como un banco en un dominio que el banco no posee; un dominio oficial metido en
  un subdominio, como `paypal.com.ejemplo.net`; una extensión como `.xyz`, `.zip` o `.top`,
  que concentran phishing muy por encima de su peso en la web y se bloquean sin gastar una
  consulta de VirusTotal.
- **Si no, cualquier alerta → `precaucion`.** Uno o dos motores; sin HTTPS; un dominio de
  pocas semanas; un certificado inválido; una redirección a un dominio ajeno que nadie
  respalda.
- **Si no → `seguro`.**

La respuesta se da como se hace la pregunta: *Puedes abrirlo*, *Ábrelo con cuidado*, *No lo
abras* —con un botón para abrir el sitio. Antes pide confirmación: una simple para un enlace
seguro, una que repite la alerta principal para uno con precaución, y para uno peligroso un
segundo paso, marcar "Entiendo el riesgo", antes de que se abra nada.

### Darle sentido a una detección

VirusTotal agrega unos noventa motores de calidad muy despareja. Tratar "uno o más motores"
como peligroso, que es lo que este proyecto hacía al principio, clasifica media web como
amenaza y enseña al usuario a ignorar el aviso. Por eso cada detección se explica, usando
solo lo que se puede comprobar:

- **Cómo decidió el motor.** VirusTotal reporta el método de cada uno. `blacklist` significa
  que la URL está en la lista de ese motor: el veredicto sale de la lista, no de analizar el
  sitio ahora.
- **Quién no está de acuerdo.** "Los otros 90, entre ellos Kaspersky, ESET y BitDefender, no
  lo marcan" dice más que un número.
- **La escala.** Mientras se escribe esto, `google.com` aparece en dos listas negras. También
  es el sitio más visitado del mundo y tiene 29 años: si fuera malicioso, lo marcaría la
  mayoría de los motores, no 2 de 92. Un dominio dentro del top 10.000 de Tranco, con al
  menos cinco años, marcado por uno o dos motores, se considera seguro —con las detecciones a
  la vista y explicadas como un falso positivo casi seguro.
- **Salvo en plataformas abiertas.** `sites.google.com`, `*.github.io`, `*.vercel.app`, los
  formularios de Google Docs y similares son populares porque cualquiera publica en ellos, y
  los kits de phishing también. Su fama no respalda nada, así que ahí las detecciones
  mantienen su peso.
- **Qué es el motor,** solo cuando su propio fabricante lo documenta. Bfore.Ai PreCrime, por
  ejemplo, es predictivo: señala dominios con patrones que podrían usarse en ataques antes de
  que ocurra alguno. Una detección suya, sola, se reporta como una predicción, no como un
  ataque detectado.

### Qué tan seguro está

Cada veredicto trae una certeza. Un enlace seguro que VirusTotal analizó y encontró limpio,
en un dominio de más de un año, con certificado válido, es de certeza *alta*. Uno seguro
que VirusTotal nunca vio es de certeza *baja* —nadie lo reportó, pero nada lo respalda— y
la página lo dice con palabras en vez de dar a entender más de lo que sabe. Un veredicto que
tuvo que explicar detecciones nunca pasa de certeza *media*.

```jsonc
// POST /api/scan { "url": "google.com" } — resumido
{
  "nivel": "seguro",
  "certeza": "media",
  "recomendacion": "Puedes abrirlo",
  "motivo": "google.com es el sitio más visitado del mundo, VirusTotal lo conoce desde 2011 y dominio registrado hace 29 años. Las 2 detecciones son casi seguro un falso positivo.",
  "detecciones": {
    "interpretacion": "falso-positivo",
    "texto": "0xSI_f33d y Fortra lo tienen en su lista de phishing: ese veredicto sale de la lista, no de analizar el sitio ahora. Los otros 90, entre ellos Kaspersky, ESET y BitDefender, no lo marcan. …"
  },
  "sitio": { "estado": "coherente", "conclusion": "Lo que dice de sí mismo cuadra con la evidencia independiente." },
  "senales": [{ "tipo": "bien", "titulo": "google.com es el sitio más visitado del mundo" }],
  "detalles": { "popularidad": {}, "destino": {}, "dominio": {}, "certificado": {}, "servidor": {}, "reputacion": {}, "pagina": {} }
}
```

### Lo que dice el sitio, y si es cierto

El informe cita cómo se describe el sitio —su meta descripción, o su título— y después
contrasta esa afirmación con evidencia que el sitio no controla: si la marca con la que se
presenta es de verdad dueña del dominio, si lo que dice hacer coincide con cómo lo
clasifican las empresas de seguridad, y cuánto tiempo tiene el dominio. La conclusión es
una de *cuadra*, *dudoso*, *no cuadra* o *sin evidencia suficiente*, con los puntos que la
sostienen.

Son reglas fijas, no un modelo de lenguaje. En una página de phishing la descripción es
texto del atacante, y un modelo que la lea puede ser convencido de repetirla; una regla no.
Una página que se presenta como una marca que no es, o una empresa de seguridad que
clasifica el sitio como phishing, también levantan una alerta en el veredicto, así que la
conclusión y el veredicto nunca se contradicen.

### Visitar un enlace sin que te use

Un servidor que descarga una URL elegida por otro puede terminar apuntándose a sí mismo:
`127.0.0.1`, la dirección de metadatos de la nube `169.254.169.254`, una red privada. Toda
conexión de Shield Link pasa por su propia resolución DNS, que rechaza cualquier dirección
que no sea pública, IPv4 o IPv6. La verificación ocurre en el momento de conectar, así que
un nombre no puede resolver a una dirección pública al revisarlo y a una privada al usarlo.

Además: solo los puertos 80, 443, 8080 y 8443; como máximo 8 redirecciones y 7 segundos;
no más de 512 KB de HTML, leídos como texto y nunca ejecutados; sin cookies, y cualquier
credencial dentro de la URL se quita antes de la petición.

Algunos enlaces se consumen al abrirlos: un restablecimiento de contraseña, una
confirmación de correo, una baja de una lista. Cuando un enlace lo parece (un parámetro
`token`, `code` o `reset`, un segmento largo y aleatorio), Shield Link solo revisa su
servidor y su certificado, sin abrir la página, y lo dice.

El límite de cualquier visita desde un servidor: un sitio puede mostrarle algo distinto de
lo que le muestra a una persona. Las otras fuentes existen para que el veredicto nunca
dependa solo de la visita.

### Caché y presupuesto

Los informes se guardan en Postgres con el SHA-256 de la URL como clave —nunca la URL,
porque un enlace puede llevar un token— y cada URL dentro de un informe guardado va sin su
query. Vencen: 7 días un veredicto seguro, 1 una precaución, 30 uno peligroso, porque un
veredicto es una foto y los dominios cambian de dueño.

Como las fuentes corren en paralelo, una investigación completa es rápida. Medido en
producción desde un cliente cuyo viaje de ida y vuelta al sitio, sin más, es de 80 ms: un
análisis nuevo tardó 402 ms y uno en caché 91 ms (medianas de 4 y de 12). La primera
consulta después de cinco minutos sin uso además despierta la base, lo que costó unos
600 ms extra en una medición anterior y única.

El plan gratuito de VirusTotal permite 4 consultas por minuto y 500 por día, compartidas por
todos los visitantes, y cada análisis nuevo además visita el sitio. Por eso los análisis
nuevos tienen un límite por cliente: 4 por minuto y 50 por día. Pasado el límite,
`/api/scan` responde `429`. Los informes en caché no cuestan nada y nunca cuentan.

## Diseños

La página viene en cinco estilos —Clásico, Y2K, Cyberpunk, Clay y Vaporwave—, cada uno en
modo claro y oscuro. El dado de la esquina cambia a uno al azar; el sol y la luna cambian el
modo, que si no sigue al del sistema. La elección se recuerda y se aplica antes del primer
pintado, así que la página nunca parpadea con el diseño por defecto. También hay algo
escondido para los curiosos.

Cada estilo es un conjunto de valores para las mismas variables, definidas en
[`src/styles/estilos/_contrato.css`](src/styles/estilos/_contrato.css); los componentes solo
leen esas variables. Agregar un estilo es un archivo CSS en esa carpeta y una línea en
[`registro.js`](src/styles/estilos/registro.js): nada más cambia. `pnpm test` revisa cada
estilo registrado contra el contrato en los dos modos: que no falte ninguna variable, y que
cada par de colores que se dibuja como texto llegue al contraste AA de WCAG (4,5:1). El botón
del diseño original, blanco sobre `#3b82f6`, medía 3,68:1 y nunca llegó.

Las fuentes están alojadas en el propio sitio, así que la Content-Security-Policy se queda
en `'self'`, y el navegador solo descarga las del estilo activo. Quien le pide a su sistema
menos movimiento no ve destellos, cursores que parpadean ni grillas que se mueven.

## Stack

| Capa | Elección | Por qué |
| ---- | -------- | ------- |
| Framework | [Astro](https://astro.build) 7, SSR en [Vercel](https://vercel.com) | La página es estática salvo por un endpoint; Astro no envía JavaScript para el resto |
| Base de datos | PostgreSQL en [Neon](https://neon.tech) | Una caché de análisis y un contador por cliente, accesibles solo desde el servidor. El driver serverless de Neon habla por HTTP, lo que encaja con una función de Vercel que vive una sola petición — un pool ahí abre una conexión por invocación |
| Inteligencia de amenazas | [VirusTotal API v3](https://www.virustotal.com) | Plan gratuito, llamado desde el servidor para que la clave nunca llegue al navegador |
| Gestor de paquetes | [pnpm](https://pnpm.io) | |

## Seguridad

Las tablas de reputación deciden si a un usuario se le dice que un enlace es seguro, lo
que convierte el acceso de escritura en lo más sensible del proyecto. Una versión
temprana traía esto:

```sql
CREATE POLICY "..." ON lista_blanca FOR ALL USING (true);
```

`FOR ALL` cubre select, insert, update y delete, y `USING (true)` se lo concede a
cualquiera — incluida la clave anónima, que es pública por diseño y se lee en las
herramientas de desarrollo de cualquier navegador. Cualquiera podía insertar una URL
maliciosa en la lista blanca y hacer que Shield Link la diera por buena, o vaciar ambas
tablas.

Una política más estrecha no lo habría arreglado: el escáner necesita escribir para
cachear veredictos, así que cualquier política que permita escribir desde el navegador es
una que un atacante puede usar. En su lugar, toda la cascada se movió al servidor. Hoy:

- La base se movió de Supabase a Neon, así que ya no hay PostgREST ni clave anónima
  delante. Solo se llega con la cadena de conexión.
- Solo `/api/scan` y `/api/health` la tocan, y ambos corren en el servidor.
- Se conectan como `shieldlink_app`, un rol que puede leer y escribir filas en sus tablas y
  nada más: nada de `DROP`, `ALTER`, `TRUNCATE`, `CREATE TABLE` ni `CREATE ROLE`. Una
  cadena de conexión filtrada cuesta filas, no la base. La cadena del owner nunca sale de la
  máquina del desarrollador.
- El bundle del navegador no contiene cliente de base de datos ni credencial — comprobable
  con `grep -r neon dist/client` después de un build.

La página corre bajo una Content-Security-Policy que Astro genera con un hash por cada
script y estilo inline, y no carga nada de otro origen. `vercel.json` agrega las cabeceras
que un `<meta>` no puede llevar: `frame-ancestors 'none'` y `X-Frame-Options` contra el
clickjacking, más `nosniff`, una `Referrer-Policy` y una `Permissions-Policy`.

## Ejecutarlo en local

```sh
pnpm install
cp .env.example .env    # completa los valores de abajo
pnpm dev                # http://localhost:4321
```

Crea el rol de la aplicación una vez, como owner de la base, y luego aplica `schema.sql` con
`psql`. El archivo es idempotente: crea las tablas si no existen, deja intactas las filas que
ya estén y le da al rol sus permisos.

```sh
psql "$DATABASE_URL_ADMIN" -c "CREATE ROLE shieldlink_app LOGIN PASSWORD '...'"
psql "$DATABASE_URL_ADMIN" -f schema.sql
```

| Variable | Dónde obtenerla |
| -------- | --------------- |
| `DATABASE_URL` | Cadena de conexión de `shieldlink_app`. Sirve cualquier PostgreSQL; el proyecto usa SQL plano, no un SDK |
| `DATABASE_URL_ADMIN` | La cadena del owner. Solo en local, para `schema.sql`; nunca en Vercel |
| `VIRUSTOTAL_API_KEY` | virustotal.com → tu perfil → API key |

Ninguna lleva prefijo `PUBLIC_` a propósito: Astro expone las `PUBLIC_*` a los bundles del
cliente.

## Verificar la configuración

```sh
curl https://shield-link.vercel.app/api/health
```

```json
{
  "base": {
    "urlDefinida": true,
    "alcanzable": true,
    "error": null
  },
  "virustotal": { "clave": true },
  "node": "v24.20.0",
  "cacheActivo": true
}
```

Una cadena de conexión ausente y una equivocada se ven idénticas desde fuera: el escáner
sigue respondiendo, solo que sin caché, gastando cuota de VirusTotal en cada consulta
hasta agotar el límite diario sin avisar. El endpoint devuelve booleanos, la versión de
Node y, si la base no responde, el mensaje de error del driver; no expone el valor, el
prefijo ni la longitud de ningún secreto.

---

Hecho por Bryan Belandria — [github.com/BryanBel](https://github.com/BryanBel)
