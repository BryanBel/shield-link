**English** | [Español](README.es.md)

# Shield Link

A URL safety scanner. Paste a link, get a verdict before you click it.

**Live at [shield-link.vercel.app](https://shield-link.vercel.app)**

![The Shield Link scanner](docs/scanner.webp)

Built as a cybersecurity project for the Computer Engineering programme at Universidad
Alejandro de Humboldt.

## How a verdict is reached

Six layers, cheapest first. Each one can answer on its own, so most links never reach the
paid API at the bottom.

| # | Layer | What it decides |
| - | ----- | --------------- |
| 1 | Format validation | Rejects anything that is not an `http(s)` URL, before any work happens |
| 2 | High-risk TLD heuristic | Blocks `.xyz`, `.zip`, `.mov`, `.tk`, `.fit`, `.icu`, `.top` outright — these carry phishing and malware far out of proportion to their share of the web |
| 3 | Local allowlist | A URL already cleared is answered from Postgres, not re-scanned |
| 4 | Local blocklist | A URL already found malicious is answered the same way, with the original reason |
| 5 | VirusTotal API v3 | ~90 engines, queried only for URLs the first four layers could not settle |
| 6 | Protocol heuristic | Last resort: plain `http` with no reputation data anywhere is called out as unencrypted |

Every confident verdict from layer 5 is written back into layer 3 or 4, so the second
lookup of the same URL costs nothing. In production that is the difference between a
474 ms answer and a 253 ms one — medians, measured from a client whose bare round trip to
the site is 234 ms, so a cached verdict costs the server about 20 ms. It also keeps the
free tier's 500-requests-a-day budget for links that actually need it.

The exception is the first request after a quiet spell. Neon suspends the database after
five minutes without traffic, and in one measurement the request that woke it — along
with a cold function — took 863 ms, about 600 ms more than a warm one.

That budget — 4 lookups a minute, 500 a day — is shared by every visitor, so lookups that
would reach layer 5 are also limited per client: 4 a minute and 50 a day. Past that,
`/api/scan` answers `429`. Cached and heuristic verdicts cost nothing and are never
counted, so they keep answering.

## Three verdicts, not two

VirusTotal aggregates around ninety engines of very uneven quality, and a handful of
detections on an established domain is routinely noise. `google.com` itself reports two
engines calling it malicious against sixty-one calling it harmless. Treating "one or more
engines" as dangerous — which is what this project did at first — labels most of the web
a threat and teaches the user to ignore the warning.

So the scanner reports three levels and shows its arithmetic:

```jsonc
// https://github.com  — nothing found
{ "nivel": "seguro", "motivo": "Análisis global completado: ninguno de los 90 motores de seguridad detectó amenazas." }

// https://google.com — a minority of engines disagree, and the user is told exactly that
{ "nivel": "precaucion", "motivo": "Detecciones minoritarias: 2 de 90 motores marcan este enlace. Esa proporción suele ser un falso positivo, pero conviene revisarlo antes de abrirlo." }

// https://something.xyz — blocked before spending a request
{ "nivel": "peligroso", "motivo": "Bloqueo preventivo: la extensión .xyz se utiliza frecuentemente para campañas de phishing y distribución de malware." }
```

A `precaucion` verdict is deliberately never cached: it is a judgement call about
ambiguous evidence, and writing it into either list would harden a maybe into a yes or
a no.

## Stack

| Layer | Choice | Why |
| ----- | ------ | --- |
| Framework | [Astro](https://astro.build) 7, SSR on [Vercel](https://vercel.com) | The page is static except for one endpoint; Astro ships no JavaScript for the rest |
| Database | PostgreSQL on [Neon](https://neon.tech) | Two reputation tables and a per-client lookup counter, reached only from the server. Neon's serverless driver talks over HTTP, which suits a Vercel function that lives for one request — a connection pool there opens a connection per invocation |
| Threat intelligence | [VirusTotal API v3](https://www.virustotal.com) | Free tier, called from the server so the key never ships to a browser |
| Package manager | [pnpm](https://pnpm.io) | |

## Security

The reputation tables decide whether a user is told a link is safe, which makes write
access to them the most sensitive thing in the project. An early version shipped this:

```sql
CREATE POLICY "..." ON lista_blanca FOR ALL USING (true);
```

`FOR ALL` covers select, insert, update and delete, and `USING (true)` grants it to every
caller — including the anonymous key, which is public by design and readable in any
browser's devtools. Anyone could have inserted a malicious URL into the allowlist and had
Shield Link vouch for it, or emptied both tables.

A narrower policy would not have fixed it: the scanner has to write in order to cache
verdicts, so any policy permitting a browser write is one an attacker can use. The whole
cascade moved server-side instead. Today:

- The database moved off Supabase to Neon, so there is no PostgREST and no anonymous key
  in front of it. It is reachable only with the connection string.
- Only `/api/scan` and `/api/health` touch it, and both run on the server.
- They connect as `shieldlink_app`, a role that can read and write rows in the three tables
  and nothing else: no `DROP`, `ALTER`, `TRUNCATE`, `CREATE TABLE` or `CREATE ROLE`. A leaked
  connection string costs rows, not the database. The owner's string never leaves the
  developer's machine.
- The browser bundle contains no database client and no credential — verifiable with
  `grep -r neon dist/client` after a build.

The page itself runs under a Content-Security-Policy that Astro generates with a hash for
every inline script and style, and loads nothing from another origin. `vercel.json` adds
the headers a `<meta>` tag cannot carry: `frame-ancestors 'none'` and `X-Frame-Options`
against clickjacking, plus `nosniff`, a `Referrer-Policy` and a `Permissions-Policy`.

## Running it locally

```sh
pnpm install
cp .env.example .env    # fill in the values below
pnpm dev                # http://localhost:4321
```

Create the application role once, as the database owner, then apply `schema.sql` with
`psql`. The file is idempotent: it creates the tables if they are missing, leaves existing
rows alone, and grants the role its privileges.

```sh
psql "$DATABASE_URL_ADMIN" -c "CREATE ROLE shieldlink_app LOGIN PASSWORD '...'"
psql "$DATABASE_URL_ADMIN" -f schema.sql
```

| Variable | Where to get it |
| -------- | --------------- |
| `DATABASE_URL` | Connection string for `shieldlink_app`. Any PostgreSQL works; the project speaks plain SQL, not a vendor SDK |
| `DATABASE_URL_ADMIN` | The owner's connection string. Local only, for `schema.sql`; never set it on Vercel |
| `VIRUSTOTAL_API_KEY` | virustotal.com → your profile → API key |

None carries a `PUBLIC_` prefix on purpose: Astro exposes `PUBLIC_*` to client bundles.

## Checking the configuration

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

A missing connection string and a wrong one otherwise look identical from outside — the
scanner keeps answering, just without its cache, quietly spending VirusTotal quota on
every request until the daily limit runs out. The endpoint reports booleans, the Node
version and, when the database is unreachable, the driver's error message; no value,
prefix or length of any secret is exposed.

---

Built by Bryan Belandria — [github.com/BryanBel](https://github.com/BryanBel)
