/**
 * Registration data over RDAP, the structured successor to WHOIS. Free, keyless, and
 * answered by the registries themselves — no aggregator in between:
 *
 * - Domains: IANA's bootstrap file maps each TLD to the registry that runs it (Verisign
 *   for .com, CentralNic for .xyz…). It is fetched once per function instance and reused.
 *   Some TLDs, .ve among them, publish no RDAP service at all.
 * - IPs: ARIN answers for its own blocks and redirects to the regional registry that owns
 *   any other (RIPE, LACNIC, APNIC, AFRINIC).
 *
 * Neither function throws. A TLD without RDAP, a timeout or a registry that answers oddly
 * all come back as `{ disponible: false }`, and the report says so.
 */

const TIEMPO_MS = 3000;
const BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_VIGENCIA_MS = 24 * 60 * 60 * 1000;
// Registries sit behind bot protection that refuses requests with no identifiable client.
const CABECERAS = { 'user-agent': 'ShieldLink/2.0 (+https://shield-link.vercel.app)', accept: 'application/rdap+json, application/json' };

async function pedirJson(url) {
  try {
    const respuesta = await fetch(url, { headers: CABECERAS, signal: AbortSignal.timeout(TIEMPO_MS) });
    if (!respuesta.ok) return null;
    return await respuesta.json();
  } catch {
    return null;
  }
}

let bootstrap = null;
let bootstrapHasta = 0;

/** TLD → registry RDAP base URL, from IANA. Cached for a day per function instance. */
async function servidores() {
  if (bootstrap && Date.now() < bootstrapHasta) return bootstrap;
  const datos = await pedirJson(BOOTSTRAP);
  if (!datos?.services) return bootstrap;
  const mapa = new Map();
  for (const [tlds, urls] of datos.services) {
    const base = urls.find((u) => u.startsWith('https://')) ?? urls[0];
    for (const tld of tlds) mapa.set(tld.toLowerCase(), base.endsWith('/') ? base : `${base}/`);
  }
  bootstrap = mapa;
  bootstrapHasta = Date.now() + BOOTSTRAP_VIGENCIA_MS;
  return bootstrap;
}

const evento = (datos, accion) => datos.events?.find((e) => e.eventAction === accion)?.eventDate ?? null;

/** The `fn` (formatted name) of the first entity holding `rol`, from its jCard. */
function nombreEntidad(entidades = [], rol) {
  const entidad = entidades.find((e) => e.roles?.includes(rol));
  const fn = entidad?.vcardArray?.[1]?.find((campo) => campo[0] === 'fn');
  return fn?.[3] || null;
}

export async function rdapDominio(dominio) {
  const mapa = await servidores();
  const base = mapa?.get(dominio.split('.').at(-1).toLowerCase());
  if (!base) return { disponible: false };

  const datos = await pedirJson(`${base}domain/${encodeURIComponent(dominio)}`);
  if (!datos) return { disponible: false };
  return {
    disponible: true,
    dominio,
    creado: evento(datos, 'registration'),
    expira: evento(datos, 'expiration'),
    actualizado: evento(datos, 'last changed'),
    registrador: nombreEntidad(datos.entities, 'registrar'),
    estados: (datos.status ?? []).slice(0, 6),
  };
}

export async function rdapIp(ip) {
  const datos = await pedirJson(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`);
  if (!datos) return { disponible: false };
  return {
    disponible: true,
    red: datos.name ?? null,
    organizacion: nombreEntidad(datos.entities, 'registrant') ?? nombreEntidad(datos.entities, 'administrative'),
    pais: datos.country ?? null,
  };
}
