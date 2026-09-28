/**
 * Reference lists the signals are measured against. Kept apart from the logic so they can
 * grow without touching it: adding a brand, a shortener or a TLD is a one-line change here.
 */

/**
 * TLDs that turn up disproportionately in phishing and malware campaigns. A link under one
 * of them is called dangerous outright and never costs a VirusTotal lookup.
 */
export const TLDS_PELIGROSOS = ['.xyz', '.zip', '.mov', '.tk', '.fit', '.icu', '.top'];

/** Link shorteners: the link says nothing about where it goes, so the destination decides. */
export const ACORTADORES = new Set([
  'bit.ly', 'bit.do', 'buff.ly', 'cutt.ly', 'goo.gl', 'is.gd', 'lnkd.in', 'ow.ly', 'qrco.de',
  'rb.gy', 'rebrand.ly', 's.id', 'shorturl.at', 't.co', 't.ly', 'tiny.cc', 'tinyurl.com', 'v.gd',
]);

/**
 * Hosts where anyone can publish a page. Their domain is popular and old, but that says
 * nothing about a page someone uploaded yesterday — and phishing kits live on exactly these.
 * A host matches an entry if it is the entry or a subdomain of it.
 */
export const PLATAFORMAS_ABIERTAS = [
  'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'storage.googleapis.com',
  'firebasestorage.googleapis.com', 'web.app', 'firebaseapp.com', 'github.io', 'githubusercontent.com',
  'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'r2.dev', 'blogspot.com', 'wixsite.com',
  'weebly.com', 'webflow.io', 'glitch.me', 'herokuapp.com', 'onrender.com', '000webhostapp.com',
  'azurewebsites.net', 's3.amazonaws.com', 'notion.site', 'canva.site', 'my.canva.site',
  'forms.office.com', 'sharepoint.com', '1drv.ms', 'dropbox.com', 'myshopify.com', 'linktr.ee',
  'wordpress.com', 'godaddysites.com', 'square.site', 'jimdosite.com', 'carrd.co', 'replit.app',
];

/**
 * Well-known engines, named when they call a flagged URL clean: "90 others, Kaspersky and
 * ESET among them" says more than a bare count.
 */
export const MOTORES_DESTACADOS = ['Kaspersky', 'ESET', 'BitDefender', 'Sophos', 'Fortinet', 'PhishTank', 'OpenPhish', 'URLhaus', 'Webroot', 'Trustwave'];

/**
 * How particular engines work, so a lone detection can be read in context. Only engines
 * whose method is documented by their own vendor are described — the rest are shown with
 * what they report, and nothing is guessed.
 */
export const NOTAS_MOTORES = {
  'Bfore.Ai PreCrime':
    'es un motor predictivo: señala dominios con patrones que podrían usarse en ataques, antes de que ocurra alguno. Es una predicción, no un ataque detectado.',
};

/**
 * Brands phishing most often impersonates, with the registrable domains that really belong
 * to them. `claves` are matched as whole words in a page title and as parts of a domain
 * name; a brand named on a domain it does not own is what the signals look for.
 */
export const MARCAS = [
  { nombre: 'PayPal', claves: ['paypal'], dominios: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  {
    nombre: 'Microsoft',
    claves: ['microsoft', 'outlook', 'office365', 'hotmail', 'onedrive'],
    dominios: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'hotmail.com', 'onedrive.com', 'sharepoint.com', 'msn.com'],
  },
  { nombre: 'Apple', claves: ['apple', 'icloud'], dominios: ['apple.com', 'icloud.com'] },
  { nombre: 'Google', claves: ['google', 'gmail'], dominios: ['google.com', 'gmail.com', 'youtube.com', 'google.co.ve', 'googleusercontent.com'] },
  { nombre: 'Amazon', claves: ['amazon'], dominios: ['amazon.com', 'amazon.es', 'amazon.co.uk', 'amazonaws.com'] },
  { nombre: 'Netflix', claves: ['netflix'], dominios: ['netflix.com'] },
  { nombre: 'Facebook', claves: ['facebook'], dominios: ['facebook.com', 'fb.com', 'meta.com'] },
  { nombre: 'Instagram', claves: ['instagram'], dominios: ['instagram.com'] },
  { nombre: 'WhatsApp', claves: ['whatsapp'], dominios: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { nombre: 'Binance', claves: ['binance'], dominios: ['binance.com'] },
  { nombre: 'Coinbase', claves: ['coinbase'], dominios: ['coinbase.com'] },
  { nombre: 'DHL', claves: ['dhl'], dominios: ['dhl.com', 'dhl.de'] },
  { nombre: 'Mercado Libre', claves: ['mercadolibre', 'mercado libre'], dominios: ['mercadolibre.com', 'mercadolibre.com.ve'] },
  { nombre: 'Banesco', claves: ['banesco'], dominios: ['banesco.com', 'banesco.com.pa', 'banescousa.com'] },
  { nombre: 'Banco de Venezuela', claves: ['banco de venezuela', 'bdvenlinea', 'banvenez'], dominios: ['banvenez.com', 'bancodevenezuela.com'] },
  { nombre: 'Mercantil', claves: ['mercantil'], dominios: ['mercantilbanco.com', 'mercantilbanco.com.pa'] },
  { nombre: 'BBVA Provincial', claves: ['provincial', 'bbva'], dominios: ['provincial.com', 'bbva.com'] },
  { nombre: 'BNC', claves: ['bncenlinea', 'banco nacional de credito'], dominios: ['bncenlinea.com', 'bnc.com.ve'] },
];
