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
