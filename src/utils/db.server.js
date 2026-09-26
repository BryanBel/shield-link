import { neon } from '@neondatabase/serverless';

/**
 * Acceso a la base de reputacion. Solo servidor.
 *
 * El driver serverless de Neon habla por HTTP en vez de mantener una conexion TCP
 * abierta, que es lo que corresponde aqui: cada peticion a /api/scan corre en una funcion
 * de Vercel que nace y muere con ella, y un pool de conexiones en ese contexto abre una
 * conexion por invocacion hasta agotar el limite de la base.
 *
 * Nunca importes esto desde algo que llegue al navegador. DATABASE_URL da acceso completo
 * a la base, y Astro empaqueta lo que un script de cliente importe. La variable no lleva
 * prefijo PUBLIC_, asi que Astro se niega a exponerla incluso por accidente.
 *
 * Vercel inyecta las variables en tiempo de ejecucion, asi que se lee process.env primero
 * y se cae a import.meta.env para `astro dev` en local.
 */
export function getSql() {
  const connectionString = process.env.DATABASE_URL ?? import.meta.env.DATABASE_URL;
  if (!connectionString) return null;

  return neon(connectionString);
}
