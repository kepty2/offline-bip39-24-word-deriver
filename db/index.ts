import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export function getDb() {
  if (!env.DB) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Configure a `DB` binding in your chosen Cloudflare deployment before using the optional database example."
    );
  }

  return drizzle(env.DB, { schema });
}
