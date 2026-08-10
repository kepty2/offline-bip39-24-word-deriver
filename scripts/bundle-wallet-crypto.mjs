import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { build } from "esbuild";

const htmlUrl = new URL("../public/offline-bip39-24-word-deriver.html", import.meta.url);
const sourceUrl = new URL("../src/wallet-crypto-lib.js", import.meta.url);
const startMarker = "/* WALLET_CRYPTO_BUNDLE_START */";
const endMarker = "/* WALLET_CRYPTO_BUNDLE_END */";

const result = await build({
  entryPoints: [sourceUrl.pathname],
  bundle: true,
  format: "iife",
  globalName: "WalletCrypto",
  minify: true,
  platform: "browser",
  target: ["es2020"],
  write: false,
  legalComments: "none",
});

const bundle = new TextDecoder().decode(result.outputFiles[0].contents).trim();
const digest = createHash("sha256").update(bundle).digest("hex");
const html = await readFile(htmlUrl, "utf8");
const start = html.indexOf(startMarker);
const end = html.indexOf(endMarker);
if (start === -1 || end === -1 || end <= start) throw new Error("Wallet crypto bundle markers are missing from the standalone HTML.");

const replacement = `${startMarker}\n${bundle}\n${endMarker}`;
let updated = html.slice(0, start) + replacement + html.slice(end + endMarker.length);
updated = updated.replace(/data-crypto-bundle-sha256="[0-9a-f]*"/, `data-crypto-bundle-sha256="${digest}"`);
updated = updated.replace(/(<code id="cryptoBundleHash">)[0-9a-f]*(<\/code>)/, `$1${digest}$2`);
await writeFile(htmlUrl, updated);
console.log(`Embedded wallet cryptography bundle SHA-256: ${digest}`);
