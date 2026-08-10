import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { BIP32Factory } from "bip32";
import * as bip39 from "bip39";
import { networks, payments } from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import {
  accountPublicFromXpub,
  createWatchOnlyPackage,
  deriveAddress,
  deriveWatchOnly,
  descriptorChecksum,
  mnemonicToSeed,
  runWalletSelfTests,
} from "../src/wallet-crypto-lib.js";

const html = await readFile(
  new URL("../public/offline-bip39-24-word-deriver.html", import.meta.url),
  "utf8",
);
const cryptoSource = await readFile(new URL("../src/wallet-crypto-lib.js", import.meta.url), "utf8");
const inlineScripts = [...html.matchAll(/<script[^>]*>\s*([\s\S]*?)<\/script>/g)].map((match) => match[1]);
const inlineScript = inlineScripts.at(-1);
assert.equal(inlineScripts.length, 2, "standalone HTML contains local crypto and application scripts");
assert.ok(inlineScript, "standalone HTML contains its application script");

const pureLogic = inlineScript.slice(0, inlineScript.indexOf("function setTest"));
const context = vm.createContext({
  crypto: webcrypto,
  TextEncoder,
  Uint8Array,
  Uint32Array,
  DataView,
  Array,
  Number,
  Math,
  Set,
});
vm.runInContext(
  `${pureLogic}\n;globalThis.deriver = { WORDLIST, WORDLIST_SHA256, ZERO_VECTOR_PHRASE, sha256JavaScript, sha256WebCrypto, hex, equalBytes, entropyToBytes, buildGroups };`,
  context,
);

test("standalone page has no external runtime resources or storage", () => {
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(html, /<script[^>]+src=/i);
  assert.doesNotMatch(html, /<link[^>]+href=/i);
  assert.doesNotMatch(html, /\b(?:fetch|XMLHttpRequest|localStorage|sessionStorage|indexedDB)\s*\(/);
  assert.doesNotMatch(html, /document\.cookie/);
});

test("embedded English wordlist is complete and hash-locked", () => {
  const { WORDLIST, WORDLIST_SHA256 } = context.deriver;
  assert.equal(WORDLIST.length, 2048);
  assert.equal(new Set(WORDLIST).size, 2048);
  assert.equal(WORDLIST[0], "abandon");
  assert.equal(WORDLIST[2047], "zoo");
  assert.equal(
    createHash("sha256").update(WORDLIST.join("\n")).digest("hex"),
    WORDLIST_SHA256,
  );
});

test("independent JavaScript SHA-256 passes known answers and Web Crypto cross-check", async () => {
  const { sha256JavaScript, sha256WebCrypto, hex, equalBytes } = context.deriver;
  const encoder = new TextEncoder();
  assert.equal(
    hex(sha256JavaScript(encoder.encode(""))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(
    hex(sha256JavaScript(encoder.encode("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  const sample = Uint8Array.from({ length: 32 }, (_, index) => index);
  assert.ok(equalBytes(sha256JavaScript(sample), await sha256WebCrypto(sample)));
});

test("256 all-zero bits derive abandon x 23 plus art with correct indices", () => {
  const { ZERO_VECTOR_PHRASE, sha256JavaScript, entropyToBytes, buildGroups } = context.deriver;
  const entropy = "0".repeat(256);
  const detail = buildGroups(entropy, sha256JavaScript(entropyToBytes(entropy)));
  assert.equal(detail.groups.length, 24);
  assert.equal(detail.checksum, "01100110");
  assert.equal(detail.phrase, ZERO_VECTOR_PHRASE);
  assert.deepEqual(
    { index: detail.groups[23].index, line: detail.groups[23].line, word: detail.groups[23].word },
    { index: 102, line: 103, word: "art" },
  );
});

test("input and concealment controls enforce the requested boundaries", () => {
  assert.match(inlineScript, /\/\^\[01\]\{256\}\$\//);
  assert.match(inlineScript, /setTimeout\(hidePhrase, 30000\)/);
  assert.match(inlineScript, /visibilitychange/);
  assert.match(inlineScript, /phraseOutput.*24-word phrase concealed/s);
  assert.doesNotMatch(html, /Copy revealed phrase/);
});

test("derivation table does not disclose indices or mnemonic words", () => {
  const tableHead = html.match(/<thead>([\s\S]*?)<\/thead>/)?.[1] ?? "";
  assert.match(tableHead, /Group/);
  assert.match(tableHead, /11-bit value/);
  assert.match(tableHead, /GitHub line/);
  assert.doesNotMatch(tableHead, /Index \(0-based\)|English word/);
  assert.match(
    inlineScript,
    /const values = \[String\(group\.number\).*group\.binary, String\(group\.line\)\]/,
  );
});

test("top download control targets the complete standalone HTML file", () => {
  assert.match(
    html,
    /<a class="download-button" href="\/offline-bip39-24-word-deriver\.html" download="offline-bip39-24-word-deriver\.html"/,
  );
  assert.match(html, /Download HTML/);
});

test("safety label uses the high-contrast eyebrow treatment", () => {
  assert.match(html, /<span class="eyebrow safety-label">Important<\/span>/);
  assert.match(html, /\.safety-label \{[^}]*color: var\(--ink\)/);
  assert.match(html, /\.eyebrow \{[^}]*background: var\(--lime\)/);
});

test("user flow uses one continuous seven-step sequence", () => {
  const labels = [...html.matchAll(/>Step (\d{2}) · ([^<]+)</g)].map((match) => `${match[1]}:${match[2]}`);
  assert.deepEqual(labels, [
    "01:Entropy",
    "02:Checksum and indices",
    "03:Final phrase",
    "04:Wallet settings",
    "05:Watch-only export",
    "06:Receiving addresses",
    "07:Verification checklist",
  ]);
  assert.doesNotMatch(html, />Section 0[5-8] ·/);
});

test("text-entry controls use a 16px font to avoid iPhone focus zoom", () => {
  assert.match(html, /textarea \{[^}]*font: 16px\/1\.8/s);
  assert.match(html, /\.field input, \.field select \{ font-size: 16px; \}/);
  assert.match(html, /textarea\.public-value \{[^}]*font-size: 16px;/);
  assert.doesNotMatch(html, /user-scalable\s*=\s*no|maximum-scale\s*=\s*1/i);
});

test("wallet cryptographic self-tests pass all required fixed vectors", () => {
  const result = runWalletSelfTests();
  assert.equal(result.passed, true);
  assert.equal(result.checks.length, 17);
  assert.ok(result.checks.every((check) => check.passed));
});

test("BIP39 passphrase handling matches an independent implementation", () => {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  for (const passphrase of ["", "TREZOR", "caf\u00e9"]) {
    const localSeed = mnemonicToSeed(mnemonic, passphrase);
    const independentSeed = bip39.mnemonicToSeedSync(mnemonic.normalize("NFKD"), passphrase.normalize("NFKD"));
    assert.equal(Buffer.from(localSeed).toString("hex"), independentSeed.toString("hex"));
    localSeed.fill(0);
    independentSeed.fill(0);
  }
});

test("BIP84 public account and addresses match independent bitcoinjs derivation", () => {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const wallet = deriveWatchOnly(mnemonic, "");
  const independentSeed = bip39.mnemonicToSeedSync(mnemonic);
  const independentAccount = BIP32Factory(ecc).fromSeed(independentSeed, networks.bitcoin).derivePath("m/84'/0'/0'").neutered();
  assert.equal(wallet.accountXpub, independentAccount.toBase58());
  for (const index of [0, 1, 2, 19, 20]) {
    const pubkey = independentAccount.derive(0).derive(index).publicKey;
    const independentAddress = payments.p2wpkh({ pubkey, network: networks.bitcoin }).address;
    assert.equal(deriveAddress(wallet.accountPublic, 0, index), independentAddress);
  }
  assert.equal(wallet.accountZpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
  assert.equal(wallet.firstReceiveAddress, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  independentSeed.fill(0);
});

test("descriptors, key origin and public package preserve watch-only metadata", () => {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const wallet = deriveWatchOnly(mnemonic, "");
  const publicPackage = createWatchOnlyPackage(wallet);
  assert.match(wallet.receiveDescriptor, /^wpkh\(\[[0-9a-f]{8}\/84h\/0h\/0h\]xpub.+\/0\/\*\)#[a-z0-9]{8}$/);
  assert.match(wallet.changeDescriptor, /^wpkh\(\[[0-9a-f]{8}\/84h\/0h\/0h\]xpub.+\/1\/\*\)#[a-z0-9]{8}$/);
  for (const descriptor of [wallet.receiveDescriptor, wallet.changeDescriptor]) {
    const [body, checksum] = descriptor.split("#");
    assert.equal(descriptorChecksum(body), checksum);
  }
  assert.equal(accountPublicFromXpub(wallet.accountXpub).privateKey, null);
  assert.equal(publicPackage.account_path, "m/84'/0'/0'");
  assert.equal(publicPackage.master_fingerprint, wallet.masterFingerprint);
  assert.equal(publicPackage.first_receive_address, wallet.firstReceiveAddress);
  assert.equal(Object.keys(publicPackage).some((key) => /seed|prv|private/i.test(key)), false);
});

test("passphrase fields and clear path enforce sensitive-state boundaries", () => {
  assert.match(html, /id="walletPassphrase"[^>]*autocomplete="off"[^>]*spellcheck="false"/);
  assert.match(html, /id="walletPassphraseConfirm"[^>]*autocomplete="off"[^>]*spellcheck="false"/);
  assert.doesNotMatch(html, /(?:localStorage|sessionStorage|indexedDB|document\.cookie)/);
  assert.match(cryptoSource, /seed\.fill\(0\)/);
  assert.match(inlineScript, /clearWalletState/);
  assert.match(inlineScript, /document\.querySelectorAll\("canvas"\)/);
});

test("wallet bundle is embedded, hash-locked and uses canvas QR without runtime fetches", () => {
  const bundle = html.match(/\/\* WALLET_CRYPTO_BUNDLE_START \*\/\n([\s\S]*?)\n\/\* WALLET_CRYPTO_BUNDLE_END \*\//)?.[1];
  const declaredHash = html.match(/data-crypto-bundle-sha256="([0-9a-f]{64})"/)?.[1];
  assert.ok(bundle);
  assert.ok(declaredHash);
  assert.equal(createHash("sha256").update(bundle).digest("hex"), declaredHash);
  assert.match(html, new RegExp(`<code id="cryptoBundleHash">${declaredHash}<\\/code>`));
  assert.match(inlineScript, /WalletCrypto\.drawQr\(canvas/);
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(html, /https?:\/\/[^\s"']+\.js/);
});
