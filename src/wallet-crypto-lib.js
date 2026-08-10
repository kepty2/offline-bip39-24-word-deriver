import { HDKey } from "@scure/bip32";
import { bech32 } from "@scure/base";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import encodeQR from "qr";

const MAINNET_VERSIONS = Object.freeze({ private: 0x0488ade4, public: 0x0488b21e });
const ZPUB_VERSIONS = Object.freeze({ private: 0x04b2430c, public: 0x04b24746 });
const ACCOUNT_PATH = "m/84'/0'/0'";
const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\\ \"";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHECKSUM_GENERATORS = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
const textEncoder = new TextEncoder();

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value) {
  if (!/^[0-9a-f]*$/i.test(value) || value.length % 2) throw new Error("Invalid hexadecimal input.");
  return Uint8Array.from(value.match(/../g) || [], (byte) => Number.parseInt(byte, 16));
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

function publicOnlyNode(node, versions = MAINNET_VERSIONS) {
  if (!node.publicKey || !node.chainCode) throw new Error("Public account node is incomplete.");
  return new HDKey({
    versions,
    depth: node.depth,
    index: node.index,
    parentFingerprint: node.parentFingerprint,
    chainCode: Uint8Array.from(node.chainCode),
    publicKey: Uint8Array.from(node.publicKey),
  });
}

function serializePublicNode(node, versions) {
  return publicOnlyNode(node, versions).publicExtendedKey;
}

export function mnemonicToSeed(mnemonic, passphrase = "") {
  const normalizedMnemonic = mnemonic.normalize("NFKD");
  const normalizedSalt = ("mnemonic" + passphrase.normalize("NFKD")).normalize("NFKD");
  const passwordBytes = textEncoder.encode(normalizedMnemonic);
  const saltBytes = textEncoder.encode(normalizedSalt);
  try {
    return pbkdf2(sha512, passwordBytes, saltBytes, { c: 2048, dkLen: 64 });
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
  }
}

function descriptorPolymod(symbols) {
  let checksum = 1n;
  for (const symbol of symbols) {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x7ffffffffn) << 5n) ^ BigInt(symbol);
    for (let index = 0; index < 5; index += 1) {
      if ((top >> BigInt(index)) & 1n) checksum ^= CHECKSUM_GENERATORS[index];
    }
  }
  return checksum;
}

export function descriptorChecksum(descriptor) {
  const symbols = [];
  let group = 0;
  let groupCount = 0;
  for (const character of descriptor) {
    const position = INPUT_CHARSET.indexOf(character);
    if (position === -1) throw new Error(`Unsupported descriptor character: ${character}`);
    symbols.push(position & 31);
    group = group * 3 + (position >> 5);
    groupCount += 1;
    if (groupCount === 3) {
      symbols.push(group);
      group = 0;
      groupCount = 0;
    }
  }
  if (groupCount > 0) symbols.push(group);
  symbols.push(0, 0, 0, 0, 0, 0, 0, 0);
  const result = descriptorPolymod(symbols) ^ 1n;
  let output = "";
  for (let index = 0; index < 8; index += 1) {
    output += CHECKSUM_CHARSET[Number((result >> BigInt(5 * (7 - index))) & 31n)];
  }
  return output;
}

export function withDescriptorChecksum(descriptor) {
  return `${descriptor}#${descriptorChecksum(descriptor)}`;
}

export function p2wpkhAddress(publicKey) {
  const program = hash160(publicKey);
  return bech32.encode("bc", [0, ...bech32.toWords(program)], 90);
}

export function deriveAddress(accountPublicNode, branch, index) {
  if (branch !== 0 && branch !== 1) throw new Error("Only receive (0) and change (1) branches are supported.");
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) throw new Error("Address index is out of range.");
  const node = accountPublicNode.deriveChild(branch).deriveChild(index);
  if (!node.publicKey) throw new Error("Derived public key is unavailable.");
  return p2wpkhAddress(node.publicKey);
}

export function accountPublicFromXpub(xpub) {
  const node = HDKey.fromExtendedKey(xpub, MAINNET_VERSIONS);
  if (node.privateKey) throw new Error("Private extended keys are not accepted.");
  return node;
}

export function deriveWatchOnly(mnemonic, passphrase = "") {
  let seed;
  let master;
  let accountPrivate;
  try {
    seed = mnemonicToSeed(mnemonic, passphrase);
    master = HDKey.fromMasterSeed(seed, MAINNET_VERSIONS);
    if (!master.publicKey) throw new Error("Master public key derivation failed.");
    const masterFingerprint = bytesToHex(hash160(master.publicKey).slice(0, 4));
    accountPrivate = master.derive(ACCOUNT_PATH);
    const accountPublic = publicOnlyNode(accountPrivate, MAINNET_VERSIONS);
    const accountXpub = accountPublic.publicExtendedKey;
    const accountZpub = serializePublicNode(accountPublic, ZPUB_VERSIONS);
    const origin = `[${masterFingerprint}/84h/0h/0h]${accountXpub}`;
    const receiveDescriptor = withDescriptorChecksum(`wpkh(${origin}/0/*)`);
    const changeDescriptor = withDescriptorChecksum(`wpkh(${origin}/1/*)`);
    const firstReceiveAddress = deriveAddress(accountPublic, 0, 0);
    return {
      accountPublic,
      masterFingerprint,
      accountXpub,
      accountZpub,
      receiveDescriptor,
      changeDescriptor,
      firstReceiveAddress,
    };
  } finally {
    if (seed) seed.fill(0);
    if (accountPrivate) accountPrivate.wipePrivateData();
    if (master) master.wipePrivateData();
  }
}

export function createWatchOnlyPackage(publicWallet) {
  return {
    format: "offline-bip39-watch-only-v1",
    network: "bitcoin-mainnet",
    wallet_type: "single-sig",
    script_type: "p2wpkh",
    standard: "BIP84",
    account: 0,
    master_fingerprint: publicWallet.masterFingerprint,
    account_path: ACCOUNT_PATH,
    account_xpub: publicWallet.accountXpub,
    account_zpub: publicWallet.accountZpub,
    receive_descriptor: publicWallet.receiveDescriptor,
    change_descriptor: publicWallet.changeDescriptor,
    first_receive_path: `${ACCOUNT_PATH}/0/0`,
    first_receive_address: publicWallet.firstReceiveAddress,
  };
}

export function drawQr(canvas, text, options = {}) {
  const matrix = encodeQR(text, "raw", { ecc: options.ecc || "medium", encoding: "byte", border: 4 });
  const scale = Math.max(2, Math.floor((options.maxSize || 300) / matrix.length));
  const size = matrix.length * scale;
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext("2d", { alpha: false });
  if (!context) throw new Error("Canvas rendering is unavailable.");
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, size, size);
  context.fillStyle = "#111111";
  matrix.forEach((row, y) => row.forEach((dark, x) => {
    if (dark) context.fillRect(x * scale, y * scale, scale, scale);
  }));
}

export function clearQr(canvas) {
  const context = canvas.getContext("2d");
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);
  canvas.width = 0;
  canvas.height = 0;
}

export function runWalletSelfTests() {
  const checks = [];
  const check = (name, passed) => {
    checks.push({ name, passed: Boolean(passed) });
    if (!passed) throw new Error(`Wallet cryptographic self-test failed: ${name}`);
  };

  const bip39Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  let seedEmpty;
  let seedTrezor;
  let root;
  let rootVectorTwo;
  let account;
  try {
    seedEmpty = mnemonicToSeed(bip39Mnemonic, "");
    check("BIP39 empty passphrase", bytesToHex(seedEmpty) === "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
    seedTrezor = mnemonicToSeed(bip39Mnemonic, "TREZOR");
    check("BIP39 nonempty passphrase", bytesToHex(seedTrezor) === "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    const composed = mnemonicToSeed(bip39Mnemonic, "caf\u00e9");
    const decomposed = mnemonicToSeed(bip39Mnemonic.normalize("NFKD"), "cafe\u0301");
    check("BIP39 Unicode NFKD", equalBytes(composed, decomposed));
    composed.fill(0);
    decomposed.fill(0);

    root = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"), MAINNET_VERSIONS);
    check("BIP32 master vector", root.publicExtendedKey === "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    rootVectorTwo = HDKey.fromMasterSeed(hexToBytes("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"), MAINNET_VERSIONS);
    check("BIP32 second master vector", rootVectorTwo.publicExtendedKey === "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
    const hardened = root.derive("m/0'");
    check("BIP32 hardened child", hardened.depth === 1 && hardened.index === 0x80000000);
    const privateGrandchild = hardened.deriveChild(1);
    const publicGrandchild = publicOnlyNode(hardened).deriveChild(1);
    check("BIP32 public child", equalBytes(privateGrandchild.publicKey, publicGrandchild.publicKey));
    const parsed = HDKey.fromExtendedKey(publicGrandchild.publicExtendedKey, MAINNET_VERSIONS);
    check("BIP32 XPUB parse", equalBytes(parsed.publicKey, publicGrandchild.publicKey));
    let hardenedRejected = false;
    try { publicOnlyNode(root).deriveChild(0x80000000); } catch { hardenedRejected = true; }
    check("BIP32 hardened XPUB rejection", hardenedRejected);

    const wallet = deriveWatchOnly(bip39Mnemonic, "");
    account = wallet.accountPublic;
    check("BIP84 account ZPUB", wallet.accountZpub === "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
    check("BIP84 receive 0", wallet.firstReceiveAddress === "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    check("BIP84 receive 1", deriveAddress(account, 0, 1) === "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    check("BIP84 change 0", deriveAddress(account, 1, 0) === "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    check("BIP380 checksum", descriptorChecksum("raw(deadbeef)") === "89f8spxm");
    check("Descriptor receive branch", wallet.receiveDescriptor.includes("]" + wallet.accountXpub + "/0/*)#"));
    check("Descriptor change branch", wallet.changeDescriptor.includes("]" + wallet.accountXpub + "/1/*)#"));
    check("Descriptor address parity", deriveAddress(accountPublicFromXpub(wallet.accountXpub), 0, 0) === wallet.firstReceiveAddress);
    return { passed: true, checks };
  } finally {
    if (seedEmpty) seedEmpty.fill(0);
    if (seedTrezor) seedTrezor.fill(0);
    if (account) account.wipePrivateData();
    if (root) root.wipePrivateData();
    if (rootVectorTwo) rootVectorTwo.wipePrivateData();
  }
}

export const walletConstants = Object.freeze({ ACCOUNT_PATH });
