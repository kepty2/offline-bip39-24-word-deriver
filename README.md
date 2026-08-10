# Offline BIP-39 / BIP84 Watch-Only Deriver

The deployed site serves `public/offline-bip39-24-word-deriver.html` as a single,
downloadable, offline-capable file. It converts exactly 256 entropy bits into a
24-word BIP39 mnemonic and, only after a separate user action, derives the
public metadata for Bitcoin mainnet account `m/84'/0'/0'`. It never offers a
private-key export or any spending function.

The restrictive inline CSP retains `connect-src 'none'`; all cryptographic and
QR code dependencies are bundled into the HTML at build time.

## Reproducible wallet bundle

Run:

```bash
npm ci
npm run bundle:wallet
npm test
```

`scripts/bundle-wallet-crypto.mjs` uses esbuild to create a browser IIFE from
`src/wallet-crypto-lib.js`, injects it between the marked boundaries in the
standalone HTML, and records the SHA-256 of the exact embedded code in both a
script data attribute and the on-page dependency note. The current embedded
bundle SHA-256 is:

```text
a7cdd76d40497be421cf153fb5d5c3f8814cdd7d07bda5acc38dcce26207ef63
```

Pinned production/build components:

| Package | Version | Source | License | npm release integrity |
| --- | ---: | --- | --- | --- |
| `@scure/bip32` | 2.2.0 | https://github.com/paulmillr/scure-bip32 | MIT | `sha512-zFr7t2F+a9+5tB7QbarF2HQNYrgjCNaoLAupZdKkrFMYMozJf5zqH2WJCQibMzm1qQ0QogrxVGO3qXfQDYMaQg==` |
| `@noble/curves` | 2.2.0 | https://github.com/paulmillr/noble-curves | MIT | `sha512-T/BoHgFXirb0ENSPBquzX0rcjXeM6Lo892a2jlYJkqk83LqZx0l1Of7DzlKJ6jkpvMrkHSnAcgb5JegL8SeIkQ==` |
| `@noble/hashes` | 2.2.0 | https://github.com/paulmillr/noble-hashes | MIT | `sha512-IYqDGiTXab6FniAgnSdZwgWbomxpy9FtYvLKs7wCUs2a8RkITG+DFGO1DM9cr+E3/RgADRpFjrKVaJ1z6sjtEg==` |
| `@scure/base` | 2.2.0 | https://github.com/paulmillr/scure-base | MIT | `sha512-b8XEupJibegiXV+tDUseI8oLQc8ei3d/4Jkb2RpbHh3MfE054ov3uIz2dhFkB3FI8iwYkEh0gGCApkrYggkPNg==` |
| `qr` | 0.6.0 | https://github.com/paulmillr/qr | MIT or Apache-2.0 | `sha512-P23VoX7SipHALdiIYG+D+LT/6n22dNKwV92FAb3d+Nlki/5WisSsfLt0UDFz2XEBtuwrECTznvu+chKKFCSYhA==` |
| `esbuild` | 0.28.1 | https://github.com/evanw/esbuild | MIT | `sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==` |

Dev-only cross-validation uses independent `bip39` 3.1.0, `bip32` 5.0.1,
`tiny-secp256k1` 2.2.4 and `bitcoinjs-lib` 7.0.1. These packages are not
included in the offline browser bundle.

## Security boundary

The application overwrites mutable seed and temporary input byte arrays and
wipes private HD node state before returning public account information, but
JavaScript cannot guarantee secure memory erasure. Copies may remain in the
browser, runtime, operating system, swap, screenshots, extensions, or malware.
Inspect the downloaded source and use a clean, permanently offline machine for
real wallet entropy.

## Development

The wallet itself is the standalone file at
`public/offline-bip39-24-word-deriver.html`. It can be opened directly from a
local disk without a web server. The included
[vinext](https://github.com/cloudflare/vinext) and Cloudflare Worker files are
an optional, provider-neutral way to serve that same file at `/`.

The project contains no sign-in helpers, identity headers, authentication
routes, cookies, or provider-specific hosting metadata. The application is
public and anonymous; it does not require an account to run.

### Prerequisites

- Node.js `>=22.13.0`

## Quick Start

```bash
npm install
npm run dev
npm run build
```

### Project structure

- `public/offline-bip39-24-word-deriver.html`: complete downloadable application
- `src/wallet-crypto-lib.js`: reviewed cryptographic library composition
- `scripts/bundle-wallet-crypto.mjs`: deterministic bundling and injection
- `tests/offline-deriver.test.mjs`: security, standards and integration tests
- `worker/index.ts`: optional generic Cloudflare Worker entry point

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: verify the optional web-hosting build
- `npm test`: build and run all offline wallet tests
- `npm run db:generate`: generate Drizzle migrations after schema changes

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
- [Drizzle D1 Guide](https://orm.drizzle.team/docs/get-started/d1-new)
