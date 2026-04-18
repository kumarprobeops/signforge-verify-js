# @signforge/verify

Verify [SignForge](https://signforge.io)-signed documents offline. No account needed, no internet needed for cryptographic verification.

[![npm version](https://img.shields.io/npm/v/@signforge/verify)](https://www.npmjs.com/package/@signforge/verify)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What This Verifies

Every SignForge-signed document contains a cryptographic proof bundle. This package verifies:

- **W3C Verifiable Credential** — ECDSA P-256 DataIntegrityProof (ecdsa-jcs-2019)
- **JAdES JWS** — EU-standard ES256 compact signature
- **Merkle transparency proof** — RFC 6962 inclusion proof against a signed tree head
- **RFC 3161 timestamp** — DigiCert TSA timestamp presence
- **Signer identity credentials** — per-signer W3C VCs
- **DID:web platform identity** — DID document snapshot

## Install

```bash
npm install @signforge/verify
```

**Zero runtime dependencies.** Uses Node.js built-in Web Crypto API (Node 18+).

## Quick Start

```javascript
import { SignForgeVerifier } from '@signforge/verify';

const verifier = new SignForgeVerifier();

// Verify a .proof.html file
const html = fs.readFileSync('document.proof.html', 'utf-8');
const result = await verifier.verifyFromHtml(html);
console.log(result.valid); // true

// Verify a signed PDF
const pdf = fs.readFileSync('document-signed.pdf');
const result = await verifier.verifyFromPdf(pdf);
console.log(result.valid); // true

// Verify a proof bundle directly
const bundle = JSON.parse(fs.readFileSync('proof-bundle.json', 'utf-8'));
const result = await verifier.verify(bundle);
```

## CLI Usage

```bash
# Verify a proof document
npx @signforge/verify document.proof.html

# Verify a signed PDF
npx @signforge/verify document-signed.pdf

# JSON output
npx @signforge/verify document-signed.pdf --json
```

Example output:
```
============================================================
  SignForge Proof Verifier
============================================================
  File: document.proof.html
  Format: v1.0

  ✓  Vc Signature: ECDSA P-256 DataIntegrityProof verified
  ✓  Jades Jws: ES256 JAdES JWS verified
  ✓  Merkle Proof: Merkle inclusion verified (tree size: 23)
  •  Timestamp: RFC 3161 timestamp from DigiCert at 2026-04-15T11:56:56Z
  ✓  Signer Identities: 1 signer identity VC(s) verified
  •  Did Snapshot: DID document captured at 2026-04-15T11:56:56Z

  ✅ DOCUMENT VERIFIED
============================================================
```

## API Reference

### `SignForgeVerifier`

#### `extractFromHtml(html: string): ProofBundle | null`

Extract the proof bundle from a `.proof.html` string.

#### `extractFromPdf(pdfBuffer: Buffer): ProofBundle | null`

Extract the proof bundle from a signed PDF buffer. Works with uncompressed PDF streams.

#### `verify(bundle: ProofBundle): Promise<VerifyResult>`

Run all verification checks on a proof bundle.

#### `verifyFromHtml(html: string): Promise<VerifyResult>`

Convenience: extract + verify in one call.

#### `verifyFromPdf(pdfBuffer: Buffer): Promise<VerifyResult>`

Convenience: extract from PDF + verify in one call.

### `VerifyResult`

```typescript
interface VerifyResult {
  checks: Record<string, CheckResult>;
  valid: boolean;
  error?: string;
  formatVersion?: string;
}

interface CheckResult {
  status: string;  // 'pass' | 'FAIL' | 'present' | 'skip' | 'error'
  detail?: string;
}
```

## How It Works

SignForge embeds a W3C Verifiable Credential and supporting cryptographic proofs inside every signed document. This verifier:

1. Extracts the proof bundle from the document
2. Imports the embedded ECDSA P-256 public key
3. Verifies the VC signature using JCS canonicalization (RFC 8785)
4. Verifies the JAdES JWS signature
5. Verifies Merkle inclusion against the transparency log tree head
6. Reports timestamp and identity credential status

All verification happens locally — no network requests, no SignForge servers involved.

[Verification Architecture](https://signforge.io/docs/verification-architecture) | [Proof Format Spec](https://signforge.io/docs/proof-format)

## Related

- [SignForge](https://signforge.io) — Free e-signature platform
- [signforge-verify (Python)](https://pypi.org/project/signforge-verify/) — Python verification package

## License

MIT
