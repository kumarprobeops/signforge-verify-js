/**
 * @signforge/verify — Standalone SignForge Document Verifier
 *
 * Verifies SignForge-signed documents offline using Web Crypto API.
 * Zero runtime dependencies. Works in Node.js (>=18) and browsers.
 *
 * @license MIT
 * @see https://signforge.io/verify
 */

import { webcrypto } from 'crypto';

// Use Node.js Web Crypto if globalThis.crypto is not available
const subtle = (globalThis.crypto?.subtle ?? (webcrypto as any).subtle) as SubtleCrypto;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface CheckResult {
  status: string;
  detail?: string;
  source?: string;
  tsa?: string;
  signingTime?: string;
  count?: number;
  capturedAt?: string;
}

export interface VerifyResult {
  checks: Record<string, CheckResult>;
  valid: boolean;
  error?: string;
  formatVersion?: string;
}

export interface ProofBundle {
  formatVersion?: string;
  type?: string;
  vc?: Record<string, any>;
  keys?: {
    issuer?: { publicKeyJwk?: JsonWebKey; did?: string };
    log?: { publicKeyJwk?: JsonWebKey; did?: string };
  };
  jades?: string;
  transparency?: {
    leaf_hash: string;
    merkle_proof: Array<{ hash: string; position: string }>;
    signed_tree_head: {
      root_hash?: string;
      root?: string;
      tree_size?: number;
      size?: number;
    };
  };
  timestamp?: {
    tsa?: string;
    tsa_name?: string;
    signingTime?: string;
    signing_time?: string;
  };
  signerIdentities?: Array<Record<string, any>>;
  didSnapshot?: {
    capturedAt?: string;
  };
  verification?: Record<string, any>;
}

// ---------------------------------------------------------------------------
// Base58btc decoding
// ---------------------------------------------------------------------------

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP: Record<string, bigint> = {};
for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = BigInt(i);

function b58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    if (!(c in B58_MAP)) throw new Error(`Invalid base58 char: ${c}`);
    n = n * 58n + B58_MAP[c];
  }
  let leadingZeros = 0;
  for (const c of s) { if (c === '1') leadingZeros++; else break; }
  if (n === 0n) return new Uint8Array(leadingZeros);
  const hex = n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}

function multibaseB58Decode(s: string): Uint8Array {
  if (!s.startsWith('z')) throw new Error("Expected 'z' multibase prefix");
  return b58Decode(s.slice(1));
}

// ---------------------------------------------------------------------------
// JWK import
// ---------------------------------------------------------------------------

async function importJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return await subtle.importKey(
    'jwk', { ...jwk, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify']
  );
}

// ---------------------------------------------------------------------------
// JCS canonicalization (RFC 8785)
// ---------------------------------------------------------------------------

function jcsCanonical(obj: any): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(jcsCanonical).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + jcsCanonical(obj[k])).join(',') + '}';
}

// ---------------------------------------------------------------------------
// Hex / Base64url utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = Buffer.from(s, 'base64');
  return new Uint8Array(bin);
}

async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await subtle.digest('SHA-256', buf as unknown as BufferSource);
  return new Uint8Array(hash);
}

// ---------------------------------------------------------------------------
// DER signature encoding/decoding
// ---------------------------------------------------------------------------

function derSigToRaw(derBytes: Uint8Array): Uint8Array {
  let offset = 2;
  if (derBytes[0] !== 0x30) throw new Error('Not a DER SEQUENCE');
  if (derBytes[offset] !== 0x02) throw new Error('Expected INTEGER tag for R');
  const rLen = derBytes[offset + 1];
  const rBytes = derBytes.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  if (derBytes[offset] !== 0x02) throw new Error('Expected INTEGER tag for S');
  const sLen = derBytes[offset + 1];
  const sBytes = derBytes.slice(offset + 2, offset + 2 + sLen);
  const raw = new Uint8Array(64);
  const rTrimmed = rBytes[0] === 0 && rLen > 32 ? rBytes.slice(1) : rBytes;
  const sTrimmed = sBytes[0] === 0 && sLen > 32 ? sBytes.slice(1) : sBytes;
  raw.set(rTrimmed, 32 - rTrimmed.length);
  raw.set(sTrimmed, 64 - sTrimmed.length);
  return raw;
}

// ---------------------------------------------------------------------------
// SignForgeVerifier class
// ---------------------------------------------------------------------------

export class SignForgeVerifier {

  /**
   * Verify a VC's DataIntegrityProof (ecdsa-jcs-2019)
   */
  async verifyVcSignature(vc: Record<string, any>, publicKey: CryptoKey): Promise<boolean> {
    try {
      const proof = vc.proof;
      if (!proof || proof.type !== 'DataIntegrityProof') return false;

      const proofValue = proof.proofValue;
      const derSigBytes = multibaseB58Decode(proofValue);
      const rawSig = derSigToRaw(derSigBytes);

      const vcNoProof: Record<string, any> = {};
      for (const [k, v] of Object.entries(vc)) {
        if (k !== 'proof') vcNoProof[k] = v;
      }
      const vcHash = await sha256(jcsCanonical(vcNoProof));

      const proofOptions: Record<string, any> = {};
      for (const [k, v] of Object.entries(proof)) {
        if (k !== 'proofValue') proofOptions[k] = v;
      }
      const optionsHash = await sha256(jcsCanonical(proofOptions));

      const combined = new Uint8Array(optionsHash.length + vcHash.length);
      combined.set(optionsHash, 0);
      combined.set(vcHash, optionsHash.length);

      return await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        rawSig as unknown as BufferSource,
        combined as unknown as BufferSource
      );
    } catch (e) {
      return false;
    }
  }

  /**
   * Verify a JAdES compact JWS (ES256)
   */
  async verifyJadesJws(jwsCompact: string, publicKey: CryptoKey): Promise<boolean> {
    try {
      const parts = jwsCompact.split('.');
      if (parts.length !== 3) return false;

      const [headerB64, payloadB64, sigB64] = parts;
      const rawSig = b64urlDecode(sigB64);
      if (rawSig.length !== 64) return false;

      const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
      return await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        rawSig as unknown as BufferSource,
        signingInput as unknown as BufferSource
      );
    } catch (e) {
      return false;
    }
  }

  /**
   * Verify Merkle inclusion proof (RFC 6962 domain-separated nodes)
   */
  async verifyMerkleProof(
    leafHash: string,
    proofPath: Array<{ hash: string; position: string }>,
    root: string
  ): Promise<boolean> {
    if (!proofPath || proofPath.length === 0) return leafHash === root;
    const NODE_PREFIX = new Uint8Array([0x01]);
    let current = hexToBytes(leafHash);
    for (const step of proofPath) {
      const sibling = hexToBytes(step.hash);
      const combined = new Uint8Array(1 + current.length + sibling.length);
      combined.set(NODE_PREFIX, 0);
      if (step.position === 'left') {
        combined.set(sibling, 1);
        combined.set(current, 1 + sibling.length);
      } else {
        combined.set(current, 1);
        combined.set(sibling, 1 + current.length);
      }
      current = await sha256(combined);
    }
    return bytesToHex(current) === root;
  }

  /**
   * Extract proof data from an HTML string
   */
  extractFromHtml(html: string): ProofBundle | null {
    // Try consolidated proof-bundle block first
    const bundleMatch = /<script\s+type="application\/json"\s+id="proof-bundle">([\s\S]*?)<\/script>/.exec(html);
    if (bundleMatch) {
      try {
        const full = JSON.parse(bundleMatch[1].trim());
        if (full.vc) return full as ProofBundle;
      } catch (e) { /* fall through */ }
    }

    // Fall back to individual per-block extraction
    const bundle: any = { formatVersion: '1.0', type: 'SignForgeProofBundle' };
    const pattern = /<script\s+type="application\/json"\s+id="(proof-[^"]+)">([\s\S]*?)<\/script>/g;
    let match;
    while ((match = pattern.exec(html)) !== null) {
      try {
        const data = JSON.parse(match[2].trim());
        const id = match[1];
        if (id === 'proof-vc') bundle.vc = data;
        else if (id === 'proof-keys') bundle.keys = data;
        else if (id === 'proof-merkle') bundle.transparency = data;
        else if (id === 'proof-timestamp') bundle.timestamp = data;
        else if (id === 'proof-did-snapshot') bundle.didSnapshot = data;
        else if (id === 'proof-signer-identities') bundle.signerIdentities = data;
        else if (id === 'proof-metadata') bundle.verification = data;
      } catch (e) { /* skip malformed blocks */ }
    }
    return bundle.vc ? bundle as ProofBundle : null;
  }

  /**
   * Extract proof bundle from a PDF file buffer.
   * Looks for embedded signforge_proof.json or signforge_proof.html attachments.
   */
  extractFromPdf(pdfBuffer: Buffer | Uint8Array): ProofBundle | null {
    const text = Buffer.from(pdfBuffer).toString('latin1');

    // Look for embedded file streams — search for signforge_proof filenames
    // PDF embedded files are stored as streams referenced by /EmbeddedFiles
    // We search for the JSON content between stream...endstream markers

    // Strategy: find signforge_proof.json or signforge_proof.html content
    // by looking for the proof bundle JSON signature in stream data
    const streamRegex = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
    let streamMatch;

    while ((streamMatch = streamRegex.exec(text)) !== null) {
      const content = streamMatch[1];

      // Try to parse as proof bundle JSON directly (signforge_proof.json)
      if (content.includes('"SignForgeProofBundle"') || content.includes('"vc"')) {
        try {
          const bundle = JSON.parse(content);
          if (bundle.vc && (bundle.type === 'SignForgeProofBundle' || bundle.formatVersion)) {
            return bundle as ProofBundle;
          }
        } catch (e) { /* not JSON, continue */ }
      }

      // Try to extract from HTML (signforge_proof.html)
      if (content.includes('proof-bundle') && content.includes('<script')) {
        const extracted = this.extractFromHtml(content);
        if (extracted) return extracted;
      }
    }

    return null;
  }

  /**
   * Run all verification checks on a proof bundle
   */
  async verify(bundle: ProofBundle): Promise<VerifyResult> {
    const results: VerifyResult = { checks: {}, valid: false };

    // Get public key
    const keys = bundle.keys || {};
    const issuerJwk = keys.issuer?.publicKeyJwk;
    let pub: CryptoKey | null = null;
    if (issuerJwk) {
      try {
        pub = await importJwk(issuerJwk);
        results.checks.public_key = { status: 'found', source: 'embedded_keys' };
      } catch (e: any) {
        results.checks.public_key = { status: 'error', detail: e.message };
      }
    }

    // Check 1: VC signature
    const vc = bundle.vc;
    if (vc && pub) {
      const valid = await this.verifyVcSignature(vc, pub);
      results.checks.vc_signature = {
        status: valid ? 'pass' : 'FAIL',
        detail: valid ? 'ECDSA P-256 DataIntegrityProof verified' : 'Signature invalid',
      };
    }

    // Check 2: JAdES JWS
    if (bundle.jades && pub) {
      const valid = await this.verifyJadesJws(bundle.jades, pub);
      results.checks.jades_jws = {
        status: valid ? 'pass' : 'FAIL',
        detail: valid ? 'ES256 JAdES JWS verified' : 'JWS invalid',
      };
    }

    // Check 3: Merkle proof
    const tp = bundle.transparency;
    if (tp && tp.merkle_proof && tp.signed_tree_head) {
      try {
        const root = tp.signed_tree_head.root_hash || tp.signed_tree_head.root || '';
        const valid = await this.verifyMerkleProof(tp.leaf_hash, tp.merkle_proof, root);
        const treeSize = tp.signed_tree_head.tree_size || tp.signed_tree_head.size || '?';
        results.checks.merkle_proof = {
          status: valid ? 'pass' : 'FAIL',
          detail: valid ? `Merkle inclusion verified (tree size: ${treeSize})` : 'Invalid',
        };
      } catch (e: any) {
        results.checks.merkle_proof = { status: 'error', detail: e.message };
      }
    }

    // Check 4: Timestamp
    const ts = bundle.timestamp;
    if (ts) {
      const tsa = ts.tsa || ts.tsa_name || 'unknown';
      const time = ts.signingTime || ts.signing_time || 'unknown';
      results.checks.timestamp = {
        status: 'present',
        tsa,
        signingTime: time,
        detail: `RFC 3161 timestamp from ${tsa} at ${time}`,
      };
    }

    // Check 5: Signer identities
    const sids = bundle.signerIdentities || [];
    if (sids.length > 0 && pub) {
      let allValid = true;
      for (const sid of sids) {
        if (!(await this.verifyVcSignature(sid, pub))) { allValid = false; break; }
      }
      results.checks.signer_identities = {
        status: allValid ? 'pass' : 'FAIL',
        count: sids.length,
        detail: allValid ? `${sids.length} signer identity VC(s) verified` : 'Invalid',
      };
    }

    // Check 6: DID snapshot
    const did = bundle.didSnapshot;
    if (did) {
      results.checks.did_snapshot = {
        status: 'present',
        capturedAt: did.capturedAt,
        detail: `DID document captured at ${did.capturedAt || 'unknown'}`,
      };
    }

    // Overall verdict
    const statuses = Object.values(results.checks).map(c => c.status);
    results.valid = !statuses.includes('FAIL') && statuses.includes('pass');
    results.formatVersion = bundle.formatVersion;

    return results;
  }

  /**
   * Verify from an HTML string (convenience method)
   */
  async verifyFromHtml(html: string): Promise<VerifyResult> {
    const bundle = this.extractFromHtml(html);
    if (!bundle) return { valid: false, checks: {}, error: 'No proof data found' };
    return await this.verify(bundle);
  }

  /**
   * Verify from a PDF buffer (convenience method)
   */
  async verifyFromPdf(pdfBuffer: Buffer | Uint8Array): Promise<VerifyResult> {
    const bundle = this.extractFromPdf(pdfBuffer);
    if (!bundle) return { valid: false, checks: {}, error: 'No proof data found in PDF' };
    return await this.verify(bundle);
  }
}
