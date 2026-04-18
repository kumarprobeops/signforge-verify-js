#!/usr/bin/env node
/**
 * @signforge/verify CLI
 *
 * Usage:
 *   signforge-verify document.proof.html
 *   signforge-verify document-signed.pdf
 *   signforge-verify document-signed.pdf --json
 */

import * as fs from 'fs';
import * as path from 'path';
import { SignForgeVerifier } from './index';

const ICONS: Record<string, string> = {
  pass: '\u2713',
  FAIL: '\u2717',
  present: '\u2022',
  skip: '\u25CB',
  found: '\u2022',
  error: '!',
};

async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const filePath = args.find(a => !a.startsWith('--'));

  if (!filePath || args.includes('--help') || args.includes('-h')) {
    console.log(`
SignForge Proof Verifier v1.0.0

Usage:
  signforge-verify <file> [--json]

Arguments:
  file        Path to a signed PDF or .proof.html file

Options:
  --json      Output results as JSON
  --help      Show this help message

Examples:
  signforge-verify document.proof.html
  signforge-verify document-signed.pdf --json

Learn more: https://signforge.io/verify
`);
    process.exit(filePath ? 0 : 1);
  }

  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    console.error(`ERROR: File not found: ${resolved}`);
    process.exit(1);
  }

  const verifier = new SignForgeVerifier();
  let result;

  const ext = path.extname(resolved).toLowerCase();
  if (ext === '.pdf') {
    const buffer = fs.readFileSync(resolved);
    result = await verifier.verifyFromPdf(buffer);
  } else if (ext === '.html') {
    const html = fs.readFileSync(resolved, 'utf-8');
    result = await verifier.verifyFromHtml(html);
  } else {
    // Try as HTML
    const content = fs.readFileSync(resolved, 'utf-8');
    result = await verifier.verifyFromHtml(content);
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ file: filePath, ...result }, null, 2));
  } else {
    console.log(`\n${'='.repeat(60)}`);
    console.log('  SignForge Proof Verifier');
    console.log('='.repeat(60));
    console.log(`  File: ${filePath}`);
    if (result.formatVersion) {
      console.log(`  Format: v${result.formatVersion}`);
    }
    console.log();

    if (result.error) {
      console.log(`  ${result.error}`);
    } else {
      for (const [name, check] of Object.entries(result.checks)) {
        const icon = ICONS[check.status] || '?';
        const label = name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        console.log(`  ${icon}  ${label}: ${check.detail || check.status}`);
      }
    }

    console.log();
    if (result.valid) {
      console.log('  \u2705 DOCUMENT VERIFIED');
    } else {
      const statuses = Object.values(result.checks).map(c => c.status);
      if (statuses.includes('FAIL')) {
        console.log('  \u274C VERIFICATION FAILED \u2014 document may be tampered');
      } else {
        console.log('  \u26A0\uFE0F  PARTIAL \u2014 some checks could not be performed');
      }
    }
    console.log('='.repeat(60) + '\n');
  }

  process.exit(result.valid ? 0 : 1);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
