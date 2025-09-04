#!/usr/bin/env node
import fs from 'node:fs';
import { stdin as input } from 'node:process';
import { scanText } from '../src/scan.js';

function readAllStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    input.setEncoding('utf8');
    input.on('data', chunk => (data += chunk));
    input.on('end', () => resolve(data));
    input.on('error', reject);
  });
}

function printJson(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

async function main() {
  const [,, cmd, ...args] = process.argv;
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    console.log('Usage: aicodesafe <scan> [--text "..."]');
    process.exit(0);
  }
  if (cmd === 'scan') {
    const textFlagIdx = args.findIndex(a => a === '--text');
    let text = '';
    if (textFlagIdx !== -1 && args[textFlagIdx + 1]) {
      text = args[textFlagIdx + 1];
    } else {
      // read from stdin
      text = await readAllStdin();
    }
    const result = scanText(text || '');
    printJson(result);
    return;
  }
  console.error('Unknown command:', cmd);
  process.exit(1);
}

main().catch(err => {
  console.error('[aicodesafe] unexpected error:', err?.stack || String(err));
  process.exit(1);
});

