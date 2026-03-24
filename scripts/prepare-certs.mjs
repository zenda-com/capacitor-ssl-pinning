#!/usr/bin/env node

import { cp, mkdir, readdir, rm } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';

const rootDir = process.env.CAPACITOR_ROOT_DIR;
const webDir = process.env.CAPACITOR_WEB_DIR;
const configJson = process.env.CAPACITOR_CONFIG;

const log = (message) => console.log(`[ssl-pinning] ${message}`);
const fail = (message) => {
  throw new Error(`[ssl-pinning] ${message}`);
};

if (!rootDir || !webDir || !configJson) {
  log('Capacitor hook environment not detected, skipping certificate preparation.');
  process.exit(0);
}

const config = JSON.parse(configJson);
const certs = config?.plugins?.SSLPinning?.certs;

if (!Array.isArray(certs) || certs.length === 0) {
  log('No plugins.SSLPinning.certs entries found, skipping certificate preparation.');
  process.exit(0);
}

const sourceFiles = certs.map((relativePath) => {
  if (typeof relativePath !== 'string' || !relativePath.trim()) {
    fail('All plugins.SSLPinning.certs entries must be non-empty strings.');
  }

  return {
    source: resolve(rootDir, relativePath),
    fileName: basename(relativePath),
  };
});

const targetDir = join(webDir, 'certs');
await mkdir(targetDir, { recursive: true });

for (const existingEntry of await readdir(targetDir, { withFileTypes: true })) {
  if (existingEntry.isFile()) {
    await rm(join(targetDir, existingEntry.name), { force: true });
  }
}

for (const { source, fileName } of sourceFiles) {
  await cp(source, join(targetDir, fileName), { force: true });
  log(`Copied ${fileName} into ${targetDir}`);
}
