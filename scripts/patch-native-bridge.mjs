import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = process.env.CAPACITOR_ROOT_DIR || join(__dirname, '../../../..');

function patchFile(filePath, patches) {
  if (!existsSync(filePath)) {
    console.warn(`  [patch-native-bridge] SKIP: ${filePath} not found`);
    return false;
  }
  let content = readFileSync(filePath, 'utf8');
  for (const { search, replace } of patches) {
    if (content.includes(search)) {
      content = content.replace(search, replace);
    } else {
      console.warn(`  [patch-native-bridge] WARN: pattern not found in ${filePath}`);
    }
  }
  writeFileSync(filePath, content, 'utf8');
  console.log(`  [patch-native-bridge] OK: ${filePath}`);
  return true;
}

const iosBridge = join(root, 'node_modules/@capacitor/ios/Capacitor/Capacitor/assets/native-bridge.js');
const androidBridge = join(root, 'node_modules/@capacitor/android/capacitor/src/main/assets/native-bridge.js');
const iosSwift = join(root, 'node_modules/@capacitor/ios/Capacitor/Capacitor/CAPBridgeViewController.swift');

let patched = 0;

if (patchFile(iosBridge, [
  // Hunk 1: Route GET/HEAD/OPTIONS/TRACE through native HTTP on iOS
  {
    search: `if (method.toLocaleUpperCase() === 'GET' ||
                            method.toLocaleUpperCase() === 'HEAD' ||
                            method.toLocaleUpperCase() === 'OPTIONS' ||
                            method.toLocaleUpperCase() === 'TRACE') {`,
    replace: `if (platform !== 'ios' &&
                            (method.toLocaleUpperCase() === 'GET' ||
                            method.toLocaleUpperCase() === 'HEAD' ||
                            method.toLocaleUpperCase() === 'OPTIONS' ||
                            method.toLocaleUpperCase() === 'TRACE')) {`,
  },
  // Hunk 2: Route GET/HEAD/OPTIONS/TRACE through native HTTP on iOS (XHR)
  {
    search: `if (!this._method ||
                                this._method === 'GET' ||
                                this._method === 'HEAD' ||
                                this._method === 'OPTIONS' ||
                                this._method === 'TRACE') {`,
    replace: `if (platform !== 'ios' && (
                                !this._method ||
                                this._method === 'GET' ||
                                this._method === 'HEAD' ||
                                this._method === 'OPTIONS' ||
                                this._method === 'TRACE')) {`,
  },
  // Hunk 3: Preserve native error on XHR catch
  {
    search: `.catch((error) => {
                                        this.status = error.status;`,
    replace: `.catch((error) => {
                                        this._cError = error;
                                        this.status = error.status;`,
  },
])) {
  patched++;
}

if (patchFile(androidBridge, [
  // Hunk 1: Disable GET proxy on Android (route through native HTTP)
  {
    search: `if (method.toLocaleUpperCase() === 'GET' ||
                            method.toLocaleUpperCase() === 'HEAD' ||
                            method.toLocaleUpperCase() === 'OPTIONS' ||
                            method.toLocaleUpperCase() === 'TRACE') {`,
    replace: `if (false && (method.toLocaleUpperCase() === 'GET' ||
                            method.toLocaleUpperCase() === 'HEAD' ||
                            method.toLocaleUpperCase() === 'OPTIONS' ||
                            method.toLocaleUpperCase() === 'TRACE')) {`,
  },
  // Hunk 2: Disable GET proxy on Android (XHR)
  {
    search: `if (!this._method ||
                                this._method === 'GET' ||
                                this._method === 'HEAD' ||
                                this._method === 'OPTIONS' ||
                                this._method === 'TRACE') {`,
    replace: `if (false && (!this._method ||
                                this._method === 'GET' ||
                                this._method === 'HEAD' ||
                                this._method === 'OPTIONS' ||
                                this._method === 'TRACE')) {`,
  },
  // Hunk 3: Preserve native error on XHR catch
  {
    search: `.catch((error) => {
                                        this.status = error.status;`,
    replace: `.catch((error) => {
                                        this._cError = error;
                                        this.status = error.status;`,
  },
])) {
  patched++;
}

if (patchFile(iosSwift, [
  // Status bar fix in bridgedWebView
  {
    search: `public var bridgedWebView: WKWebView? {
        return webView`,
    replace: `public var bridgedWebView: WKWebView? {
        // Fix to status bar overlay
        webView?.frame.origin = CGPoint(x: 0, y: UIApplication.shared.statusBarFrame.size.height)
        webView?.frame.size.height = UIScreen.main.bounds.height - UIApplication.shared.statusBarFrame.size.height
        return webView`,
  },
])) {
  patched++;
}

console.log(`\n  [patch-native-bridge] ${patched}/3 files patched`);
