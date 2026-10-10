import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
const root = resolve(import.meta.dirname, '..');
const publicDir = resolve(root, 'public');
for (const filename of readdirSync(publicDir).filter((name) => name.endsWith('.html'))) {
  const html = readFileSync(resolve(publicDir, filename), 'utf8');
  assert.match(html, /<html lang="zh-CN">/);
  assert.match(html, /name="viewport"/);
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, filename + ': duplicate ids');
  for (const match of html.matchAll(/(?:href|src)="(\/[^"]+)"/g)) {
    assert.ok(existsSync(resolve(publicDir, '.' + match[1])), filename + ': missing asset ' + match[1]);
  }
}
const html = readFileSync(resolve(publicDir, 'index.html'), 'utf8');
const script = readFileSync(resolve(publicDir, 'app.js'), 'utf8');
for (const match of script.matchAll(/\$\('([^']+)'\)/g)) assert.ok(html.includes(`id="${match[1]}"`), 'missing DOM id: ' + match[1]);
assert.match(readFileSync(resolve(publicDir, 'config.js'), 'utf8'), /TONGJI_API_ORIGIN = '(?:https:\/\/tongji-api\.hachile\.org)?'/);
assert.ok(!html.includes('type="password"'));
console.log('Static checks passed: assets, unique IDs, DOM references and default disabled configuration.');
