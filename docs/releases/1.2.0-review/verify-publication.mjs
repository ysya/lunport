import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';

const root = process.argv[2];
assert.equal(process.argv[3], 'v1.2.0');
const read = name => JSON.parse(readFileSync(`${root}/${name}`, 'utf8'));
const before = read('previous-stable-before.json');
const after = read('previous-stable-after.json');
assert.equal(before.tag_name, 'v1.1.0');
for (const key of ['id', 'tag_name', 'name', 'body', 'draft', 'prerelease', 'published_at']) {
  assert.deepEqual(after[key], before[key], `v1.1.0 ${key} changed`);
}
const assets = release => release.assets
  .map(({ id, name, size, digest }) => ({ id, name, size, digest }))
  .sort((a, b) => a.id - b.id);
assert.deepEqual(assets(after), assets(before), 'v1.1.0 assets changed');
assert.deepEqual(read('previous-stable-tag-after.json').object,
  read('previous-stable-tag-before.json').object, 'v1.1.0 tag changed');

// Reuse the full artifact/digest/updater/signature/tamper checks, including v1.0.0.
await import('../1.1.0-review/verify-publication.mjs');
const receipt = read('verification.json');
receipt.historicalReleasesUnchanged = ['v1.0.0', 'v1.1.0'];
writeFileSync(`${root}/verification.json`, `${JSON.stringify(receipt, null, 2)}\n`);
console.log('Historical v1.0.0 and v1.1.0 releases and tags remain unchanged.');
