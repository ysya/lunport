import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {validateManifest,canonicalJson} from '../../../scripts/beta-channel.mjs';
const [root,tag,expected]=process.argv.slice(2);
assert.ok(root&&/^v1\.0\.0-\d+$/.test(tag)&&/^[a-f0-9]{40}$/.test(expected),'root/tag/expected SHA required');
const read=name=>JSON.parse(readFileSync(`${root}/${name}`,'utf8'));
const release=read('release.json'),stable=read('stable.json'),baseline=read('stable-before.json'),ref=read('tag.json');
const source=read('release/latest.json'),channel=read('channel/latest.json');
const channelRelease=read('channel-release.json');
assert.equal(channelRelease.prerelease,true);assert.equal(channelRelease.draft,false);
assert.equal(channelRelease.tag_name,'updater-beta');
assert.equal(release.tag_name,tag);assert.equal(release.prerelease,true);assert.equal(release.draft,false);
assert.equal(stable.id,baseline.id);assert.equal(stable.tag_name,baseline.tag_name);assert.equal(stable.prerelease,false);
const commit=ref.object.type==='commit'?ref.object.sha:read('annotated-tag.json').object.sha;
assert.equal(commit,expected);validateManifest(source,tag);validateManifest(channel,tag);
assert.equal(canonicalJson(source),canonicalJson(channel));
const assets=new Map(release.assets.map(asset=>[asset.name,asset]));
assert.equal(assets.size,release.assets.length,'duplicate asset names');
for(const asset of assets.values()){assert.ok(asset.size>0,`empty asset: ${asset.name}`);assert.equal(asset.state,'uploaded');}
for(const [platform,value] of Object.entries(source.platforms)){
 assert.equal(typeof value.signature,'string',`${platform}: missing signature`);assert.ok(value.signature.length>0,`${platform}: empty signature`);
 const url=new URL(value.url);assert.equal(url.origin,'https://github.com');assert.ok(url.pathname.startsWith(`/ysya/sshelter/releases/download/${tag}/`));
 const name=decodeURIComponent(url.pathname.split('/').at(-1));assert.ok(assets.has(name),`${platform}: missing ${name}`);
 assert.ok(assets.has(`${name}.sig`),`${platform}: missing signature asset`);
 assert.equal(readFileSync(`${root}/signatures/${name}.sig`,'utf8').trim(),value.signature.trim(),`${platform}: signature file differs from manifest`);
}
console.log(JSON.stringify({version:source.version,sourceCommit:commit,prerelease:true,stable:stable.tag_name,stableReleaseId:stable.id,platforms:Object.keys(source.platforms),assetCount:assets.size,allAssetsUploadedNonempty:true,channelMatchesRelease:true,manifestSignaturesMatchUploadedFiles:true}));
