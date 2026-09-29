'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const {execFileSync} = require('node:child_process');
const {webcrypto, createPrivateKey, createPublicKey} = require('node:crypto');

const root = path.resolve(__dirname, '../..');
const html = fs.readFileSync(path.join(root, 'web/config.html'), 'utf8');
const context = vm.createContext({crypto: webcrypto, TextEncoder, Uint8Array, DataView, Blob, btoa, atob});
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
const C = vm.runInContext('VelvetConfig', context);
const plain = x => JSON.parse(JSON.stringify(x));
const fixture = C.examples(false);
const errors = async specs => plain(await C.validate(specs)).filter(x => !x.warning);

test('editor schema covers every current Go NodeSpec JSON field', () => {
  const source = ['spec.go','ports.go'].map(f => fs.readFileSync(path.join(root,'internal/spec',f),'utf8')).join('\n');
  const contracts = {
    NodeSpec:C.schema, FabricSpec:C.schema.fabric, Node:C.schema.node, NodeUID:C.schema.node.uid,
    Peer:C.schema.peers[0], BabelSpec:C.schema.babel, DynamicLinksSpec:C.schema.dynamic_links,
    DurableSpec:C.schema.dynamic_links.durable, PortRange:C.schema.node.port_range,
    DomainSpec:C.schema.domains.$map,
    Route:{prefix:'string',metric:'number'}, Announcement:{prefix:'string',metric:'number'}
  };
  for (const [type,rule] of Object.entries(contracts)) {
    const body=source.match(new RegExp('type '+type+' struct \\{([\\s\\S]*?)\\n\\}'))?.[1];
    assert.ok(body,type);
    const fields=[...body.matchAll(/json:"([^",]+)/g)].map(m => m[1]).sort();
    assert.deepEqual(Object.keys(rule).sort(),fields,type);
  }
});

test('single HTML has no external assets, network calls or storage', () => {
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)\s*=/i);
  assert.doesNotMatch(html, /\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage)\b/);
  assert.match(html, /connect-src 'none'/);
});

test('X25519 public derivation matches RFC 7748 Alice vector', async () => {
  const key = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex').toString('base64');
  const expected = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex').toString('base64');
  assert.equal(await C.publicKey(key), expected);
  const pair = await C.keyPair();
  const raw = Buffer.from(pair.privateKey, 'base64');
  assert.equal(raw[0] & 7, 0); assert.equal(raw[31] & 192, 64);
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'), raw]);
  const native = createPublicKey(createPrivateKey({key: der, format:'der', type:'pkcs8'})).export({format:'jwk'});
  assert.equal(pair.publicKey, Buffer.from(native.x, 'base64url').toString('base64'));
});

for (const dynamic of [false, true]) test(`preset matches actual ${dynamic ? 'dynamic' : 'static'} examples`, async () => {
  const specs = await C.examples(dynamic);
  assert.deepEqual(await errors(specs), []);
  const pubs = await Promise.all(specs.map(s => C.publicKey(s.node.private_key)));
  for (let i = 0; i < 3; i++) {
    const actual = plain(specs[i]);
    const expected = JSON.parse(fs.readFileSync(path.join(root, 'examples', dynamic ? 'dynamic_minimal' : 'static_minimal', 'abc'[i]+'.json')));
    assert.match(actual.node.uid.uuid, /^[0-9a-f-]{36}$/);
    delete actual.node.uid.uuid;
    actual.fabric.psk = '<FABRIC_PSK>';
    actual.node.private_key = `<${'ABC'[i]}_PRIVATE_KEY>`;
    for (const peer of actual.peers) {
      const remote = pubs.indexOf(peer.public_key); assert.notEqual(remote,-1);
      peer.public_key = `<${'ABC'[remote]}_PUBLIC_KEY>`;
    }
    assert.deepEqual(actual, expected);
  }
});

test('import preserves complete optional fields and explicit zeroes', async () => {
  const s = plain((await fixture)[0]);
  Object.assign(s.fabric, {link_prefix_v4:'10.240.0.0/16',link_prefix_v6:'fd77::/48',vfp_port:58421});
  Object.assign(s.node, {port_range:{first:40000,last:49999}});
  Object.assign(s.peers[0], {listen_port:0,persistent_keepalive_seconds:0,link_addresses:['10.240.0.0/30','fd77::/126']});
  s.fabric.routes.b = [{prefix:'fd78:abcd::3/128',metric:0}];
  s.fabric.announcements = [{prefix:'10.100.20.0/24',metric:0}];
  s.dynamic_links = {mode:'active',recovery_timeout_seconds:1800,allow_candidate_prefixes:['0.0.0.0/0','::/0'],durable:{soft_limit:0,stable_seconds:1}};
  s.babel = {enabled:false,executable:'/usr/local/bin/babel-rs'};
  assert.deepEqual(plain(C.imported(s)), s);
  assert.deepEqual(await errors([s]), []);
  assert.equal(C.effectivePorts(s,s.peers[0]).listen_port,0);
  delete s.peers[0].listen_port;
  assert.deepEqual(plain(C.effectivePorts(s,s.peers[0]).port_range),s.node.port_range);
  s.peers[0].port_range = {first:52000,last:52001};
  assert.deepEqual(await errors([s]), []);
});

test('invalid JSON types and unknown fields are not silently discarded', () => {
  for (const value of [null, [], {node:{listen_port:'0'}}, {fabric:{future_field:1}}, {domains:{internet:{source_prefixes:'10.0.0.0/8'}}}, {peers:[{endpoints:null}]}]) {
    assert.throws(() => C.imported(value));
  }
  const valid = {api_version:'velvet.io/v1alpha1',kind:'NodeSpec',fabric:{},node:{},peers:[]};
  assert.equal(C.imported(valid).node.uid.uuid,undefined);
});

test('address parsing handles canonical prefixes, compressed IPv6 and families', () => {
  for (const raw of ['10.0.0.1/24','256.0.0.0/8','01.2.3.4/32','fd00:::1/128','1:2:3:4:5:6:7:8::/128','fe80::1%eth0/128','::/129']) assert.equal(C.prefix(raw),null,raw);
  for (const raw of ['0.0.0.0/0','10.100.20.0/24','::/0','fd78:abcd::/48','2001:db8::ffff/128','::ffff:192.0.2.1/128']) assert.ok(C.prefix(raw),raw);
  assert.equal(C.prefix('::ffff:192.0.2.1/128').value, C.prefix('::ffff:c000:201/128').value);
  assert.equal(C.contains(C.prefix('10.0.0.0/8'),C.prefix('10.1.0.0/16')),true);
  assert.equal(C.contains(C.prefix('::/0'),C.prefix('10.0.0.0/8')),false);
});

const invalidCases = [
  ['missing peers', s => {s.peers=[];}, 'peers'],
  ['same local key', async s => {s.peers[0].public_key=await C.publicKey(s.node.private_key);}, 'public_key'],
  ['exclusive ports', s => {s.node.listen_port=0;s.node.port_range={first:1,last:2};}, 'node'],
  ['reversed range', s => {s.node.port_range={first:10,last:2};}, 'port_range'],
  ['fixed port inheritance collision', s => {s.node.listen_port=12345;delete s.peers[0].listen_port;s.peers.push({...s.peers[0],name:'d',interface_name:'vl-a-d'});}, 'listen_port'],
  ['unknown next hop', s => {s.fabric.routes={missing:['10.0.0.0/8']};}, 'routes.missing'],
  ['empty route group', s => {s.fabric.routes.b=[];}, 'routes.b'],
  ['metric bounds', s => {s.fabric.routes.b=[{prefix:'::/0',metric:-1}];}, 'metric'],
  ['announcement conflict', s => {s.fabric.routes.b=['10.100.20.0/24'];}, 'announcements'],
  ['source overlap', s => {s.domains.internet.source_prefixes.push('10.100.20.0/25');}, 'source_prefixes'],
  ['canonical duplicate IPv6', s => {s.fabric.routes.b=['fd78:abcd::3/128','fd78:abcd:0:0:0:0:0:3/128'];}, 'routes'],
  ['table collision', s => {s.domains.internet.table_id=20000;}, 'table_id'],
  ['reserved table', s => {s.fabric.routing_table_id=254;}, 'routing_table_id'],
  ['link address outside pool', s => {s.peers[0].link_addresses=['10.0.0.0/30'];}, 'link_addresses'],
  ['wrong announcement family', s => {s.domains.internet.announcements=['::/0'];}, 'announcements'],
  ['allowlist conditional required', s => {s.dynamic_links={mode:'passive'};}, 'allow_candidate_prefixes'],
  ['recovery timeout bounds', s => {s.dynamic_links={mode:'off',recovery_timeout_seconds:29};}, 'recovery_timeout_seconds'],
  ['recovery timeout upper bound', s => {s.dynamic_links={mode:'off',recovery_timeout_seconds:604801};}, 'recovery_timeout_seconds'],
  ['loopback metric alignment', s => {s.babel={enabled:true};s.fabric.announcements=[{prefix:s.node.loopback_address_v6+'/128',metric:1}];}, 'metric'],
  ['durable bounds', s => {s.dynamic_links={mode:'off',durable:{soft_limit:129}};}, 'soft_limit'],
  ['Babel enabled required', s => {s.babel={executable:'/bin/babel-rs'};}, 'babel.enabled'],
  ['Babel absolute path', s => {s.babel={enabled:true,executable:'babel-rs'};}, 'executable'],
];
for (const [name, change, pathFragment] of invalidCases) test(`validation: ${name}`,async () => {
  const s=plain((await fixture)[0]); await change(s);
  assert.ok((await errors([s])).some(x => x.path.includes(pathFragment)),name);
});

test('cross-node identity and Fabric mismatch errors, independent of local table IDs', async () => {
  const specs=plain(await fixture);
  specs[1].fabric.routing_table_id=19000;
  specs[1].domains.internet.table_id=19001;
  assert.deepEqual(await errors(specs),[]);
  specs[1].node.uid.uuid=specs[0].node.uid.uuid;
  specs[1].fabric.psk=C.randomKey();
  const result=await errors(specs);
  assert.ok(result.some(x => x.path==='node.uid.uuid'));
  assert.ok(result.some(x => x.text.includes('fabric.psk')));
});

test('unique export filenames cannot escape the ZIP directory', () => {
  const specs=['a','a','a-2','../../bad',''].map(name => ({node:{uid:{name}}}));
  const names=plain(C.filenames(specs));
  assert.equal(new Set(names).size,5); assert.ok(names.every(x => !x.includes('/')));
});

test('ZIP has intact UTF-8 payloads, CRC and private Unix modes', async () => {
  const files=[{name:'a.json',text:'{"node":"节点 a"}\n'},{name:'b.json',text:'{}\n'}];
  const bytes=Buffer.from(await C.zip(files).arrayBuffer());
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'velvet-web-zip-'));
  try {
    const filename=path.join(tmp,'configs.zip');fs.writeFileSync(filename,bytes,{mode:0o600});
    const output=execFileSync('python3',['-c',
      'import json,sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None; print(json.dumps([{"name":i.filename,"text":z.read(i).decode(),"mode":(i.external_attr>>16)&511} for i in z.infolist()]))',filename],{encoding:'utf8'});
    assert.deepEqual(JSON.parse(output),files.map(f => ({...f,mode:0o600})));
  } finally {fs.rmSync(tmp,{recursive:true,force:true});}
});

test('generated configs accepted by velvetctl resolve', {skip:!process.env.VELVET_CONFIG_CTL}, async () => {
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'velvet-web-resolve-'));
  try {
    const complete=plain((await fixture)[0]);
    Object.assign(complete.fabric,{link_prefix_v4:'10.240.0.0/16',link_prefix_v6:'fd77::/48',vfp_port:58421});
    complete.node.port_range={first:40000,last:49999};
    Object.assign(complete.peers[0],{listen_port:0,persistent_keepalive_seconds:0,link_addresses:['10.240.0.0/30','fd77::/126']});
    complete.fabric.routes.b=[{prefix:'fd78:abcd::3/128',metric:0}];
    complete.fabric.announcements=[{prefix:'10.100.20.0/24',metric:0}];
    complete.dynamic_links={mode:'active',recovery_timeout_seconds:1800,allow_candidate_prefixes:['0.0.0.0/0','::/0'],durable:{soft_limit:0,stable_seconds:1}};
    complete.babel={enabled:true,executable:'/usr/local/bin/babel-rs'};
    const peerRange=plain(complete);delete peerRange.peers[0].listen_port;peerRange.peers[0].port_range={first:52000,last:52999};
    const all=[...await C.examples(false),...await C.examples(true),complete,peerRange];
    for (const [i,s] of all.entries()) {
      const file=path.join(tmp,`${i}-${s.node.uid.name}.json`);
      fs.writeFileSync(file,JSON.stringify(s),{mode:0o600});
      const output=JSON.parse(execFileSync(process.env.VELVET_CONFIG_CTL,['resolve','--config',file],{encoding:'utf8'}));
      assert.equal(output.loopback_v6,s.node.loopback_address_v6);
      assert.equal(output.links.length,s.peers.length);
    }
  } finally {fs.rmSync(tmp,{recursive:true,force:true});}
});
