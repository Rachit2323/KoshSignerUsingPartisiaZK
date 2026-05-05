import fs from 'node:fs';
import { AbiParser, JsonValueConverter, StateReader } from '@partisiablockchain/abi-client';

function encodeKeyIdBase64(keyId) {
  return Buffer.from(Uint8Array.of(keyId & 0xff, (keyId >> 8) & 0xff, (keyId >> 16) & 0xff, (keyId >> 24) & 0xff)).toString('base64');
}

const keyId = Number(process.argv[2]);
if (!Number.isFinite(keyId)) {
  console.error('usage: node decode-threshold-state.mjs <key_id>');
  process.exit(1);
}

const abiPath = new URL('../../../../target/wasm32-unknown-unknown/release/kosh_zk_signer.abi', import.meta.url);
const abi = new AbiParser(fs.readFileSync(abiPath)).parseAbi().chainComponent;
const input = await new Promise((resolve, reject) => {
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { buf += chunk; });
  process.stdin.on('end', () => resolve(buf));
  process.stdin.on('error', reject);
});
const contract = JSON.parse(input);
const avlTrees = new Map();
for (const tree of contract.openState?.avlTrees ?? []) {
  avlTrees.set(
    tree.key,
    tree.value.avlTree.map((entry) => [
      Buffer.from(entry.key.data.data, 'base64'),
      Buffer.from(entry.value.data, 'base64'),
    ]),
  );
}
const keyEntries = contract.openState?.avlTrees?.find((tree) => tree.key === 0)?.value?.avlTree ?? [];
const keyEntry = keyEntries.find((entry) => entry.key.data.data === encodeKeyIdBase64(keyId));
if (!keyEntry) {
  process.stdout.write('null');
  process.exit(0);
}
const reader = StateReader.create(Buffer.from(keyEntry.value.data, 'base64'), abi, avlTrees);
const decoded = JsonValueConverter.toJson(reader.readStateValue({ typeIndex: 0, index: 32 }));
process.stdout.write(JSON.stringify(decoded));
