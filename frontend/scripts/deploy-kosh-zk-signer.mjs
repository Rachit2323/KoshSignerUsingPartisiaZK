import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import abiClientPkg from "@partisiablockchain/abi-client";
import txClientPkg from "@partisiablockchain/blockchain-api-transaction-client";

const { DeploymentClient } = abiClientPkg;
const { SenderAuthenticationKeyPair } = txClientPkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

const currentSignerAddress =
  process.env.EXISTING_SIGNER_ADDRESS ??
  process.env.SIGNER_ADDRESS ??
  "03a1e8aba3ba45c1e42d01f688768436cb2b572de0";

const defaultReaderUrl =
  process.env.PARTISIA_READER_URL ??
  process.env.PARTISIA_NODE_URL ??
  "https://node1.testnet.partisiablockchain.com";

const privateKeyPath =
  process.env.PARTISIA_DEPLOYER_PK_PATH ??
  path.join(repoRoot, "partisia-testnet-sender-20260428.pk");

const pbcPath =
  process.env.KOSH_ZK_SIGNER_PBC_PATH ??
  path.join(repoRoot, "target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc");

const deployGas = Number(process.env.KOSH_ZK_SIGNER_DEPLOY_GAS ?? "5000000");

function expectString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing ${label}`);
  }
  return value;
}

function getNested(obj, pathParts) {
  let cur = obj;
  for (const part of pathParts) {
    if (cur == null || !(part in cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

async function fetchContractState(readerUrl, contractAddress) {
  const url = `${readerUrl}/shards/Shard0/blockchain/contracts/${contractAddress}?requireContractState=true`;
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Failed to fetch contract state from ${url}: ${resp.status}`);
  }
  return await resp.json();
}

function extractDeploymentConfig(contractState) {
  const fallbackOwner =
    process.env.SIGNER_OWNER_ADDRESS ??
    "002ee35cde26782f255b9550ea1ac53faeac2c71cd";
  const fallbackEngines = (
    process.env.SIGNER_ENGINE_ADDRESSES ??
    "00eb99a86577a18fd24b8cdda5d5b57134ca187ce4,00c64bd3ad942e3efc3d4f3a6b7000ff88b595a180,009b3b44fc72180aed07002aaa66073f8d4b6afe62"
  )
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const fallbackSpecificNodes = (
    process.env.SIGNER_SPECIFIC_NODES ??
    "00c4b91b81531fb571f0a815346b808cfd266b4fbf,00dd4aa71c78bfea151a0fdb149e4c012720ee0250,006df142b1c3f820ffc07df2ab7358cad2202da18f,00a44d16e47871a20cdc8b2beb6bb2fe16d1ba8ff1"
  )
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  const state = contractState.contractState ?? contractState.openState ?? null;
  const zkEngines = getNested(contractState, [
    "zkState",
    "engines",
    "innerValue",
    "engines",
    "innerValue",
  ]);

  const owner = typeof state?.owner === "string" ? state.owner : fallbackOwner;
  const engines = Array.isArray(state?.engines)
    ? state.engines.map((engine) => expectString(engine?.address, "engine.address"))
    : fallbackEngines;

  const specificNodes = Array.isArray(zkEngines)
    ? zkEngines.map((engine) => expectString(engine?.innerValue?.identity, "zkState.engines.identity"))
    : fallbackSpecificNodes;

  if (engines.length !== 3) {
    throw new Error(`Expected 3 engine addresses, got ${engines.length}`);
  }
  if (specificNodes.length !== 4) {
    throw new Error(`Expected 4 zk node identities, got ${specificNodes.length}`);
  }

  return {
    owner,
    engines,
    threshold: Number(state?.threshold ?? 2),
    numShares: Number(state?.num_shares ?? 3),
    specificNodes,
  };
}

async function main() {
  const [pkHex, pbcBytes, currentState] = await Promise.all([
    fs.readFile(privateKeyPath, "utf8"),
    fs.readFile(pbcPath),
    fetchContractState(defaultReaderUrl, currentSignerAddress),
  ]);

  const deployConfig = extractDeploymentConfig(currentState);
  const senderAuthentication = SenderAuthenticationKeyPair.fromString(pkHex.trim());
  const deploymentClient = DeploymentClient.createWithUrl(defaultReaderUrl, senderAuthentication);

  const deployResult = await deploymentClient
    .builder()
    .pbcFile(pbcBytes)
    .specificNodes(deployConfig.specificNodes)
    .gasCost(deployGas)
    .initRpc((builder) => {
      builder.addAddress(deployConfig.owner);
      const enginesVec = builder.addVec();
      for (const engineAddress of deployConfig.engines) {
        enginesVec.addStruct().addAddress(engineAddress);
      }
      builder.addU16(deployConfig.threshold);
      builder.addU8(deployConfig.numShares);
    })
    .deploy();

  const output = {
    currentSignerAddress,
    newSignerAddress: deployResult.contractAddress,
    owner: deployConfig.owner,
    engines: deployConfig.engines,
    specificNodes: deployConfig.specificNodes,
    threshold: deployConfig.threshold,
    numShares: deployConfig.numShares,
    deployGas,
  };

  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
