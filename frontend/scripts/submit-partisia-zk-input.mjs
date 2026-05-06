import {
  BlockchainTransactionClient,
  SenderAuthenticationKeyPair,
} from "@partisiablockchain/blockchain-api-transaction-client";
import { BitOutput } from "@secata-public/bitmanipulation-ts";
import { Client as ZkStateClient, RealZkClient } from "@partisiablockchain/zk-client";

function fmt(err) {
  if (err instanceof Error) return err.message;
  return String(err ?? "unknown error");
}

const input = await new Promise((resolve, reject) => {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
  });
  process.stdin.on("end", () => resolve(buf));
  process.stdin.on("error", reject);
});

const req = JSON.parse(input || "{}");
const nodeUrls = Array.isArray(req.nodeUrls) ? req.nodeUrls.filter(Boolean) : [];
if (nodeUrls.length === 0) throw new Error("nodeUrls required");
if (!req.senderKey) throw new Error("senderKey required");
if (!req.senderAddress) throw new Error("senderAddress required");
if (!req.contractAddress) throw new Error("contractAddress required");
if (!req.publicRpcHex) throw new Error("publicRpcHex required");
if (!req.secretHex) throw new Error("secretHex required");

const senderKey = SenderAuthenticationKeyPair.fromString(req.senderKey);
const senderAddress = req.senderAddress;
const contractAddress = req.contractAddress;
const publicRpc = Buffer.from(req.publicRpcHex, "hex");
const secretBytes = Buffer.from(req.secretHex, "hex");
const gasCost = Number.isFinite(req.gasCost) ? req.gasCost : 750000;

const compactSecret = BitOutput.serializeBits((out) => {
  out.writeBytes(secretBytes);
});

let lastErr;
for (let i = 0; i < Math.min(nodeUrls.length, req.maxRetries ?? nodeUrls.length); i++) {
  const nodeUrl = nodeUrls[i % nodeUrls.length];
  try {
    const zkStateClient = new ZkStateClient(nodeUrl);
    const zkClient = RealZkClient.create(contractAddress, zkStateClient);
    const txClient = BlockchainTransactionClient.create(nodeUrl, senderKey);

    const tx = await zkClient.buildOnChainInputTransaction(
      senderAddress,
      compactSecret,
      publicRpc,
    );
    const sent = await txClient.signAndSend(tx, gasCost);
    const txHash = sent.transactionPointer.identifier;
    const tree = await txClient.waitForSpawnedEvents(sent);
    const rootStatus =
      tree?.root?.transaction?.executionStatus ?? tree?.transaction?.executionStatus;
    if (rootStatus?.success === false) {
      const msg = rootStatus.failure?.errorMessage ?? "unknown error";
      throw new Error(`contract failure: ${msg.split("\n")[0]}`);
    }
    const events = tree?.events ?? tree?.spawned ?? [];
    for (const ev of events) {
      const es = ev?.transaction?.executionStatus ?? ev?.executionStatus;
      if (es?.success === false) {
        const msg = es.failure?.errorMessage ?? es.errorMessage ?? "unknown error";
        throw new Error(`spawned failure: ${msg.split("\n")[0]}`);
      }
    }
    process.stdout.write(JSON.stringify({ ok: true, txHash, nodeUrl }));
    process.exit(0);
  } catch (err) {
    lastErr = { nodeUrl, message: fmt(err) };
  }
}

process.stderr.write(JSON.stringify(lastErr ?? { message: "zk submit failed" }));
process.exit(1);
