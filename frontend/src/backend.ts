/**
 * Legacy TypeScript backend bridge.
 * Phase 12 cleanup: frontend should use the Rust backend (`cargo run -p kosh-backend`).
 * Keep this file only as a behavioral reference until final deletion.
 */

import http from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { SenderAuthenticationKeyPair } from "@partisiablockchain/blockchain-api-transaction-client";
import { AbiParser, JsonValueConverter, StateReader } from "@partisiablockchain/abi-client";
import { pubKeyToEvmAddress } from "kosh-evm-client/browser";
import { parseSignatureBytes, signTransaction, submitSignedTransaction } from "kosh-evm-client";

type ExecutionMode = "legacy_existing_key" | "fresh_owned_contract";

type JobStatus =
  | "idle"
  | "running"
  | "failed_partisia_write"
  | "failed_partisia_contract"
  | "failed_sepolia_broadcast"
  | "completed";

type ErrorStage =
  | "partisia_preflight"
  | "partisia_write"
  | "partisia_contract"
  | "sepolia_broadcast"
  | "fresh_setup";

type ThresholdRuntimeState = {
  version: 1;
  mode: "fresh_owned_contract";
  createdAt: string;
  updatedAt: string;
  senderKey: string;
  senderAddress: string;
  contractAddress: string;
  keyId: number;
  shareFileKey: string;
  shareFiles: Record<number, string>;
  pqcKeyFiles: Record<number, string>;
  evmAddress: string | null;
};

type Job = {
  id: string;
  status: JobStatus;
  createdAt: string;
  finishedAt: string | null;
  request: {
    keyId: number;
    signerAddress: string;
    signingHashHex: string;
    signingSubset: string;
    unsignedTx?: Record<string, unknown>;
  };
  logs: string[];
  error: string | null;
  errorStage: ErrorStage | null;
  mode: ExecutionMode | null;
  pathSwitched: boolean;
  coordPort: number;
  children: ChildProcess[];
  evmTxHash: string | null;
  senderAddress: string;
  contractOwnerAddress: string | null;
  activeContractAddress: string;
  activeKeyId: number;
  activeEvmAddress: string | null;
  nodeUrls: string[];
  latestAttemptedNode: string | null;
  targetChain: "ethereum-sepolia";
};

type RuntimeSummary = {
  mode: ExecutionMode;
  contractAddress: string;
  keyId: number;
  senderAddress: string;
  evmAddress: string | null;
  updatedAt: string;
};

function publicJob(job: Job | null): Record<string, unknown> {
  if (!job) return { status: "idle" };
  return {
    id: job.id,
    status: job.status,
    createdAt: job.createdAt,
    finishedAt: job.finishedAt,
    request: job.request,
    logs: job.logs,
    error: job.error,
    errorStage: job.errorStage,
    mode: job.mode,
    pathSwitched: job.pathSwitched,
    coordPort: job.coordPort,
    evmTxHash: job.evmTxHash,
    senderAddress: job.senderAddress,
    contractOwnerAddress: job.contractOwnerAddress,
    activeContractAddress: job.activeContractAddress,
    activeKeyId: job.activeKeyId,
    activeEvmAddress: job.activeEvmAddress,
    nodeUrls: job.nodeUrls,
    latestAttemptedNode: job.latestAttemptedNode,
    targetChain: job.targetChain,
  };
}

function runtimeSummary(state: ThresholdRuntimeState | null): RuntimeSummary | null {
  if (!runtimeStateLooksUsable(state)) return null;
  return {
    mode: state.mode,
    contractAddress: state.contractAddress,
    keyId: state.keyId,
    senderAddress: state.senderAddress,
    evmAddress: state.evmAddress,
    updatedAt: state.updatedAt,
  };
}

const PORT = Number(process.env.KOSH_FRONTEND_API_PORT ?? "8787");
const rootClientDir = path.resolve(process.cwd(), "../../../client");
const repoRootDir = path.resolve(process.cwd(), "../../..");
const signerAbiPath = path.join(repoRootDir, "target/wasm32-unknown-unknown/release/kosh_zk_signer.abi");
const defaultNodeUrl = process.env.PARTISIA_NODE_URL ?? "https://node4.testnet.partisiablockchain.com";
const defaultSenderKey = normalizeSecretEnv(process.env.PARTISIA_SENDER_KEY ?? "");
const defaultSenderAddress = normalizeSecretEnv(process.env.PARTISIA_SENDER_ADDRESS ?? "");
const defaultSignerAddress = process.env.SIGNER_ADDRESS ?? "03134ea5680d7681863d25f99e28ca30dfb44adb9b";
const defaultShareFileKey = process.env.SHARE_FILE_KEY ?? "kosh-test-share-key-1777145890";
const defaultSigningSubset = process.env.SIGNING_SUBSET ?? "1,2";
const requiredOwnerAddress = normalizeSecretEnv(process.env.PARTISIA_CONTRACT_OWNER_ADDRESS ?? "");
const defaultNodeUrls = defaultNodeUrl.split(",").map((url) => url.trim()).filter(Boolean);
const freshSenderKeyEnv = normalizeSecretEnv(process.env.PARTISIA_FRESH_SENDER_KEY ?? "");
const freshSenderAddressEnv = normalizeSecretEnv(process.env.PARTISIA_FRESH_SENDER_ADDRESS ?? "");
const legacyDefaultKeyId = Number(process.env.LEGACY_KEY_ID ?? "60004");
const runtimeDir = path.join(process.cwd(), ".kosh-runtime");
const freshRuntimePath = path.join(runtimeDir, "fresh-threshold-runtime.json");
const freshSenderKeyPath = path.join(runtimeDir, "fresh-partisia-sender.pk");

let activeJob: Job | null = null;
const signerAbi = new AbiParser(fs.readFileSync(signerAbiPath)).parseAbi().chainComponent;

function normalizeSecretEnv(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "...") return "";
  if (trimmed.includes("<") || trimmed.includes(">")) return "";
  return trimmed;
}

function sendJson(res: http.ServerResponse, statusCode: number, body: unknown): void {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(JSON.stringify(body));
}

function append(job: Job, line: string): void {
  job.logs.push(line);
  if (job.logs.length > 300) job.logs.shift();
}

function attachLogs(job: Job, name: string, child: ChildProcess): void {
  child.stdout?.on("data", (chunk) => {
    for (const line of String(chunk).split("\n").filter(Boolean)) {
      trackJobLog(job, line);
      append(job, `[${name}] ${line}`);
    }
  });
  child.stderr?.on("data", (chunk) => {
    for (const line of String(chunk).split("\n").filter(Boolean)) {
      trackJobLog(job, line);
      append(job, `[${name}:err] ${line}`);
    }
  });
}

function killChildren(job: Job): void {
  for (const child of job.children) {
    try {
      child.kill("SIGTERM");
    } catch {}
  }
}

async function clearCoord(coordPort: number): Promise<void> {
  await fetch(`http://localhost:${coordPort}/clear`, { method: "DELETE" });
}

function ensureRuntimeDir(): void {
  fs.mkdirSync(runtimeDir, { recursive: true });
}

function shareFileFor(keyId: number, partyIndex: number): string {
  return path.join(rootClientDir, "test-logs", `share_key${keyId}_party${partyIndex}.enc`);
}

function freshShareFileFor(keyId: number, partyIndex: number): string {
  ensureRuntimeDir();
  return path.join(runtimeDir, `fresh_share_key${keyId}_party${partyIndex}.enc`);
}

function freshPqcFileFor(keyId: number, partyIndex: number): string {
  ensureRuntimeDir();
  return path.join(runtimeDir, `fresh_pqc_key${keyId}_party${partyIndex}.json`);
}

function encodeKeyIdBase64(keyId: number): string {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(keyId, 0);
  return buf.toString("base64");
}

function formatUnknownError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err ?? "unknown error");
}

function loadFreshRuntimeState(): ThresholdRuntimeState | null {
  if (!fs.existsSync(freshRuntimePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(freshRuntimePath, "utf8")) as ThresholdRuntimeState;
  } catch {
    return null;
  }
}

function saveFreshRuntimeState(state: ThresholdRuntimeState): void {
  ensureRuntimeDir();
  fs.writeFileSync(freshRuntimePath, JSON.stringify(state, null, 2), "utf8");
}

function runtimeStateLooksUsable(state: ThresholdRuntimeState | null): state is ThresholdRuntimeState {
  if (!state) return false;
  if (!state.contractAddress || !state.senderKey || !state.senderAddress) return false;
  if (!Number.isFinite(state.keyId)) return false;
  for (const partyIndex of [1, 2, 3]) {
    if (!state.shareFiles[partyIndex] || !fs.existsSync(state.shareFiles[partyIndex])) return false;
  }
  return true;
}

function classifyJobFailure(job: Job, message: string): { status: JobStatus; stage: ErrorStage } {
  const lower = message.toLowerCase();
  if (lower.includes("preflight")) {
    return { status: "failed_partisia_write", stage: "partisia_preflight" };
  }
  if (lower.includes("fresh") || lower.includes("deploy")) {
    return { status: "failed_partisia_write", stage: "fresh_setup" };
  }
  if (lower.includes("broadcast") || lower.includes("sepolia")) {
    return { status: "failed_sepolia_broadcast", stage: "sepolia_broadcast" };
  }
  if (lower.includes("failed:") || lower.includes("failed (spawned)")) {
    return { status: "failed_partisia_contract", stage: "partisia_contract" };
  }
  return { status: "failed_partisia_write", stage: "partisia_write" };
}

function trackJobLog(job: Job, line: string): void {
  const nodeMatch = line.match(/https:\/\/node\d+\.testnet\.partisiablockchain\.com/);
  if (nodeMatch) job.latestAttemptedNode = nodeMatch[0];
}

function summarizeRecentPartyError(job: Job, partyName: string): string {
  const matches = job.logs
    .filter((line) => line.startsWith(`[${partyName}`))
    .slice(-8);
  return matches.length ? matches.join(" | ") : `${partyName} exited unexpectedly`;
}

async function runCommand(
  job: Job,
  name: string,
  command: string,
  args: string[],
  options: { cwd: string; env?: NodeJS.ProcessEnv }
): Promise<string> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
    });
    let output = "";
    child.stdout?.on("data", (chunk) => {
      const text = String(chunk);
      output += text;
      for (const line of text.split("\n").filter(Boolean)) append(job, `[${name}] ${line}`);
    });
    child.stderr?.on("data", (chunk) => {
      const text = String(chunk);
      output += text;
      for (const line of text.split("\n").filter(Boolean)) append(job, `[${name}:err] ${line}`);
    });
    child.on("error", (err) => reject(err));
    child.on("exit", (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(`${name} exited with code ${code}: ${output.trim()}`));
    });
  });
}

async function preflightPartisiaWrite(
  job: Job,
  senderKey: string,
  senderAddress: string,
  ownerAddress: string | null,
  signerAddress: string,
): Promise<void> {
  append(job, `Preflight: sender ${senderAddress} targeting nodes ${job.nodeUrls.join(", ")}`);
  if (ownerAddress && senderAddress.toLowerCase() !== ownerAddress.toLowerCase()) {
    throw new Error(
      `Partisia sender ${senderAddress} is not the contract owner ${ownerAddress}. This signer contract only allows owner-triggered signing actions.`
    );
  }
  try {
    SenderAuthenticationKeyPair.fromString(senderKey);
  } catch (err) {
    throw new Error(`Partisia sender key is malformed: ${formatUnknownError(err)}`);
  }
  let lastErr: unknown;
  for (const nodeUrl of job.nodeUrls) {
    try {
      const resp = await fetch(`${nodeUrl.replace(/\/$/, "")}/shards/Shard0/blockchain/contracts/${signerAddress}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      append(job, `Preflight OK on ${nodeUrl}`);
      job.latestAttemptedNode = nodeUrl;
      return;
    } catch (err) {
      lastErr = err;
      append(job, `Preflight failed on ${nodeUrl}: ${formatUnknownError(err)}`);
    }
  }
  throw new Error(`Partisia preflight failed for sender ${senderAddress}: ${formatUnknownError(lastErr)}`);
}

async function fetchThresholdKeyStatus(nodeUrl: string, signerAddress: string, keyId: number): Promise<Record<string, unknown>> {
  const url = `${nodeUrl.replace(/\/$/, "")}/shards/Shard0/blockchain/contracts/${signerAddress}?requireContractState=true`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to read contract state: ${resp.status}`);
  const payload = await resp.json() as { serializedContract?: any };
  const contract = payload.serializedContract ?? payload;
  const avlTrees = new Map<number, Array<[Buffer, Buffer]>>();
  for (const tree of contract.openState?.avlTrees ?? []) {
    avlTrees.set(
      tree.key,
      tree.value.avlTree.map((entry: any) => [
        Buffer.from(entry.key.data.data, "base64"),
        Buffer.from(entry.value.data, "base64"),
      ])
    );
  }
  const keyEntries = contract.openState?.avlTrees?.find((tree: any) => tree.key === 0)?.value?.avlTree ?? [];
  const keyEntry = keyEntries.find((entry: any) => entry.key.data.data === encodeKeyIdBase64(keyId));
  if (!keyEntry) {
    return {
      keyId,
      exists: false,
      publicKeyHex: null,
      evmAddress: null,
      keygenPhaseDiscriminant: null,
      signingPhaseDiscriminant: null,
      verifiedTaskIds: [],
      latestSignatureHex: null,
    };
  }

  const reader = StateReader.create(
    Buffer.from(keyEntry.value.data, "base64"),
    signerAbi as any,
    avlTrees as any
  );
  const decoded = JsonValueConverter.toJson(reader.readStateValue({ typeIndex: 0, index: 32 })) as any;
  const publicKeyHex = decoded.public_key?.isSome ? `0x${decoded.public_key.innerValue}` : null;
  const verifiedTasks = Array.isArray(decoded.signing_information?.map)
    ? decoded.signing_information.map
        .filter((entry: any) => entry?.value?.verified)
        .map((entry: any) => Number(entry.key))
        .filter((value: number) => Number.isFinite(value))
        .sort((a: number, b: number) => a - b)
    : [];
  const latestVerified = verifiedTasks.length
    ? decoded.signing_information.map.find((entry: any) => Number(entry.key) === verifiedTasks[verifiedTasks.length - 1])
    : null;
  return {
    keyId,
    exists: true,
    publicKeyHex,
    evmAddress: publicKeyHex ? pubKeyToEvmAddress(Buffer.from(publicKeyHex.slice(2), "hex")) : null,
    keygenPhaseDiscriminant: decoded.keygen_phase?.["@type"] === "Complete" ? 2 : null,
    signingPhaseDiscriminant: decoded.signing_phase?.["@type"] === "Idle" ? 0 : 1,
    verifiedTaskIds: verifiedTasks,
    latestSignatureHex: latestVerified?.value?.signature?.isSome ? `0x${latestVerified.value.signature.innerValue}` : null,
  };
}

function reviveUnsignedTx(input: Record<string, unknown>): Record<string, unknown> {
  const tx = { ...input };
  for (const key of ["value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"]) {
    const value = tx[key];
    if (typeof value === "string" && /^\d+$/.test(value)) tx[key] = BigInt(value);
  }
  for (const key of ["chainId", "nonce"]) {
    const value = tx[key];
    if (typeof value === "string" && /^\d+$/.test(value)) tx[key] = Number(value);
  }
  return tx;
}

function ensureShareFiles(keyId: number): void {
  for (const i of [1, 2, 3]) {
    const file = shareFileFor(keyId, i);
    if (!fs.existsSync(file)) {
      throw new Error(`Missing share file: ${file}`);
    }
  }
}

async function waitForChildrenToExit(job: Job, timeoutMs = 1500): Promise<void> {
  const children = [...job.children];
  if (!children.length) return;
  await Promise.all(children.map((child) => new Promise<void>((resolve) => {
    if (child.exitCode !== null || child.killed) {
      resolve();
      return;
    }
    const timer = setTimeout(resolve, timeoutMs);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  })));
}

async function ensureFreshSender(job: Job): Promise<{ senderKey: string; senderAddress: string }> {
  if (freshSenderKeyEnv && freshSenderAddressEnv) {
    append(job, `Using configured fresh sender ${freshSenderAddressEnv}`);
    return { senderKey: freshSenderKeyEnv, senderAddress: freshSenderAddressEnv };
  }
  const saved = loadFreshRuntimeState();
  if (saved?.senderKey && saved?.senderAddress) {
    append(job, `Using persisted fresh sender ${saved.senderAddress}`);
    return { senderKey: saved.senderKey, senderAddress: saved.senderAddress };
  }
  ensureRuntimeDir();
  if (!fs.existsSync(freshSenderKeyPath)) {
    append(job, `Creating fresh Partisia testnet sender...`);
    await runCommand(job, "fresh-sender", "cargo", ["pbc", "account", "create", `--file=${freshSenderKeyPath}`], {
      cwd: repoRootDir,
    });
  }
  const senderKey = fs.readFileSync(freshSenderKeyPath, "utf8").trim();
  const senderAddress = SenderAuthenticationKeyPair.fromString(senderKey).getAddress();
  append(job, `Fresh sender ready: ${senderAddress}`);
  return { senderKey, senderAddress };
}

async function deployFreshSigner(job: Job, senderKey: string, senderAddress: string): Promise<string> {
  append(job, `Deploying fresh signer contract with owner ${senderAddress}...`);
  const output = await runCommand(job, "deploy", "npm", ["run", "deploy"], {
    cwd: rootClientDir,
    env: {
      ...process.env,
      PARTISIA_SENDER_KEY: senderKey,
      PARTISIA_SENDER_ADDRESS: senderAddress,
      PARTISIA_NODE_URL: job.nodeUrls.join(","),
    },
  });
  const match = output.match(/Address:\s*([0-9a-fA-F]+)/);
  if (!match) throw new Error(`Fresh deploy failed: unable to parse contract address from output`);
  append(job, `Fresh signer deployed: ${match[1]}`);
  return match[1];
}

function createFreshRuntimeState(senderKey: string, senderAddress: string, contractAddress: string, keyId: number): ThresholdRuntimeState {
  const shareFiles: Record<number, string> = {};
  const pqcKeyFiles: Record<number, string> = {};
  for (const partyIndex of [1, 2, 3]) {
    shareFiles[partyIndex] = freshShareFileFor(keyId, partyIndex);
    pqcKeyFiles[partyIndex] = freshPqcFileFor(keyId, partyIndex);
  }
  const now = new Date().toISOString();
  return {
    version: 1,
    mode: "fresh_owned_contract",
    createdAt: now,
    updatedAt: now,
    senderKey,
    senderAddress,
    contractAddress,
    keyId,
    shareFileKey: defaultShareFileKey,
    shareFiles,
    pqcKeyFiles,
    evmAddress: null,
  };
}

async function ensureFreshRuntime(job: Job, signingHashHex: string): Promise<{ runtime: ThresholdRuntimeState; bootstrappedThisRun: boolean }> {
  const saved = loadFreshRuntimeState();
  if (runtimeStateLooksUsable(saved)) {
    append(job, `Using persisted fresh runtime ${saved.contractAddress} KEY_ID=${saved.keyId}`);
    saved.updatedAt = new Date().toISOString();
    saveFreshRuntimeState(saved);
    return { runtime: saved, bootstrappedThisRun: false };
  }
  const { senderKey, senderAddress } = await ensureFreshSender(job);
  const contractAddress = await deployFreshSigner(job, senderKey, senderAddress);
  const keyId = Date.now() % 1_000_000;
  const runtime = createFreshRuntimeState(senderKey, senderAddress, contractAddress, keyId);
  await preflightPartisiaWrite(job, senderKey, senderAddress, senderAddress, contractAddress);
  await runPartySigning(job, {
    senderKey,
    senderAddress,
    signerAddress: contractAddress,
    keyId,
    signingSubset: defaultSigningSubset,
    reuseExistingKey: false,
    shareFiles: runtime.shareFiles,
    pqcKeyFiles: runtime.pqcKeyFiles,
    messageHashHex: signingHashHex,
  });
  const status = await fetchThresholdKeyStatus(job.nodeUrls[0] ?? defaultNodeUrl, contractAddress, keyId);
  runtime.evmAddress = (status.evmAddress as string | null) ?? null;
  runtime.updatedAt = new Date().toISOString();
  saveFreshRuntimeState(runtime);
  append(job, `Fresh runtime ready: contract=${runtime.contractAddress} KEY_ID=${runtime.keyId}`);
  return { runtime, bootstrappedThisRun: true };
}

async function runPartySigning(
  job: Job,
  config: {
    senderKey: string;
    senderAddress: string;
    signerAddress: string;
    keyId: number;
    signingSubset: string;
    reuseExistingKey: boolean;
    shareFiles: Record<number, string>;
    pqcKeyFiles: Record<number, string>;
    messageHashHex: string;
  }
): Promise<void> {
  const coordPort = job.coordPort;
  const commonEnv = {
    ...process.env,
    COORD_URL: `http://localhost:${coordPort}`,
    PARTISIA_NODE_URL: defaultNodeUrl,
    PARTISIA_SENDER_KEY: config.senderKey,
    PARTISIA_SENDER_ADDRESS: config.senderAddress,
    SIGNER_ADDRESS: config.signerAddress,
    KEY_ID: String(config.keyId),
    SIGNING_SUBSET: config.signingSubset,
    REUSE_EXISTING_KEY: config.reuseExistingKey ? "1" : "0",
    SHARE_FILE_KEY: defaultShareFileKey,
    MESSAGE_HASH_HEX: config.messageHashHex,
  };

  const coord = spawn("npm", ["run", "coord"], {
    cwd: rootClientDir,
    env: { ...process.env, PORT: String(coordPort) },
    shell: true,
  });
  job.children.push(coord);
  attachLogs(job, "coord", coord);

  await new Promise((resolve) => setTimeout(resolve, 1500));
  await clearCoord(coordPort);

  const partyResults = [1, 2, 3].map((partyIndex) => new Promise<void>((resolve, reject) => {
    const child = spawn("npm", ["run", "party"], {
      cwd: rootClientDir,
      env: {
        ...commonEnv,
        PARTY_INDEX: String(partyIndex),
        SHARE_FILE: config.shareFiles[partyIndex],
        PQC_KEY_FILE: config.pqcKeyFiles[partyIndex],
      },
      shell: true,
    });
    job.children.push(child);
    attachLogs(job, `party${partyIndex}`, child);
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`party${partyIndex} exited with code ${code}: ${summarizeRecentPartyError(job, `party${partyIndex}`)}`));
    });
  }));

  await Promise.all(partyResults);
}

async function runLegacyThresholdSigning(job: Job): Promise<void> {
  if (!defaultSenderKey || !defaultSenderAddress) {
    throw new Error("Legacy owner sender is not configured.");
  }
  await preflightPartisiaWrite(
    job,
    defaultSenderKey,
    defaultSenderAddress,
    requiredOwnerAddress || defaultSenderAddress,
    job.request.signerAddress,
  );
  ensureShareFiles(job.request.keyId);
  job.mode = "legacy_existing_key";
  job.senderAddress = defaultSenderAddress;
  job.contractOwnerAddress = requiredOwnerAddress || defaultSenderAddress;
  job.activeContractAddress = job.request.signerAddress;
  job.activeKeyId = job.request.keyId;
  await runPartySigning(job, {
    senderKey: defaultSenderKey,
    senderAddress: defaultSenderAddress,
    signerAddress: job.request.signerAddress,
    keyId: job.request.keyId,
    signingSubset: job.request.signingSubset,
    reuseExistingKey: true,
    shareFiles: { 1: shareFileFor(job.request.keyId, 1), 2: shareFileFor(job.request.keyId, 2), 3: shareFileFor(job.request.keyId, 3) },
    pqcKeyFiles: { 1: `/tmp/kosh-ui-p1-pqc.json`, 2: `/tmp/kosh-ui-p2-pqc.json`, 3: `/tmp/kosh-ui-p3-pqc.json` },
    messageHashHex: job.request.signingHashHex,
  });
}

function shouldFallbackToFresh(job: Job, err: Error): boolean {
  const message = err.message.toLowerCase();
  return (
    message.includes("sign_message failed") ||
    message.includes("only the owner can call this action") ||
    message.includes("legacy owner sender is not configured") ||
    message.includes("partisia sender") ||
    message.includes("transient partisia rpc failure") ||
    message.includes("response returned an error code") ||
    message.includes("party1 exited")
  );
}

async function runThresholdSigning(job: Job): Promise<void> {
  const savedFresh = loadFreshRuntimeState();
  if (runtimeStateLooksUsable(savedFresh) &&
      job.request.signerAddress === savedFresh.contractAddress &&
      job.request.keyId === savedFresh.keyId) {
    job.mode = "fresh_owned_contract";
    job.senderAddress = savedFresh.senderAddress;
    job.contractOwnerAddress = savedFresh.senderAddress;
    job.activeContractAddress = savedFresh.contractAddress;
    job.activeKeyId = savedFresh.keyId;
    job.activeEvmAddress = savedFresh.evmAddress;
    append(job, `Using requested fresh-owned contract ${savedFresh.contractAddress} KEY_ID=${savedFresh.keyId}`);
    await preflightPartisiaWrite(job, savedFresh.senderKey, savedFresh.senderAddress, savedFresh.senderAddress, savedFresh.contractAddress);
    await runPartySigning(job, {
      senderKey: savedFresh.senderKey,
      senderAddress: savedFresh.senderAddress,
      signerAddress: savedFresh.contractAddress,
      keyId: savedFresh.keyId,
      signingSubset: defaultSigningSubset,
      reuseExistingKey: true,
      shareFiles: savedFresh.shareFiles,
      pqcKeyFiles: savedFresh.pqcKeyFiles,
      messageHashHex: job.request.signingHashHex,
    });
    return;
  }
  try {
    job.mode = "legacy_existing_key";
    ensureShareFiles(job.request.keyId);
    await runLegacyThresholdSigning(job);
  } catch (err) {
    const legacyError = err instanceof Error ? err : new Error(String(err));
    append(job, `Legacy path failed: ${legacyError.message}`);
    killChildren(job);
    await waitForChildrenToExit(job);
    job.children = [];
    if (!shouldFallbackToFresh(job, legacyError)) {
      throw legacyError;
    }
    job.pathSwitched = true;
    job.mode = "fresh_owned_contract";
    append(job, `Switching to fresh-owned contract flow...`);
    const { runtime, bootstrappedThisRun } = await ensureFreshRuntime(job, job.request.signingHashHex);
    job.senderAddress = runtime.senderAddress;
    job.contractOwnerAddress = runtime.senderAddress;
    job.activeContractAddress = runtime.contractAddress;
    job.activeKeyId = runtime.keyId;
    job.activeEvmAddress = runtime.evmAddress;
    job.latestAttemptedNode = null;
    if (!bootstrappedThisRun) {
      append(job, `Fresh runtime already complete; reusing KEY_ID ${runtime.keyId}`);
      await runPartySigning(job, {
        senderKey: runtime.senderKey,
        senderAddress: runtime.senderAddress,
        signerAddress: runtime.contractAddress,
        keyId: runtime.keyId,
        signingSubset: defaultSigningSubset,
        reuseExistingKey: true,
        shareFiles: runtime.shareFiles,
        pqcKeyFiles: runtime.pqcKeyFiles,
        messageHashHex: job.request.signingHashHex,
      });
    }
  }
}

async function parseBody(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    sendJson(res, 204, {});
    return;
  }

  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, { ok: true, activeJob: activeJob?.id ?? null });
    return;
  }

  if (req.method === "GET" && url.pathname === "/job") {
    sendJson(res, 200, publicJob(activeJob));
    return;
  }

  if (req.method === "GET" && url.pathname === "/threshold/key-status") {
    try {
      const keyId = Number(url.searchParams.get("keyId") ?? "60004");
      const signerAddress = url.searchParams.get("signerAddress") ?? defaultSignerAddress;
      const nodeUrl = url.searchParams.get("nodeUrl") ?? defaultNodeUrl;
      const status = await fetchThresholdKeyStatus(nodeUrl, signerAddress, keyId);
      sendJson(res, 200, { ok: true, status });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/runtime/active") {
    sendJson(res, 200, { ok: true, runtime: runtimeSummary(loadFreshRuntimeState()) });
    return;
  }

  if (req.method === "POST" && url.pathname === "/threshold/sign") {
    if (activeJob?.status === "running") {
      sendJson(res, 409, { ok: false, error: "A signing job is already running" });
      return;
    }

    try {
      const body = await parseBody(req);
      const keyId = Number(body.keyId ?? 60004);
      const signerAddress = String(body.signerAddress ?? defaultSignerAddress);
      const signingHashHex = String(body.signingHashHex ?? "");
      const signingSubset = String(body.signingSubset ?? defaultSigningSubset);
      const unsignedTx = body.unsignedTx ? (body.unsignedTx as Record<string, unknown>) : undefined;

      if (!/^0x[0-9a-fA-F]{64}$/.test(signingHashHex)) {
        throw new Error("signingHashHex must be a 32-byte hex string");
      }

      ensureShareFiles(keyId);

      const job: Job = {
        id: `${Date.now()}`,
        status: "running",
        createdAt: new Date().toISOString(),
        finishedAt: null,
        request: { keyId, signerAddress, signingHashHex, signingSubset },
        logs: [],
        error: null,
        errorStage: null,
        mode: null,
        pathSwitched: false,
        coordPort: 3300,
        children: [],
        evmTxHash: null,
        senderAddress: defaultSenderAddress,
        contractOwnerAddress: requiredOwnerAddress || null,
        activeContractAddress: signerAddress,
        activeKeyId: keyId,
        activeEvmAddress: null,
        nodeUrls: defaultNodeUrls,
        latestAttemptedNode: null,
        targetChain: "ethereum-sepolia",
      };
      job.request.unsignedTx = unsignedTx;
      activeJob = job;
      append(job, `Starting threshold signing for KEY_ID=${keyId} hash=${signingHashHex}`);

      runThresholdSigning(job)
        .then(() => {
          if (job.request.unsignedTx) {
            return fetchThresholdKeyStatus(job.nodeUrls[0] ?? defaultNodeUrl, job.activeContractAddress, job.activeKeyId).then((status) => {
              const latestSignatureHex = status.latestSignatureHex as `0x${string}` | null;
              const evmAddress = status.evmAddress as `0x${string}` | null;
              if (!latestSignatureHex || !evmAddress) {
                throw new Error("Threshold signing completed but latest signature or EVM address is missing");
              }
              job.activeEvmAddress = evmAddress;
              const sigBytes = Buffer.from(latestSignatureHex.slice(2), "hex");
              const { r, s, recoveryId } = parseSignatureBytes(sigBytes, job.request.signingHashHex as `0x${string}`, evmAddress);
              const signedTx = signTransaction(reviveUnsignedTx(job.request.unsignedTx!) as any, r, s, recoveryId);
              append(job, `Broadcasting signed transaction to Ethereum Sepolia...`);
              return submitSignedTransaction(signedTx).then((txHash) => {
                job.evmTxHash = txHash;
                append(job, `Ethereum Sepolia tx hash: ${txHash}`);
              }).catch((err) => {
                throw new Error(`Sepolia broadcast failed: ${formatUnknownError(err)}`);
              });
            });
          }
          return Promise.resolve();
        })
        .then(() => {
          job.status = "completed";
          job.finishedAt = new Date().toISOString();
          append(job, "Threshold signing completed successfully.");
          killChildren(job);
          job.children = [];
        })
        .catch((err) => {
          const message = formatUnknownError(err);
          const classified = classifyJobFailure(job, message);
          job.status = classified.status;
          job.finishedAt = new Date().toISOString();
          job.error = message;
          job.errorStage = classified.stage;
          append(job, `Threshold signing failed: ${job.error}`);
          killChildren(job);
          job.children = [];
        });

      sendJson(res, 202, { ok: true, jobId: job.id });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }

  sendJson(res, 404, { ok: false, error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`Kosh frontend threshold backend listening on http://localhost:${PORT}`);
});
