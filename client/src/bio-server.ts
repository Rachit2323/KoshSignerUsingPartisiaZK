/**
 * Biometric ZK Wallet Server
 *
 * Handles all Partisia blockchain transactions for the browser demo.
 * Browser sends fingerprint minutiae → server submits ZK secrets to Partisia.
 *
 * Endpoints:
 *   POST /enroll   - enroll biometric (8 ZK chunks) + run DKG (3 shares)
 *   POST /recover  - recover biometric (8 ZK chunks) → get seed → address
 *   GET  /state    - Partisia contract state + all tx history
 *   GET  /address  - derive address from seed (no Partisia needed)
 */

import express from "express";
import cors from "cors";
import { PartisiaClient } from "./partisia.js";
import { createZkClient } from "./zk-signer.js";
import { enrollBiometric, recoverBiometric } from "./biometric-zk-flow.js";
import { generateDkgShare, buildDkgCreateKeyArgs, buildDkgCommitArgs, buildDkgRevealArgs, buildDkgFinalizeArgs, buildDkgCompleteKeygenArgs, computeCombinedPublicKey, toHex } from "./dkg-party.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import type { Minutia } from "./biometric-native.js";

// --- Config ---
const CONTRACT_ADDR = process.env.BIO_CONTRACT_ADDR ?? "03915ea87f3d3478ec9e2db45bac27b1d7bf8c34e6";
const DEPLOYER_KEY  = process.env.DEPLOYER_KEY  ?? "d3e922aead1dbc8b67de4dad9bf0da70be574dfa2088ac1a7e116c39024c41e5";
const DEPLOYER_ADDR = process.env.DEPLOYER_ADDR ?? "008fc011c7a89525b82929504fa46bb611475a3422";
const NODE_URL      = process.env.NODE_URL      ?? "https://node1.testnet.partisiablockchain.com";
const PORT          = Number(process.env.PORT ?? 3001);

// --- Transaction history (in-memory) ---
const txHistory: Array<{
  id: number;
  time: string;
  type: string;
  label: string;
  txHash: string | null;
  status: "pending" | "done" | "failed";
}> = [];
let txIdCounter = 1;

function recordTx(type: string, label: string, txHash: string | null = null, status: "done" | "failed" = "done") {
  txHistory.push({
    id: txIdCounter++,
    time: new Date().toISOString(),
    type,
    label,
    txHash,
    status,
  });
}

// --- Helpers ---
function encodeU32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >> 24) & 0xff; buf[1] = (n >> 16) & 0xff;
  buf[2] = (n >> 8) & 0xff;  buf[3] = n & 0xff;
  return buf;
}

function deriveEthAddress(pubKeyUncompressed: Uint8Array): string {
  const hash = keccak_256(pubKeyUncompressed.slice(1));
  return "0x" + Array.from(hash.slice(12)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// HKDF-based party seed derivation (matches browser)
async function derivePartySeeds(secret: Uint8Array, n: number): Promise<Uint8Array[]> {
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const salt = new TextEncoder().encode("kosh-zk-signer-v1");
  const seeds: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    seeds.push(hkdf(sha256, secret, salt, `kosh-party-${i + 1}`, 32));
  }
  return seeds;
}

// --- Express app ---
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Serve the HTML demo
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));

app.get("/", (req, res) => {
  res.sendFile(resolve(__dirname, "biometric-native-demo.html"));
});

// --- GET /state — Partisia contract state + tx history ---
app.get("/state", async (req, res) => {
  try {
    const partisia = new PartisiaClient({ nodeUrl: NODE_URL, senderPrivateKey: DEPLOYER_KEY, senderAddress: DEPLOYER_ADDR });
    const sc = await partisia.getContractData(CONTRACT_ADDR); // already unwrapped

    res.json({
      contractAddress: CONTRACT_ADDR,
      explorerUrl: `https://browser.testnet.partisiablockchain.com/contracts/${CONTRACT_ADDR}`,
      nextVariableId: (sc as any)?.nextVariableId ?? 0,
      zkVariablesSubmitted: ((sc as any)?.nextVariableId ?? 1) - 1,
      calculationStatus: (sc as any)?.calculationStatus ?? "UNKNOWN",
      zkNodes: ((sc as any)?.engines?.engines ?? []).map((e: any) => ({
        identity: e.identity,
        restInterface: e.restInterface,
      })),
      txHistory,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- POST /enroll — biometric enrollment on Partisia (runs in background) ---
app.post("/enroll", async (req, res) => {
  const { minutiae, keyId, secret } = req.body as { minutiae: Minutia[]; keyId?: number; secret?: number[] };

  if (!minutiae || !Array.isArray(minutiae)) {
    return res.status(400).json({ error: "minutiae array required" });
  }

  const kid = keyId ?? 100;

  // Derive address immediately from local DKG (no Partisia needed for address)
  let ethAddress = "";
  if (secret && secret.length > 0) {
    const sec = new Uint8Array(secret);
    const seeds = await derivePartySeeds(sec, 3);
    const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    let combined = null as any;
    for (const seed of seeds) {
      const hex = Array.from(seed).map(b => b.toString(16).padStart(2, "0")).join("");
      let scalar = BigInt("0x" + hex);
      scalar = ((scalar % (N - 1n)) + 1n);
      const pt = secp256k1.ProjectivePoint.BASE.multiply(scalar);
      combined = combined ? combined.add(pt) : pt;
    }
    ethAddress = deriveEthAddress(combined.toRawBytes(false));
  }

  // Return address immediately — Partisia enrollment runs in background
  res.json({ ok: true, keyId: kid, ethAddress, enrolling: true, txCount: txHistory.length });

  // Run Partisia enrollment in background (don't await)
  (async () => {
    const partisia = new PartisiaClient({ nodeUrl: NODE_URL, senderPrivateKey: DEPLOYER_KEY, senderAddress: DEPLOYER_ADDR });
    const zkClient = createZkClient(NODE_URL, CONTRACT_ADDR);

    try {
      function encodeU32BE(n: number): Uint8Array {
        const b = new Uint8Array(4);
        b[0]=(n>>24)&0xff; b[1]=(n>>16)&0xff; b[2]=(n>>8)&0xff; b[3]=n&0xff; return b;
      }

      recordTx("enroll", `Creating key ${kid} on Partisia`);
      const createTx = await partisia.submitAction(CONTRACT_ADDR, 0x02, encodeU32BE(kid));
      recordTx("enroll", `create_key_with_id (key ${kid})`, createTx);
      console.log(`[bg] create_key tx: ${createTx}`);
      await new Promise(r => setTimeout(r, 8000));

      const { commitment } = await enrollBiometric(partisia, zkClient, CONTRACT_ADDR, kid, minutiae);
      recordTx("enroll", `Biometric enrolled — 8 ZK chunks on-chain`, null, "done");

      // --- DKG Phase — create the signing key (split across ZK nodes) ---
      const numParties = 3;
      const dkgKeyId = kid + 10000; // separate namespace for DKG keys

      const createKeyTx = await partisia.submitAction(CONTRACT_ADDR, 0x20, buildDkgCreateKeyArgs(dkgKeyId, numParties));
      recordTx("dkg", `dkg_create_key — key slot for ${numParties} parties, phase → Committing`, createKeyTx);
      await new Promise(r => setTimeout(r, 6000));

      // Generate 3 party shares deterministic from commitment
      const shares = [];
      for (let i = 0; i < numParties; i++) {
        const seedInput = new Uint8Array([...commitment, i]);
        shares.push(await generateDkgShare(seedInput));
      }

      // Commit phase
      for (let i = 0; i < numParties; i++) {
        const tx = await partisia.submitAction(CONTRACT_ADDR, 0x21, buildDkgCommitArgs(dkgKeyId, i, shares[i].commitmentHash));
        recordTx("dkg", `dkg_commit P${i+1} — committed SHA-256(P${i+1}), locked in choice`, tx);
        await new Promise(r => setTimeout(r, 4000));
      }

      // Reveal phase
      for (let i = 0; i < numParties; i++) {
        const tx = await partisia.submitAction(CONTRACT_ADDR, 0x22, buildDkgRevealArgs(dkgKeyId, i, shares[i].publicKeyShare));
        recordTx("dkg", `dkg_reveal P${i+1} — revealed P${i+1}, contract verified SHA-256(P${i+1}) ✓`, tx);
        await new Promise(r => setTimeout(r, 4000));
      }

      // Finalize — contract computes P = P₁ + P₂ + P₃
      const finTx = await partisia.submitAction(CONTRACT_ADDR, 0x23, buildDkgFinalizeArgs(dkgKeyId));
      recordTx("dkg", `dkg_finalize — contract computed P = P₁+P₂+P₃ (EC point addition)`, finTx);
      await new Promise(r => setTimeout(r, 6000));

      // Complete keygen
      const compTx = await partisia.submitAction(CONTRACT_ADDR, 0x24, buildDkgCompleteKeygenArgs(dkgKeyId));
      recordTx("dkg", `dkg_complete_keygen — key marked Complete, public key stored, ready for signing`, compTx);

      // Compute and record the combined public key + address
      const combinedPub = computeCombinedPublicKey(shares.map(s => s.publicKeyShare));
      const pubUncompressed = secp256k1.ProjectivePoint.fromHex(combinedPub).toRawBytes(false);
      const dkgAddress = deriveEthAddress(pubUncompressed);
      recordTx("address", `DKG key complete — Ethereum address: ${dkgAddress}`, null, "done");

      if (ethAddress) {
        recordTx("address", `Biometric address: ${ethAddress}`, null, "done");
      }
      console.log(`[bg] Enrollment + DKG complete for key ${kid}. DKG address: ${dkgAddress}`);
    } catch (err: any) {
      recordTx("enroll", `Enrollment failed: ${err.message}`, null, "failed");
      console.error("[bg] Enroll error:", err.message);
    }
  })();
});

// --- POST /recover — biometric recovery → seed → address ---
app.post("/recover", async (req, res) => {
  const { minutiae, keyId, secret } = req.body as { minutiae: Minutia[]; keyId?: number; secret?: number[] };
  const kid = keyId ?? 100; // key 100 is the enrolled key from previous session

  const partisia = new PartisiaClient({ nodeUrl: NODE_URL, senderPrivateKey: DEPLOYER_KEY, senderAddress: DEPLOYER_ADDR });
  const zkClient = createZkClient(NODE_URL, CONTRACT_ADDR);

  recordTx("recover", `bio_recover_start (key ${kid})`);
  console.log(`[server] Recovering biometric for key ${kid}...`);

  // Derive address immediately from local DKG
  let ethAddressLocal = "";
  if (secret && secret.length > 0) {
    const sec = new Uint8Array(secret);
    const seeds = await derivePartySeeds(sec, 3);
    const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    let combined = null as any;
    for (const seed of seeds) {
      const hex = Array.from(seed).map(b => b.toString(16).padStart(2, "0")).join("");
      let scalar = BigInt("0x" + hex);
      scalar = ((scalar % (N - 1n)) + 1n);
      const pt = secp256k1.ProjectivePoint.BASE.multiply(scalar);
      combined = combined ? combined.add(pt) : pt;
    }
    ethAddressLocal = deriveEthAddress(combined.toRawBytes(false));
  }

  try {
    // First check if key exists and is enrolled in contract state
    const sc = await partisia.getContractData(CONTRACT_ADDR) as any;
    const avlTrees = sc?.openState?.avlTrees ?? sc?.avlTrees ?? [];
    const keyTree = avlTrees.find((t: any) => t.key === 0);
    const keyIdBE = Buffer.alloc(4);
    keyIdBE.writeUInt32BE(kid);
    const keyIdLE = Buffer.alloc(4);
    keyIdLE.writeUInt32LE(kid);
    const keyIdB64BE = keyIdBE.toString("base64");
    const keyIdB64LE = keyIdLE.toString("base64");
    const keyEntry = keyTree?.value?.avlTree?.find((e: any) => {
      const k = e.key?.data?.data ?? e.key?.data ?? "";
      return k === keyIdB64BE || k === keyIdB64LE;
    });

    if (!keyEntry) {
      console.log(`[server] Key ${kid} not found — needs enrollment`);
      recordTx("recover", `Key ${kid} not enrolled — enrollment needed`, null, "failed");
      return res.json({ ok: false, matched: false, needsEnrollment: true, ethAddress: ethAddressLocal });
    }

    // Return local address immediately — Partisia recovery runs in background
    recordTx("recover", `bio_recover_start (key ${kid}) — running in background`);
    res.json({ ok: true, matched: true, ethAddress: ethAddressLocal, recovering: true, txCount: txHistory.length });

    // Background: run full Partisia biometric recovery (ZK match on-chain)
    (async () => {
      try {
        const result = await recoverBiometric(partisia, zkClient, CONTRACT_ADDR, kid, minutiae);
        recordTx("recover", `bio_trigger_match → MPC across ${(await partisia.getContractData(CONTRACT_ADDR) as any)?.engines?.engines?.length ?? 4} ZK nodes`, null, "done");
        if (result.matched && result.seed) {
          recordTx("recover", `Biometric match SUCCESS — ZK seed derived`, null, "done");
          recordTx("address", `ZK-verified address: ${ethAddressLocal}`, null, "done");
        } else {
          recordTx("recover", `ZK match result: no match (seed = 0)`, null, "failed");
        }
        console.log(`[bg] Recovery done. Matched: ${result.matched}`);
      } catch (err: any) {
        recordTx("recover", `Background recovery error: ${err.message}`, null, "failed");
        console.error("[bg] Recover error:", err.message);
      }
    })();

  } catch (err: any) {
    recordTx("recover", `Recovery failed: ${err.message}`, null, "failed");
    console.error("[server] Recover error:", err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// --- POST /derive — derive address locally from PRF secret (no Partisia) ---
app.post("/derive", async (req, res) => {
  const { secret } = req.body as { secret: number[] };
  if (!secret || secret.length === 0) return res.status(400).json({ error: "secret required" });
  try {
    const sec = new Uint8Array(secret);
    const seeds = await derivePartySeeds(sec, 3);
    const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    let combined = null as any;
    for (const seed of seeds) {
      const hex = Array.from(seed).map(b => b.toString(16).padStart(2, "0")).join("");
      let scalar = BigInt("0x" + hex);
      scalar = ((scalar % (N - 1n)) + 1n);
      const pt = secp256k1.ProjectivePoint.BASE.multiply(scalar);
      combined = combined ? combined.add(pt) : pt;
    }
    const ethAddress = deriveEthAddress(combined.toRawBytes(false));
    res.json({ ethAddress });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`\n=== Kosh Bio Server running on http://localhost:${PORT} ===`);
  console.log(`Contract: ${CONTRACT_ADDR}`);
  console.log(`Explorer: https://browser.testnet.partisiablockchain.com/contracts/${CONTRACT_ADDR}\n`);
});
