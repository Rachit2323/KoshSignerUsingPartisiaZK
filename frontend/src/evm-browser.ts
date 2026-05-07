/**
 * Local replacement for kosh-evm-client/browser.
 * Implements EVM transaction building, signing, and submission using viem.
 */
import { createPublicClient, http, keccak256, toHex, serializeTransaction, type Hex, type TransactionSerializableLegacy } from "viem";
import { sepolia } from "viem/chains";
import { secp256k1 } from "@noble/curves/secp256k1";

// ── Types ────────────────────────────────────────────────────────────────────

export type BrowserThresholdKeyStatus = {
  key_id: string | number;
  exists: boolean;
  phase: number;
  combined_pk_hex?: string;
  evm_address?: string;
  // camelCase aliases populated after load
  evmAddress?: string;
  publicKeyHex?: string;
  keygenPhaseDiscriminant?: number;
  verifiedTaskIds: (string | number)[];
};

export type UnsignedEthTransfer = {
  to: Hex;
  from: Hex;
  value: bigint;
  nonce: number;
  gas: bigint;
  gasPrice: bigint;
  chainId: number;
  data?: Hex;
};

// ── Sepolia public client ────────────────────────────────────────────────────

const sepoliaClient = createPublicClient({
  chain: sepolia,
  transport: http("https://ethereum-sepolia-rpc.publicnode.com"),
});

// ── buildEthTransfer ─────────────────────────────────────────────────────────

export async function buildEthTransfer({
  apiBaseUrl,
  from,
  to,
  value,
}: {
  apiBaseUrl?: string;
  from: Hex;
  to: Hex;
  value: bigint;
}): Promise<UnsignedEthTransfer> {
  if (apiBaseUrl) {
    const resp = await fetch(`${apiBaseUrl}/api/v1/evm/build-eth-transfer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, value: value.toString() }),
    });
    if (resp.ok) {
      const body = (await resp.json()) as {
        transaction?: {
          to: Hex;
          from: Hex;
          value: string;
          nonce: number;
          gas: string;
          gasPrice: string;
          chainId: number;
          data?: Hex;
        };
      };
      if (body.transaction) {
        return {
          to: body.transaction.to,
          from: body.transaction.from,
          value: BigInt(body.transaction.value),
          nonce: body.transaction.nonce,
          gas: BigInt(body.transaction.gas),
          gasPrice: BigInt(body.transaction.gasPrice),
          chainId: body.transaction.chainId,
          data: body.transaction.data,
        };
      }
    }
  }

  const [nonce, gasPrice, gas] = await Promise.all([
    sepoliaClient.getTransactionCount({ address: from }),
    sepoliaClient.getGasPrice(),
    sepoliaClient.estimateGas({ account: from, to, value }).catch(() => 21000n),
  ]);

  return { to, from, value, nonce, gas, gasPrice, chainId: sepolia.id };
}

// ── getTransactionSigningHash ─────────────────────────────────────────────────

export function getTransactionSigningHash(tx: UnsignedEthTransfer): Hex {
  const serialized = serializeTransaction({
    type: "legacy",
    to: tx.to,
    value: tx.value,
    nonce: tx.nonce,
    gas: tx.gas,
    gasPrice: tx.gasPrice,
    chainId: tx.chainId,
    data: tx.data,
  } as TransactionSerializableLegacy);
  return keccak256(serialized);
}

// ── parseSignatureBytes ───────────────────────────────────────────────────────

export function parseSignatureBytes(
  sigBytes: Uint8Array,
  _signingHash: Hex,
  _evmAddress: Hex
): { r: Hex; s: Hex; recoveryId: 0 | 1 } {
  if (sigBytes.length < 64) {
    throw new Error(`signature too short: ${sigBytes.length} bytes`);
  }
  const r = toHex(sigBytes.slice(0, 32)) as Hex;
  const s = toHex(sigBytes.slice(32, 64)) as Hex;
  // Use v byte if present (65-byte DER), otherwise try recoveryId=0
  let recoveryId: 0 | 1 = 0;
  if (sigBytes.length >= 65) {
    const v = sigBytes[64];
    recoveryId = (v === 28 || v === 1) ? 1 : 0;
  }
  return { r, s, recoveryId };
}

// ── signTransaction ───────────────────────────────────────────────────────────

export function signTransaction(
  tx: UnsignedEthTransfer,
  r: Hex,
  s: Hex,
  recoveryId: 0 | 1
): Hex {
  // EIP-155: v = recoveryId + 2 * chainId + 35
  const v = BigInt(recoveryId) + BigInt(2 * tx.chainId + 35);
  return serializeTransaction(
    {
      type: "legacy",
      to: tx.to,
      value: tx.value,
      nonce: tx.nonce,
      gas: tx.gas,
      gasPrice: tx.gasPrice,
      chainId: tx.chainId,
      data: tx.data,
    } as TransactionSerializableLegacy,
    { r, s, v }
  );
}

// ── submitSignedTransaction ───────────────────────────────────────────────────

export async function submitSignedTransaction(signedTx: Hex, apiBaseUrl?: string): Promise<Hex> {
  if (apiBaseUrl) {
    const resp = await fetch(`${apiBaseUrl}/api/v1/evm/broadcast-signed`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ signed_tx_hex: signedTx }),
    });
    if (resp.ok) {
      const body = (await resp.json()) as { tx_hash?: Hex };
      if (body.tx_hash) return body.tx_hash;
    }
  }
  return sepoliaClient.sendRawTransaction({ serializedTransaction: signedTx });
}

// ── pubKeyToEvmAddress ────────────────────────────────────────────────────────
// EVM address = keccak256(uncompressed_pubkey[1:])[12:]
// Decompress 33-byte compressed pubkey to 65-byte uncompressed (04 + X + Y),
// then hash the 64 bytes (X + Y) and take last 20 bytes.
export function pubKeyToEvmAddress(compressedPubKey: Uint8Array): Hex {
  // @noble/curves provides ProjectivePoint to decompress
  // viem doesn't expose this directly; use the implementation already imported
  const point = secp256k1.ProjectivePoint.fromHex(compressedPubKey);
  const uncompressed = point.toRawBytes(false); // 65 bytes: 04 || X || Y
  const hash = keccak256(uncompressed.slice(1)); // hash 64 bytes (X || Y)
  return `0x${hash.slice(-40)}` as Hex;
}
