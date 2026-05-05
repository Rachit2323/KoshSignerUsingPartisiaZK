# Kosh ZK Signer — Threshold ECDSA Wallet on Partisia

A distributed signing system where a secp256k1 private key **never exists as a whole** — not during creation, not during signing. Three parties each hold a random piece. They produce valid Ethereum ECDSA signatures without any single party knowing the full private key.

> **Live proof**: Sepolia tx `0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41` — signed by threshold MPC, private key never existed anywhere.

---

## Table of Contents

1. [What This Does](#1-what-this-does)
2. [High-Level System Diagram](#2-high-level-system-diagram)
3. [Full Data Flow — Step by Step](#3-full-data-flow--step-by-step)
4. [Microservices Architecture](#4-microservices-architecture)
5. [DKG Flow — Key Born Split](#5-dkg-flow--key-born-split)
6. [GG20 Signing Flow](#6-gg20-signing-flow)
7. [PQC Post-Quantum Layer](#7-pqc-post-quantum-layer)
8. [Frontend — How It Connects](#8-frontend--how-it-connects)
9. [Smart Contracts](#9-smart-contracts)
10. [API Reference](#10-api-reference)
11. [Contract Actions Reference](#11-contract-actions-reference)
12. [Environment Setup](#12-environment-setup)
13. [Running Everything Locally](#13-running-everything-locally)
14. [Test Results](#14-test-results)
15. [Live Contract Addresses](#15-live-contract-addresses)
16. [Security Properties](#16-security-properties)

---

## 1. What This Does

```
User opens browser → connects wallet → signs Ethereum transaction
                                              ↓
                         No single server ever holds the private key
                         Three parties compute the signature together
                         Partisia blockchain coordinates the math
                                              ↓
                    Valid (r, σ) ECDSA signature → broadcast to Ethereum
```

Three core guarantees:
- **Key never assembled** — `s = s₁ + s₂ + s₃` exists as a sum, never as a number
- **Nonce never assembled** — `k` in ECDSA is split across parties via GG20
- **Post-quantum gated** — ML-DSA-65 + ML-KEM-768 approval required before signing

---

## 2. High-Level System Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              USER'S BROWSER                                  │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                    Kosh Frontend (Vite + TypeScript)                  │   │
│   │                 frontend/KoshSignerUsingPartisiaZK/client/           │   │
│   │                                                                      │   │
│   │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│   │  │  Create Key  │  │  Sign TX     │  │  View Status │               │   │
│   │  │  (DKG flow)  │  │  (GG20 flow) │  │  + Passkey   │               │   │
│   │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │   │
│   │         │                 │                  │                       │   │
│   │         └─────────────────┴──────────────────┘                       │   │
│   │                           │                                          │   │
│   │                    fetch() REST calls                                │   │
│   │                    http://localhost:8080/api/v1/...                  │   │
│   └───────────────────────────┼──────────────────────────────────────────┘   │
└───────────────────────────────┼──────────────────────────────────────────────┘
                                │
                                ▼ HTTP REST (port 8080)
┌──────────────────────────────────────────────────────────────────────────────┐
│                       kosh-backend  (Rust / Axum)                            │
│                       backend/src/                                           │
│                                                                              │
│   POST /api/v1/passkeys/create-key   → triggers DKG on all 3 parties        │
│   POST /api/v1/passkeys/reuse-sign   → triggers GG20 signing                │
│   GET  /api/v1/health                → health check                         │
│   GET  /api/v1/runtime/preflight     → preflight check                      │
│   GET  /api/v1/threshold/key-status  → key status on Partisia               │
│   POST /api/v1/passkeys/register/*   → WebAuthn passkey registration        │
│   POST /api/v1/passkeys/auth/*       → WebAuthn passkey auth                │
│                                                                              │
│   Orchestrates all 3 party daemons internally                               │
│   Manages job queue + SSE event streaming                                    │
└───────┬────────────────────────────────────────────────┬─────────────────────┘
        │ gRPC / internal                                │ HTTP
        │                                                │
        ▼                                                ▼
┌───────────────────────────────────┐     ┌─────────────────────────────────┐
│   NEW: kosh-gateway  (Go :8080)   │     │   Partisia Testnet / Mainnet    │
│   services/kosh-gateway/          │     │                                 │
│                                   │     │  kosh-zk-signer contract        │
│   JWT auth middleware             │     │  (Rust WASM — on-chain)         │
│   POST /api/v1/keys  → DKG        │     │                                 │
│   POST /api/v1/sign  → Signing    │     │  ZK nodes hold encrypted        │
│   POST /api/v1/policies → Policy  │     │  key share fragments            │
└───────┬───────────────────────────┘     └─────────────────────────────────┘
        │ gRPC                                          ▲
        ▼                                               │ Partisia RPC
┌────────────────────────────────────────────────────────────────────┐
│                    MICROSERVICES LAYER                              │
│                                                                    │
│  ┌────────────────────┐   ┌────────────────────────────────────┐  │
│  │ kosh-coordinator   │   │ kosh-policy  (Go :50052)           │  │
│  │ (Go :50051)        │   │                                    │  │
│  │                    │   │  Add / Remove / Validate policies  │  │
│  │ Bulletin board     │   │  Mandatory parties + thresholds    │  │
│  │ gRPC Watch streams │   └────────────────────────────────────┘  │
│  │ Post / Read / List │                                           │
│  └────────┬───────────┘                                           │
│           │ Watch streams (gRPC)                                   │
│    ┌──────┴──────────────────────────────┐                        │
│    │              │                      │                        │
│    ▼              ▼                      ▼                        │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐                           │
│ │ party-1  │ │ party-2  │ │ party-3  │  kosh-party (Rust)        │
│ │ :50060   │ │ :50061   │ │ :50062   │                           │
│ │          │ │          │ │          │  DKG phases               │
│ │ DKG      │ │ DKG      │ │ DKG      │  GG20 round 1 + 2        │
│ │ GG20     │ │ GG20     │ │ GG20     │  Paillier MtA             │
│ │ MtA      │ │ MtA      │ │ MtA      │  (FuturesUnordered)       │
│ └─┬──┬─────┘ └─┬──┬─────┘ └─┬──┬────┘                           │
│   │  │         │  │         │  │                                 │
│   ▼  ▼         ▼  ▼         ▼  ▼                                 │
│ ┌──┐┌──┐    ┌──┐┌──┐    ┌──┐┌──┐                                │
│ │KS││PQ│    │KS││PQ│    │KS││PQ│  KS = kosh-keystore (Rust)     │
│ │  ││C │    │  ││C │    │  ││C │  PQC = kosh-pqc (Rust)         │
│ └──┘└──┘    └──┘└──┘    └──┘└──┘                                │
│                                                                    │
│  ┌────────────────────────────────┐  ┌──────────────────────────┐ │
│  │ kosh-chain-relay  (Rust :50053)│  │ kosh-monitor  (Go :9090) │ │
│  │                                │  │                          │ │
│  │ Tx queue + 7-retry backoff     │  │ /metrics (Prometheus)    │ │
│  │ k256 secp256k1 signing         │  │ /health  (JSON)          │ │
│  │ All 44 contract actions        │  │ /ready   (probe)         │ │
│  └──────────────┬─────────────────┘  └──────────────────────────┘ │
└─────────────────┼──────────────────────────────────────────────────┘
                  │ HTTPS
                  ▼
        Partisia Blockchain Node
```

---

## 3. Full Data Flow — Step by Step

### A. User Creates a Wallet (DKG)

```
Browser                Backend          Party-1,2,3       Coordinator        Partisia Chain
  │                      │                  │                  │                  │
  │  POST /create-key     │                  │                  │                  │
  │─────────────────────►│                  │                  │                  │
  │                      │                  │                  │                  │
  │                      │──StartDkg()─────►│  (goroutine      │                  │
  │                      │──StartDkg()──────┼──fan-out to all) │                  │
  │                      │──StartDkg()──────┼──────────────────┘                  │
  │                      │                  │                  │                  │
  │                      │                  │  Post(commit_i)──►│                  │
  │                      │                  │  Watch(commit_j)──►│                 │
  │                      │                  │◄─commit_j─────────│                  │
  │                      │                  │  [Schnorr verify] │                  │
  │                      │                  │                  │                  │
  │                      │                  │  Post(subshare)──►│                  │
  │                      │                  │◄─subshare_ji──────│                  │
  │                      │                  │  [Feldman verify] │                  │
  │                      │                  │                  │                  │
  │                      │                  │──────────────────────────────────────►│
  │                      │                  │  dkg_create(0x20)                    │
  │                      │                  │  dkg_commit(0x21)                    │
  │                      │                  │  dkg_reveal(0x22)                    │
  │                      │                  │  dkg_finalize(0x23) → P=P₁+P₂+P₃   │
  │                      │                  │  submit_key_share(0x10) × 6         │
  │                      │                  │  dkg_complete(0x24)                  │
  │                      │                  │◄─────────────────────────────────────│
  │                      │◄─DKG_COMPLETE────│  combined_pk="02abc..."             │
  │◄─ {eth_address}──────│                  │                  │                  │
  │   {combined_pk}      │                  │                  │                  │
```

### B. User Signs a Transaction (GG20)

```
Browser                Backend          Party-1,2          Coordinator        Partisia Chain
  │                      │                  │                  │                  │
  │  POST /reuse-sign     │                  │                  │                  │
  │  {tx, key_id}        │                  │                  │                  │
  │─────────────────────►│                  │                  │                  │
  │                      │                  │                  │                  │
  │                      │  policy check ──►│                  │                  │
  │                      │  StartSign()────►│ (fan-out)        │                  │
  │                      │                  │                  │                  │
  │  [SSE stream]        │                  │  k_i=HMAC(x_i,hash,session)        │
  │◄─ phase: GG20_R1 ────│                  │  Gamma_i = gamma_i·G               │
  │                      │                  │  Post(gamma_commit)──►│             │
  │                      │                  │◄─gamma_commit_j───────│             │
  │                      │                  │  [verify, reveal]  │               │
  │                      │                  │                  │                  │
  │◄─ phase: MTA_START───│                  │  [Paillier MtA — all pairs parallel]│
  │                      │                  │  k_i·x_j → alpha_kx + beta_kx     │
  │                      │                  │  k_i·γ_j → alpha_kg + beta_kg     │
  │                      │                  │                  │                  │
  │◄─ phase: GG20_R2 ────│                  │  delta_i = k_i·gamma_i + Σ MtA    │
  │                      │                  │  sigma_i = k_i·x_i + Σ MtA        │
  │                      │                  │──────────────────────────────────────►│
  │                      │                  │  submit_delta(0x45)                 │
  │                      │                  │  submit_gamma_point(0x46)           │
  │                      │                  │  gg20_finalize_r(0x47)→r=R.x mod N │
  │                      │                  │◄─────────────────────────────────────│
  │                      │                  │  s_i = k_i⁻¹·(m + r·sigma_i)      │
  │                      │                  │──────────────────────────────────────►│
  │                      │                  │  commit_partial_sig(0x51)           │
  │                      │                  │  submit_partial_sig(0x52)           │
  │                      │                  │  finalize_gg20_sig(0x53)            │
  │                      │                  │  → σ=Σσᵢ, ECDSA verify ✓          │
  │◄─ {signature: 0x...}─│                  │◄─────────────────────────────────────│
  │                      │                  │                  │                  │
  │  broadcast to Sepolia│                  │                  │                  │
  │─────────────────────────────────────────────────────────────────────────────►│
  │                                                                      Ethereum │
```

---

## 4. Microservices Architecture

The original system was a 1339-line TypeScript monolith. It is replaced with isolated microservices:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  WHY MICROSERVICES                                                       │
│                                                                         │
│  Old: All crypto in one process → crash = restart everything            │
│  New: Crash one service → others keep running                           │
│                                                                         │
│  Old: Secrets (key share) in same memory as routing logic               │
│  New: kosh-keystore isolated — party daemon never holds secrets         │
│                                                                         │
│  Old: No external API — only driveable via env vars + bash              │
│  New: REST API + JWT → any dApp can call it                             │
│                                                                         │
│  Old: 30s polling delays between parties                                │
│  New: gRPC streaming Watch → instant push notification                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Service map

| Service | Lang | Port | Secrets | Responsibility |
|---|---|---|---|---|
| `kosh-gateway` | Go | 8080 | None | REST API, JWT auth, goroutine fan-out |
| `kosh-coordinator` | Go | 50051 | None | Bulletin board, gRPC Watch streams |
| `kosh-policy` | Go | 50052 | None | Signing policy CRUD + enforcement |
| `kosh-monitor` | Go | 9090 | None | Prometheus /metrics, health checks |
| `kosh-party` | Rust | 50060–62 | Ephemeral (k_i, gamma_i) | DKG + GG20 + Paillier MtA |
| `kosh-keystore` | Rust | 50070–72 | `x_i` (Shamir share) | AES-256-GCM encrypted shares |
| `kosh-pqc` | Rust | 50080–82 | KEM+DSA private keys | ML-KEM-768 + ML-DSA-65 |
| `kosh-chain-relay` | Rust | 50053 | Partisia private key | Tx queue, k256 signing |

### gRPC Protocol definitions

```
services/proto/
├── bulletin_board.proto   Post, Read, Watch(stream), Clear, List
├── party.proto            StartDkg(stream), StartSign(stream), GetStatus
├── keystore.proto         GenerateShare, LoadShare, FinalizeShare, GetShareHalves
├── pqc.proto              GetIdentity, Encapsulate, Decapsulate, Sign, Verify
├── chain_relay.proto      Submit(stream), GetContractState
└── policy.proto           AddPolicy, RemovePolicy, ListPolicies, Validate
```

---

## 5. DKG Flow — Key Born Split

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DKG COMMIT-REVEAL PROTOCOL                      │
│                                                                     │
│  Party 1          Party 2          Party 3                          │
│  ─────────        ─────────        ─────────                        │
│  s₁ = rand()      s₂ = rand()      s₃ = rand()                    │
│  a₁ = rand()      a₂ = rand()      a₃ = rand()                    │
│                                                                     │
│  C₁₀ = s₁·G      C₂₀ = s₂·G      C₃₀ = s₃·G   (public shares)   │
│  C₁₁ = a₁·G      C₂₁ = a₂·G      C₃₁ = a₃·G   (slope commit.)   │
│                                                                     │
│  Schnorr proof: z = r + e·sᵢ   (proves knowledge of sᵢ)           │
│  Commitment:    hash = SHA256(Cᵢ₀)                                 │
│                                                                     │
│         ┌── POST hash_1 → Coordinator ──────────────────────┐     │
│         │   POST hash_2 → Coordinator                        │     │
│         │   POST hash_3 → Coordinator                        │     │
│         │   [all parties WATCH each other's hashes]          │     │
│         │                                                     │     │
│         └── POST reveal(Cᵢ₀, Cᵢ₁, Schnorr) → Coordinator ──┘     │
│             [Schnorr verify: z·G == R + e·Cᵢ₀]                    │
│                                                                     │
│  SUBSHARE EXCHANGE (Feldman VSS):                                   │
│  fᵢ(j) = sᵢ + aᵢ·j   ← sub-share for party j                     │
│                                                                     │
│  Party i → POST fᵢ(j) for all j ≠ i                               │
│  Party i ← WATCH f_j(i) from all j ≠ i                            │
│                                                                     │
│  Verify: fⱼ(i)·G == Cⱼ₀ + i·Cⱼ₁   (Feldman check)               │
│                                                                     │
│  Final share: xᵢ = Σⱼ fⱼ(i)   (sum of all sub-shares)            │
│                                                                     │
│  Combined public key: P = C₁₀ + C₂₀ + C₃₀ = (s₁+s₂+s₃)·G       │
│  EVM address = keccak256(P.x ‖ P.y)[12:]                          │
└─────────────────────────────────────────────────────────────────────┘

                    ON-CHAIN SEQUENCE
                    ─────────────────
  0x20  dkg_create_key(key_id, n_parties)
  0x21  dkg_commit(key_id, party, SHA256(Cᵢ₀))   × 3
  0x22  dkg_reveal(key_id, party, Cᵢ₀)            × 3
  0x23  dkg_finalize(key_id)
        → Contract: P = P₁ + P₂ + P₃  (EC point addition on-chain)
  0x10  submit_key_share(ZK encrypted sᵢ halves)  × 6
  0x24  dkg_complete_keygen(key_id)
```

---

## 6. GG20 Signing Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      GG20 ROUND 1 — NONCE SETUP                     │
│                                                                     │
│  Each party i:                                                      │
│    kᵢ   = HMAC-DRBG(xᵢ, msg_hash, session_id)   ← deterministic   │
│    γᵢ   = random_scalar()                         ← masking        │
│    Γᵢ   = γᵢ · G                                  ← gamma point    │
│                                                                     │
│  Commit-reveal Γᵢ via Coordinator:                                 │
│    commit = SHA256(Γᵢ ‖ nonce)  →  all parties                     │
│    reveal = (Γᵢ, nonce)         →  after all commits               │
│    [verify SHA256(Γᵢ ‖ nonce) == committed hash]                   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│           MtA (Multiplicative-to-Additive) — Paillier               │
│                    Runs in parallel for all pairs                   │
│                                                                     │
│  For each pair (i, j):                                              │
│                                                                     │
│  k·x cross-term:                                                    │
│    Party i: Enc_j(kᵢ·xᵢ - βᵢⱼ)  →  Coordinator                   │
│    Party j: Homomorphic add xⱼ term, respond with αⱼᵢ              │
│    Result: αᵢⱼ + βᵢⱼ = kᵢ · xⱼ  (additive shares)               │
│                                                                     │
│  k·γ cross-term:  same protocol for kᵢ · γⱼ                       │
│                                                                     │
│  Uses 2048-bit Paillier (safe prime generation)                     │
│  All pairs run concurrently via FuturesUnordered                    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      GG20 ROUND 2 — AGGREGATION                     │
│                                                                     │
│  δᵢ = kᵢ·γᵢ + Σⱼ (αkγ_ij + βkγ_ji)    ← share of k·γ            │
│  σᵢ = kᵢ·xᵢ + Σⱼ (αkx_ij + βkx_ji)    ← share of k·s (secret!)  │
│                                                                     │
│  Commit-reveal δᵢ via Coordinator (same pattern as Γᵢ)             │
│                                                                     │
│  On-chain:                                                          │
│    0x45  submit_delta(δᵢ)         × n                              │
│    0x46  submit_gamma_point(Γᵢ)   × n                              │
│    0x47  gg20_finalize_r()                                          │
│          Contract computes:                                         │
│            δ = Σδᵢ       (= k·γ)                                   │
│            Γ = ΣΓᵢ       (= γ·G)                                   │
│            R = δ⁻¹ · Γ   (= k⁻¹·G, γ cancels!)                    │
│            r = R.x mod N                                            │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     PARTIAL SIGNATURES                               │
│                                                                     │
│  Each party i:                                                      │
│    sᵢ = kᵢ⁻¹ · (m + r · σᵢ)  mod N                               │
│                                                                     │
│  On-chain commit-reveal:                                            │
│    0x51  commit_partial_sig(SHA256(sᵢ))   × n                      │
│    0x52  submit_partial_sig(sᵢ)           × n                      │
│    0x53  finalize_gg20_sig()                                        │
│          Contract:                                                  │
│            σ = Σsᵢ                                                  │
│            if σ > N/2: σ = N - σ    (EIP-2 low-s)                 │
│            verify ECDSA(P, msg, r, σ) ✓   on-chain                 │
│            store (r, σ) on Partisia                                 │
└─────────────────────────────────────────────────────────────────────┘

  WHY R = δ⁻¹·Γ = k⁻¹·G :
  ─────────────────────────
  δ = k·γ   (nobody knows k or γ separately)
  Γ = γ·G   (sum of public gamma points)

  R = δ⁻¹·Γ = (k·γ)⁻¹·(γ·G) = k⁻¹·γ⁻¹·γ·G = k⁻¹·G   ✓
  γ cancels out. Nobody computed k or k⁻¹.
```

---

## 7. PQC Post-Quantum Layer

```
┌─────────────────────────────────────────────────────────────────────┐
│              PQC IDENTITY — kosh-pqc service                        │
│                                                                     │
│  On startup (or first call):                                        │
│    ML-KEM-768 keypair: (kem_dk, kem_ek)  ← from 64-byte seed      │
│    ML-DSA-65 keypair:  (dsa_sk, dsa_vk)  ← from 32-byte seed      │
│    Persisted to: PQC_KEY_FILE=/data/pqc-identity.json             │
│                                                                     │
│  GetIdentity() → (kyber_pk_b64, dilithium_pk_b64)  [public only]  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              PQC SIGNING APPROVAL (before GG20)                     │
│                                                                     │
│  1. Register on-chain (once per key):                               │
│     0x72  register_party_address(key_id, party, address)            │
│     0x73  register_dilithium_pubkey(key_id, party, pk)             │
│     0x74  register_kyber_pubkey(key_id, party, pk)                 │
│                                                                     │
│  2. Before each signing session:                                    │
│     0x75  start_pqc_approval_session(key_id, task_id, subset)      │
│                                                                     │
│  3. Each party in subset:                                           │
│     approval_hash = SHA256(domain ‖ key_id ‖ task_id ‖ msg_hash   │
│                            ‖ tx_tag ‖ party ‖ subset ‖ challenge) │
│     ML-DSA-65 sign(approval_hash) → dilithium_sig                  │
│     ML-KEM-768 encapsulate(recipient_pk) → (ciphertext, ss)        │
│     0x76  submit_pqc_approval(key_id, dilithium_sig, kyber_ct)     │
│                                                                     │
│  4. Finalize:                                                       │
│     0x77  finalize_pqc_approval(key_id, task_id)                   │
│           Contract verifies all Dilithium signatures on-chain       │
│           → GG20 signing unblocked                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 8. Frontend — How It Connects

```
frontend/KoshSignerUsingPartisiaZK/client/
├── src/
│   ├── main.ts        UI logic, state machine, all fetch() calls
│   ├── backend.ts     Legacy TS bridge (reference only)
│   ├── evm.ts         Ethereum tx building + broadcast
│   ├── partisia.ts    Partisia chain helpers
│   └── styles.css     UI styles
├── index.html         Entry point
└── package.json       Vite + TypeScript
```

### Connection flow

```
Frontend (main.ts)
       │
       │  const defaultApiBaseUrl = "http://127.0.0.1:8080"
       │
       ├─► GET  /api/v1/health                   → check backend up
       ├─► GET  /api/v1/runtime/preflight        → check chain + keys
       ├─► GET  /api/v1/runtime/active           → get current key state
       ├─► POST /api/v1/passkeys/register/start  → WebAuthn register
       ├─► POST /api/v1/passkeys/register/finish → WebAuthn complete
       ├─► POST /api/v1/passkeys/auth/start      → WebAuthn login
       ├─► POST /api/v1/passkeys/auth/finish     → WebAuthn verify
       ├─► POST /api/v1/passkeys/create-key      → trigger DKG (all 3 parties)
       ├─► POST /api/v1/passkeys/reuse-sign      → trigger GG20 signing
       ├─► GET  /api/v1/threshold/key-status     → poll key on Partisia
       └─► GET  /api/v1/threshold/task-signature → get final signature
```

### Running the frontend

```bash
# 1. Start the Rust backend (serves port 8080)
cargo run -p kosh-backend

# 2. Start the frontend dev server
cd frontend/KoshSignerUsingPartisiaZK/client
npm install
npm run dev
# → http://localhost:5173
```

### Frontend UI states

```
┌─────────────────────────────────────────────────────┐
│                  KOSH SIGNER UI                     │
│                                                     │
│  ┌───────────┐        ┌───────────────────────┐    │
│  │  CREATE   │        │       SIGN TX         │    │
│  │  NEW KEY  │        │                       │    │
│  │           │        │  Contract: 03abc...   │    │
│  │ → DKG     │        │  Key ID:   42         │    │
│  │   phases  │        │  EVM:      0x46fe...  │    │
│  │   stream  │        │                       │    │
│  │   SSE     │        │  Amount: [_____] ETH  │    │
│  │           │        │  To:     [___________]│    │
│  └───────────┘        │                       │    │
│                       │  [  SIGN & SEND  ]    │    │
│  Passkey auth         │                       │    │
│  ← WebAuthn           └───────────────────────┘    │
│                                                     │
│  Status stream (SSE):                               │
│  ● DKG_START          ● GG20_ROUND1                 │
│  ● DKG_COMMITTED      ● MTA_COMPLETE                │
│  ● DKG_SUBSHARES      ● GG20_ROUND2                 │
│  ● DKG_FINALIZED      ● PARTIAL_SIGS                │
│  ● DKG_COMPLETE  ✓    ● SIGN_COMPLETE  ✓            │
└─────────────────────────────────────────────────────┘
```

---

## 9. Smart Contracts

All contracts are Rust → WASM, deployed to Partisia. **Never modified after deploy.**

| Contract | Purpose |
|----------|---------|
| `kosh-zk-signer` | Main — DKG, GG20, PQC, policy enforcement |
| `kosh-vault` | Optional vault — holds assets, requires signer approval |
| `kosh-account-registry` | Maps Partisia addresses → signer contracts |

**Key files** (`contracts/kosh-zk-signer/src/`):

| File | What it does |
|------|-------------|
| `lib.rs` | All action handlers (0x20–0x85) |
| `signing_state.rs` | `KeyEntry`, `SigningTask`, `Phase` state types |
| `dkg.rs` | Commit/reveal, Schnorr verify, k256 EC point addition |
| `shamir.rs` | Lagrange interpolation (legacy path) |
| `off_chain.rs` | ZK node callbacks on encrypted share confirmation |
| `zk_compute.rs` | ZK compiler integration for Partisia ZK nodes |

---

## 10. API Reference

### Rust backend endpoints (port 8080, used by frontend)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Service health |
| GET | `/api/v1/runtime/preflight` | Check chain + key readiness |
| GET | `/api/v1/runtime/active` | Current runtime state |
| POST | `/api/v1/passkeys/register/start` | WebAuthn registration start |
| POST | `/api/v1/passkeys/register/finish` | WebAuthn registration finish |
| POST | `/api/v1/passkeys/auth/start` | WebAuthn auth start |
| POST | `/api/v1/passkeys/auth/finish` | WebAuthn auth finish |
| GET | `/api/v1/passkeys/me` | Current passkey account |
| POST | `/api/v1/passkeys/create-key` | Trigger DKG — creates distributed key |
| POST | `/api/v1/passkeys/reuse-sign` | Trigger GG20 — sign a transaction |
| POST | `/api/v1/passkeys/link-key` | Link key to passkey account |
| POST | `/api/v1/passkeys/select-key` | Select active key |
| GET | `/api/v1/threshold/key-status` | Key phase on Partisia |
| GET | `/api/v1/threshold/task-signature` | Retrieve final signature |
| GET | `/api/v1/jobs/:id` | Job status |
| GET | `/api/v1/jobs/:id/events` | SSE stream of job events |

### Go gateway endpoints (port 8080, microservices path)

All routes require `Authorization: Bearer <jwt>` except `/api/v1/health` and `/api/v1/token`.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/token` | Issue JWT (`X-API-Key` header) |
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/keys` | DKG — create distributed key |
| GET | `/api/v1/keys/{id}` | Key status |
| POST | `/api/v1/sign` | GG20 — sign message hash |
| GET | `/api/v1/sign/{id}` | Sign session status |
| POST | `/api/v1/policies` | Add signing policy |
| GET | `/api/v1/policies` | List policies |
| DELETE | `/api/v1/policies/{id}` | Remove policy |

### Monitor endpoints (port 9090)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/metrics` | Prometheus metrics |
| GET | `/health` | JSON service status map |
| GET | `/ready` | Readiness probe |

---

## 11. Contract Actions Reference

### DKG (0x20–0x24)
| Shortname | Name | Effect |
|-----------|------|--------|
| `0x20` | `dkg_create_key` | Open key slot, phase → Committing |
| `0x21` | `dkg_commit` | Store SHA256(Pᵢ) per party |
| `0x22` | `dkg_reveal` | Reveal Pᵢ, verify hash |
| `0x23` | `dkg_finalize` | P = P₁+P₂+P₃ on-chain |
| `0x10` | `submit_key_share` | Encrypt sᵢ half to ZK nodes |
| `0x24` | `dkg_complete_keygen` | Mark key Complete |

### GG20 Signing (0x45–0x53)
| Shortname | Name | Effect |
|-----------|------|--------|
| `0x50` | `gg20_start_signing` | Open signing session |
| `0x45` | `submit_delta` | Submit δᵢ |
| `0x46` | `submit_gamma_point` | Submit Γᵢ = γᵢ·G |
| `0x47` | `gg20_finalize_r` | R = δ⁻¹·Γ, extract r |
| `0x51` | `commit_partial_sig` | Commit SHA256(σᵢ) |
| `0x52` | `submit_partial_sig` | Reveal σᵢ |
| `0x53` | `finalize_gg20_sig` | σ=Σσᵢ, low-s, ECDSA verify ✓ |
| `0x48` | `abort_signing` | Cancel session |

### PQC (0x72–0x77)
| Shortname | Name | Effect |
|-----------|------|--------|
| `0x72` | `register_party_address` | Map party → Partisia address |
| `0x73` | `register_dilithium_pubkey` | Store ML-DSA-65 pk |
| `0x74` | `register_kyber_pubkey` | Store ML-KEM-768 pk |
| `0x75` | `start_pqc_approval_session` | Open approval window |
| `0x76` | `submit_pqc_approval` | Submit Dilithium sig |
| `0x77` | `finalize_pqc_approval` | Verify all, ungate GG20 |

---

## 12. Environment Setup

### Prerequisites

```bash
# Rust
rustup target add wasm32-unknown-unknown
cargo install cargo-partisia-contract

# Go 1.23+
go version  # must be >= 1.23

# Node.js 18+
node --version
```

### Environment variables

```bash
# ── Partisia blockchain ───────────────────────────────────────────────────
PARTISIA_NODE_URL=https://node1.testnet.partisiablockchain.com
SIGNER_ADDRESS=03...          # deployed kosh-zk-signer contract

# ── One key per party (held by chain-relay) ───────────────────────────────
PARTISIA_SENDER_KEY_1=<64-char hex private key>
PARTISIA_SENDER_ADDRESS_1=<partisia address>
PARTISIA_SENDER_KEY_2=...
PARTISIA_SENDER_ADDRESS_2=...
PARTISIA_SENDER_KEY_3=...
PARTISIA_SENDER_ADDRESS_3=...

# ── Share file encryption ─────────────────────────────────────────────────
SHARE_FILE_KEY_1=party1-secret-passphrase
SHARE_FILE_KEY_2=party2-secret-passphrase
SHARE_FILE_KEY_3=party3-secret-passphrase

# ── Gateway ───────────────────────────────────────────────────────────────
JWT_SECRET=change-me-in-production
PORT=8080

# ── Service addresses ─────────────────────────────────────────────────────
COORDINATOR_ADDR=localhost:50051
POLICY_ADDR=localhost:50052
PARTY_1_ADDR=localhost:50060
PARTY_2_ADDR=localhost:50061
PARTY_3_ADDR=localhost:50062
```

---

## 13. Running Everything Locally

### Option A — Rust backend (used by frontend)

```bash
# Terminal 1: Start the Rust backend
cargo run -p kosh-backend
# Listens on :8080, orchestrates party daemons internally

# Terminal 2: Start the frontend
cd frontend/KoshSignerUsingPartisiaZK/client
npm install
npm run dev
# Open http://localhost:5173
```

### Option B — Full microservices stack

```bash
# Step 1: Build all Rust services
cargo build --release \
  -p kosh-party -p kosh-pqc -p kosh-keystore -p kosh-chain-relay

# Step 2: Start Go services
cd services/kosh-coordinator && PORT=50051 go run ./cmd/coordinator &
cd services/kosh-policy      && PORT=50052 POLICY_FILE= go run ./cmd/policy &

# Step 3: Start PQC services (one per party)
PQC_KEY_FILE=/tmp/pqc1.json PORT=50080 ./target/release/kosh-pqc &
PQC_KEY_FILE=/tmp/pqc2.json PORT=50081 ./target/release/kosh-pqc &
PQC_KEY_FILE=/tmp/pqc3.json PORT=50082 ./target/release/kosh-pqc &

# Step 4: Start party daemons
PARTY_INDEX=1 PORT=50060 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &
PARTY_INDEX=2 PORT=50061 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &
PARTY_INDEX=3 PORT=50062 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &

# Step 5: Start chain relay
PARTISIA_NODE_URLS=https://node1.testnet.partisiablockchain.com \
  PORT=50053 ./target/release/kosh-chain-relay &

# Step 6: Start gateway + monitor
cd services/kosh-gateway && PORT=8080 \
  COORDINATOR_ADDR=localhost:50051 POLICY_ADDR=localhost:50052 \
  PARTY_1_ADDR=localhost:50060 PARTY_2_ADDR=localhost:50061 \
  PARTY_3_ADDR=localhost:50062 JWT_SECRET=dev go run ./cmd/gateway &

cd services/kosh-monitor && PORT=9090 go run ./cmd/monitor &
```

### Option C — Docker Compose

```bash
cp deploy/.env.example deploy/.env
# Fill in your Partisia keys in deploy/.env
docker-compose -f deploy/docker-compose.yml up
```

### Quick API test (Option B / C)

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/token \
  -H "X-API-Key: mykey" | jq -r .token)

# Create distributed key (DKG)
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id": 1, "num_parties": 3, "threshold": 2}'

# Sign a message
curl -X POST http://localhost:8080/api/v1/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": 1,
    "message_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "tx_tag": "transfer",
    "signing_subset": [1, 2]
  }'

# Check Prometheus metrics
curl http://localhost:9090/metrics | grep kosh_
```

---

## 14. Test Results

### All tests — 27/27 passing

```
Service               Tests   Result   What is tested
──────────────────────────────────────────────────────────────────────
kosh-coordinator      6       ✅ PASS  Post/Read/Watch(immediate+future)/Clear/List gRPC
kosh-policy           5       ✅ PASS  AddPolicy/ListPolicies/Validate/RemovePolicy gRPC
cross-service         1       ✅ PASS  Coordinator + policy running together
kosh-gateway          4       ✅ PASS  Health, JWT auth, Policy CRUD, 3-party DKG REST→gRPC
kosh-monitor          4       ✅ PASS  Ready, Health JSON, Prometheus /metrics, metric types
kosh-pqc              5       ✅ PASS  GetIdentity, KEM round-trip, AES-GCM, ML-DSA, tamper
kosh-party            2       ✅ PASS  GetStatus, 3-party DKG → all 3 compute same combined_pk
──────────────────────────────────────────────────────────────────────
TOTAL                 27      ✅ ALL PASS
```

### Key proof: 3-party DKG produces identical public key

```
Party 1 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
Party 2 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
Party 3 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
```

All three parties independently computed the same `P = P₁ + P₂ + P₃`.

### Run all tests

```bash
# Go tests
cd services/integration-test && go test ./... -timeout 60s
cd services/kosh-gateway     && go test -timeout 300s
cd services/kosh-monitor     && go test -timeout 60s

# Rust tests
cargo test -p kosh-pqc   --test grpc_test
cargo test -p kosh-party --test party_grpc_test

# TypeScript integration tests (needs Partisia testnet)
cd client
npx tsx src/test-gg20-sign.ts   # Full DKG + GG20 on testnet (~3-5 min)
npx tsx src/test-policy.ts      # 20 assertions
npx tsx src/test-pqc.ts         # 28 assertions
```

---

## 15. Live Contract Addresses

| Contract | Address |
|----------|---------|
| kosh-zk-signer (current) | `031fb3ede8b7274ffb94ef250ba3747e49b2706d12` |
| kosh-zk-signer (previous) | `03a1e8aba3ba45c1e42d01f688768436cb2b572de0` |

**Explorer**: `https://browser.testnet.partisiablockchain.com/contracts/<ADDRESS>`

**Deployer**: `002ee35cde26782f255b9550ea1ac53faeac2c71cd`

**Proven Ethereum signing** — private key never existed:

| Item | Value |
|------|-------|
| Sepolia Tx | `0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41` |
| Block | 10432151 |
| From (EVM) | `0x46fe38ef06876C3d76E03D1e5991eD28FF2714ad` |

---

## 16. Security Properties

| Property | Status | Mechanism |
|----------|--------|-----------|
| Private key never assembled | ✅ | DKG additive shares — s = s₁+s₂+s₃ never computed |
| Nonce never assembled | ✅ | GG20 — k_i are additive shares, k⁻¹ never exists as a number |
| Rogue key attack prevented | ✅ | DKG commit-reveal + Schnorr proof of knowledge of sᵢ |
| Sub-share integrity | ✅ | Feldman VSS: fⱼ(i)·G == Cⱼ₀ + i·Cⱼ₁ verified before combining |
| Gamma bias prevented | ✅ | Commit-reveal for Γᵢ before delta submit |
| Delta manipulation prevented | ✅ | Commit-reveal for δᵢ |
| Partial sig manipulation | ✅ | Commit-reveal for σᵢ |
| Secret memory cleared | ✅ | Rust `ZeroizeOnDrop` on all key material structs |
| Secret isolation | ✅ | Secrets never cross service boundaries (stay in kosh-keystore/kosh-pqc) |
| ZK share security | ✅ | sᵢ split into two 128-bit halves, each encrypted per ZK node |
| Post-quantum gating | ✅ | ML-DSA-65 + ML-KEM-768 approval required before GG20 |
| EIP-2 low-s compliance | ✅ | Contract normalizes σ if σ > N/2 |
| Policy enforcement | ✅ | Mandatory parties + min threshold checked before fan-out |
| JWT authentication | ✅ | HS256 tokens required on all gateway routes |
| 2048-bit Paillier | ✅ | Upgraded from 1024-bit in original TypeScript |

### Known gaps (pre-production)

| Priority | Issue | Fix |
|----------|-------|-----|
| Critical | No ZK range proofs in MtA | Add Πenc + Πaff-g per GG20 paper, or use CGGMP21 |
| Critical | Keystore→Party wire not complete | Wire kosh-keystore gRPC to kosh-party (placeholder x_i used in tests) |
| Medium | Chain relay not called from party | Wire kosh-chain-relay into party phase.rs (stubs present) |
| Medium | No identifiable abort | Add per-submission ZK proofs |
| Low | Single coordinator | Add clustering for high availability |
