# Kosh ZK Signer

Threshold ECDSA wallet on Partisia blockchain. A secp256k1 private key **never exists anywhere** — three parties each hold a fragment and sign Ethereum transactions together using GG20 multi-party computation.

**Live proof:** Sepolia `0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41` — signed by threshold MPC, private key never assembled.

---

## Repository Structure

```
KoshSignerUsingPartisiaZK/
│
├── frontend/KoshSignerUsingPartisiaZK/client/   ← BROWSER UI (Vite + TypeScript)
│   └── src/main.ts                                3-step UI: Auth → Key → Sign
│       Uses kosh-evm-client from client/ below
│
├── client/                                       ← npm LIBRARY (kosh-evm-client)
│   └── src/                                        TypeScript SDK used by the UI
│       ├── party.ts                                GG20 + DKG party logic
│       ├── chain-utils.ts                          Partisia RPC + tx submission
│       ├── paillier.ts / mta.ts                    Paillier MtA crypto
│       └── test-gg20-sign.ts                       integration tests
│
├── backend/                                      ← RUST BACKEND (kosh-backend)
│   └── src/                                        Axum REST server on :8080
│       ├── api/routes.rs                           all /api/v1/... endpoints
│       ├── orchestrator.rs                         drives 3 party.ts processes
│       └── passkeys.rs                             WebAuthn passkey auth
│
├── services/                                     ← NEW MICROSERVICES (Go + Rust)
│   ├── kosh-gateway/      Go  :8080              REST API + JWT
│   ├── kosh-coordinator/  Go  :50051             gRPC bulletin board
│   ├── kosh-policy/       Go  :50052             signing policies
│   ├── kosh-monitor/      Go  :9090              Prometheus + health
│   ├── kosh-party/        Rust :50060-62         DKG + GG20 + MtA
│   ├── kosh-keystore/     Rust :50070-72         AES-256-GCM share storage
│   ├── kosh-pqc/          Rust :50080-82         ML-KEM-768 + ML-DSA-65
│   └── kosh-chain-relay/  Rust :50053            Partisia tx queue
│
├── contracts/                                    ← PARTISIA WASM (on-chain)
│   ├── kosh-zk-signer/                            main contract (DKG+GG20+PQC)
│   ├── kosh-vault/                                asset vault
│   └── kosh-account-registry/                     address registry
│
└── deploy/docker-compose.yml                     ← Docker: all services together
```

> **Which backend?** The `backend/` (Rust/Axum) is what the **frontend uses today** — it
> orchestrates DKG+GG20 internally. The `services/` microservices are the new production
> architecture where each concern is a separate gRPC service.

---

## Table of Contents

1. [What It Does](#1-what-it-does)
2. [System Overview Diagram](#2-system-overview-diagram)
3. [How Everything Connects](#3-how-everything-connects)
4. [DKG — How the Key Is Born](#4-dkg--how-the-key-is-born)
5. [GG20 — How Signing Works](#5-gg20--how-signing-works)
6. [PQC Post-Quantum Layer](#6-pqc-post-quantum-layer)
7. [Microservices Architecture](#7-microservices-architecture)
8. [Frontend — UI Flow](#8-frontend--ui-flow)
9. [Smart Contracts](#9-smart-contracts)
10. [API Endpoints](#10-api-endpoints)
11. [Contract Actions](#11-contract-actions)
12. [Setup & Running](#12-setup--running)
13. [Test Results — 27/27 Passing](#13-test-results--2727-passing)
14. [Live Addresses](#14-live-addresses)
15. [Security](#15-security)

---

## 1. What It Does

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  User opens browser → signs Ethereum transaction                │
│                                                                 │
│  HOW:                                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                     │
│  │  Party 1 │  │  Party 2 │  │  Party 3 │  ← each holds sᵢ   │
│  │  s₁      │  │  s₂      │  │  s₃      │    never the full   │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘    private key      │
│        │              │              │                          │
│        └──────────────┴──────────────┘                          │
│                       │ GG20 protocol on Partisia               │
│                       ▼                                         │
│              (r, σ) ECDSA signature                             │
│                       │                                         │
│                       ▼ broadcast to Ethereum                   │
│              Transaction confirmed ✓                            │
│                                                                 │
│  The private key s = s₁+s₂+s₃ is never computed anywhere.     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. System Overview Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║                          USER'S BROWSER                                  ║
║                                                                          ║
║  ┌────────────────────────────────────────────────────────────────────┐  ║
║  │               Kosh Frontend (Vite + TypeScript)                    │  ║
║  │         frontend/KoshSignerUsingPartisiaZK/client/                 │  ║
║  │                                                                    │  ║
║  │   ┌──────────────┐  ┌─────────────────┐  ┌───────────────────┐   │  ║
║  │   │  STEP 1      │  │   STEP 2        │  │   STEP 3          │   │  ║
║  │   │  Auth        │  │   Key           │  │   Sign & Send     │   │  ║
║  │   │              │  │                 │  │                   │   │  ║
║  │   │  WebAuthn    │  │  Load Key       │  │  Build EVM tx     │   │  ║
║  │   │  Passkey     │  │  Create Key     │  │  Sign (GG20)      │   │  ║
║  │   │  Register    │  │  (→ DKG)        │  │  Broadcast        │   │  ║
║  │   │  Sign In     │  │  Show EVM addr  │  │  to Sepolia       │   │  ║
║  │   └──────┬───────┘  └────────┬────────┘  └─────────┬─────────┘   │  ║
║  │          │                   │                      │             │  ║
║  └──────────┼───────────────────┼──────────────────────┼─────────────┘  ║
╚═════════════╪═══════════════════╪══════════════════════╪════════════════╝
              │                   │                      │
              │  fetch() REST calls to http://127.0.0.1:8080              
              │                   │                      │
╔═════════════╪═══════════════════╪══════════════════════╪════════════════╗
║             ▼                   ▼                      ▼                ║
║  ┌──────────────────────────────────────────────────────────────────┐   ║
║  │              kosh-backend  (Rust / Axum)  :8080                  │   ║
║  │              backend/src/                                        │   ║
║  │                                                                  │   ║
║  │  /api/v1/health                 → alive check                   │   ║
║  │  /api/v1/runtime/preflight      → check chain + key ready        │   ║
║  │  /api/v1/runtime/active         → get current key/contract       │   ║
║  │  /api/v1/passkeys/register/*    → WebAuthn registration          │   ║
║  │  /api/v1/passkeys/auth/*        → WebAuthn authentication        │   ║
║  │  /api/v1/passkeys/create-key    → trigger DKG (3 parties)        │   ║
║  │  /api/v1/passkeys/reuse-sign    → trigger GG20 signing           │   ║
║  │  /api/v1/threshold/key-status   → key phase on Partisia          │   ║
║  │  /api/v1/threshold/task-sig..   → retrieve final signature        │   ║
║  │  /api/v1/jobs/:id/events        → SSE live phase stream           │   ║
║  │                                                                  │   ║
║  │  CORS: allows localhost:5173 and 127.0.0.1:5173 by default       │   ║
║  └───────────────────┬────────────────────────┬─────────────────────┘   ║
║                      │ orchestrates            │ HTTP Partisia RPC       ║
║                      │                         │                         ║
║        ┌─────────────┴──────────────┐          │                         ║
║        │ Party daemons (internal)   │          ▼                         ║
║        │  party.ts × 3 processes    │  ┌───────────────────────────┐    ║
║        │  DKG + GG20 + MtA logic    │  │   Partisia Testnet        │    ║
║        └─────────────┬──────────────┘  │   kosh-zk-signer (WASM)   │    ║
║                      │                 │                           │    ║
║                      └────────────────►│  DKG actions (0x20–0x24)  │    ║
║                                        │  GG20 actions (0x45–0x53) │    ║
║                                        │  PQC actions (0x72–0x77)  │    ║
║                                        │  ZK nodes store encrypted │    ║
║                                        │  key share fragments      │    ║
║                                        └───────────────────────────┘    ║
║                                                                          ║
║  ─────────────── NEW MICROSERVICES LAYER (Go + Rust) ──────────────────  ║
║                                                                          ║
║  ┌─────────────────┐  ┌───────────────────┐  ┌─────────────────────┐   ║
║  │ kosh-gateway    │  │ kosh-coordinator  │  │ kosh-policy         │   ║
║  │ Go :8080        │  │ Go :50051         │  │ Go :50052           │   ║
║  │                 │  │                   │  │                     │   ║
║  │ JWT auth        │  │ Bulletin board    │  │ Policy CRUD         │   ║
║  │ REST → gRPC     │  │ gRPC Watch stream │  │ Validate signing    │   ║
║  └────────┬────────┘  └─────────┬─────────┘  └─────────────────────┘   ║
║           │                     │ Watch streams                          ║
║           │         ┌───────────┼────────────┐                          ║
║           │         ▼           ▼            ▼                          ║
║           │  ┌───────────┐ ┌──────────┐ ┌──────────┐                   ║
║           │  │ kosh-party│ │kosh-party│ │kosh-party│  Rust             ║
║           │  │ :50060    │ │ :50061   │ │ :50062   │                   ║
║           │  │ DKG+GG20  │ │ DKG+GG20 │ │ DKG+GG20 │                   ║
║           │  │ Paillier  │ │ Paillier │ │ Paillier │                   ║
║           │  └─┬──┬──────┘ └─┬──┬────┘ └─┬──┬─────┘                   ║
║           │    │  │           │  │         │  │                         ║
║           │    ▼  ▼           ▼  ▼         ▼  ▼                         ║
║           │  ┌──┐┌──┐     ┌──┐┌──┐    ┌──┐┌──┐                        ║
║           │  │KS││PQ│     │KS││PQ│    │KS││PQ│  KS=keystore PQ=pqc    ║
║           │  └──┘└──┘     └──┘└──┘    └──┘└──┘  Rust (secrets here)   ║
║           │                                                              ║
║           │  ┌───────────────────────┐  ┌───────────────────────────┐   ║
║           └─►│ kosh-chain-relay      │  │ kosh-monitor Go :9090     │   ║
║              │ Rust :50053           │  │ /metrics /health /ready   │   ║
║              │ Tx queue + k256 sign  │  └───────────────────────────┘   ║
║              └───────────┬───────────┘                                   ║
║                          │ HTTPS                                          ║
║                          ▼ Partisia Blockchain                            ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## 3. How Everything Connects

### Frontend → Backend (the main connection)

```
frontend/KoshSignerUsingPartisiaZK/client/src/main.ts
  │
  │  const defaultApiBaseUrl = "http://127.0.0.1:8080"
  │  (user can change this in the UI input field)
  │
  ├─► GET  /api/v1/health
  │         └─ checks backend is reachable before showing UI
  │
  ├─► GET  /api/v1/runtime/preflight?contract_address=...&key_id=...
  │         └─ checks: chain reachable? key exists on-chain? gas ok?
  │
  ├─► GET  /api/v1/runtime/active
  │         └─ loads saved contract + key state from backend
  │
  ├─► POST /api/v1/passkeys/register/start   ┐
  ├─► POST /api/v1/passkeys/register/finish  ├─ WebAuthn passkey flow
  ├─► POST /api/v1/passkeys/auth/start       │  (browser biometrics)
  ├─► POST /api/v1/passkeys/auth/finish      ┘
  │
  ├─► GET  /api/v1/passkeys/me
  │         └─ gets logged-in passkey account + linked keys
  │
  ├─► POST /api/v1/passkeys/create-key
  │         └─ triggers DKG across all 3 party processes
  │            returns job_id → frontend polls for progress
  │
  ├─► POST /api/v1/passkeys/reuse-sign
  │         └─ triggers GG20 signing session
  │            SSE stream pushes phase updates to frontend
  │
  ├─► GET  /api/v1/jobs/:id
  │         └─ poll job status (running / completed / failed)
  │
  ├─► GET  /api/v1/threshold/key-status
  │         └─ reads key phase directly from Partisia blockchain
  │
  └─► GET  /api/v1/threshold/task-signature
            └─ fetches final (r, σ) signature from Partisia
```

### Backend → Partisia chain

```
kosh-backend (Rust) orchestrates 3 party daemons:

  Party 1 process                    Partisia chain
       │    Party 2 process               │
       │         │    Party 3 process      │
       │         │         │              │
       ├─────────┴─────────┤              │
       │  DKG: each party  │──────────────►  0x20 create_key
       │  generates sᵢ     │──────────────►  0x21 commit × 3
       │  exchanges commits │◄─────────────   confirm
       │  verifies Feldman  │──────────────►  0x22 reveal × 3
       │                   │──────────────►  0x23 finalize
       │                   │──────────────►  0x10 zk_shares × 6
       │                   │──────────────►  0x24 complete
       │                   │◄─────────────   key ready
       │                   │
       │  GG20: generate   │──────────────►  0x50 start_signing
       │  kᵢ, γᵢ, MtA      │──────────────►  0x45 delta × n
       │  exchange deltas  │──────────────►  0x46 gamma_point × n
       │                   │──────────────►  0x47 finalize_r
       │                   │◄─────────────   r = R.x mod N
       │  partial sigs     │──────────────►  0x51 commit_sig × n
       │                   │──────────────►  0x52 submit_sig × n
       │                   │──────────────►  0x53 finalize_sig
       │                   │◄─────────────   (r,σ) stored on-chain
```

---

## 4. DKG — How the Key Is Born

```
┌────────────────────────────────────────────────────────────────────┐
│                  COMMIT-REVEAL (prevents rogue key attack)          │
│                                                                    │
│  Each party i independently:                                       │
│                                                                    │
│    sᵢ  = random_scalar()         ← secret constant term           │
│    aᵢ  = random_scalar()         ← secret slope term              │
│    Cᵢ₀ = sᵢ · G                  ← public share commitment        │
│    Cᵢ₁ = aᵢ · G                  ← public slope commitment        │
│                                                                    │
│    Schnorr proof:                                                  │
│      r   = random_scalar()                                         │
│      R   = r · G                                                   │
│      e   = SHA256(G ‖ Cᵢ₀ ‖ R ‖ i)                               │
│      z   = r + e·sᵢ  mod N                                        │
│    → proves knowledge of sᵢ without revealing it                  │
│                                                                    │
│    commit_hash = SHA256(Cᵢ₀)                                       │
│                                                                    │
│  ROUND 1: All parties POST commit_hash to Coordinator              │
│           All parties WATCH other parties' commit_hash             │
│           [nobody can see Pᵢ yet — only its hash]                 │
│                                                                    │
│  ROUND 2: All parties POST (Cᵢ₀, Cᵢ₁, R, z)                      │
│           Verify: z·G == R + e·Cᵢ₀   ← Schnorr verify            │
│           Verify: hash == SHA256(Cᵢ₀)  ← commit matches           │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│              FELDMAN VSS — SUBSHARE EXCHANGE                        │
│                                                                    │
│  Polynomial for party i:  fᵢ(x) = sᵢ + aᵢ·x                     │
│                                                                    │
│  Party i computes sub-share for party j:                           │
│    fᵢ(j) = sᵢ + aᵢ·j                                              │
│                                                                    │
│  Party i → POST fᵢ(j) for every j ≠ i  (via Coordinator)         │
│  Party i ← WATCH fⱼ(i) from every j ≠ i                          │
│                                                                    │
│  VERIFY each received sub-share:                                   │
│    fⱼ(i)·G  ==  Cⱼ₀ + i·Cⱼ₁                                      │
│    [Feldman check: algebraically proves fⱼ(i) is on polynomial]   │
│                                                                    │
│  COMBINE: xᵢ = Σⱼ fⱼ(i)   ← final Shamir share for party i      │
│                                                                    │
│  COMBINED PUBLIC KEY:                                              │
│    P = Cᵢ₀ + C₂₀ + C₃₀ = (s₁+s₂+s₃)·G                           │
│    EVM address = keccak256(P.x ‖ P.y)[12:]                        │
└────────────────────────────────────────────────────────────────────┘

         ON-CHAIN SEQUENCE (via chain-relay)
         ──────────────────────────────────
   0x20  dkg_create_key(key_id, num_parties)
   0x21  dkg_commit(key_id, party, SHA256(Cᵢ₀))     ← × 3 parties
   0x22  dkg_reveal(key_id, party, Cᵢ₀)              ← × 3 parties
   0x23  dkg_finalize(key_id)
         Contract: P = P₁ + P₂ + P₃  [EC point addition on-chain]
   0x10  submit_key_share(ZK encrypted sᵢ halves)    ← × 6 (2 per party)
   0x24  dkg_complete_keygen(key_id)
         → Key stored on Partisia, EVM address derivable
```

---

## 5. GG20 — How Signing Works

```
┌────────────────────────────────────────────────────────────────────┐
│                    ROUND 1 — NONCE GENERATION                       │
│                                                                    │
│  Each party i:                                                     │
│    kᵢ   = HMAC-DRBG(xᵢ, msg_hash, session_id)                    │
│             └─ deterministic: same key+msg → same kᵢ              │
│    γᵢ   = random_scalar()           ← masking value               │
│    Γᵢ   = γᵢ · G                    ← gamma point (public)        │
│                                                                    │
│  Commit-reveal Γᵢ (prevents last-party bias):                     │
│    nonce  = random_bytes(32)                                       │
│    commit = SHA256(Γᵢ ‖ nonce) → POST to Coordinator             │
│    [wait for all parties' commits]                                 │
│    reveal = (Γᵢ, nonce)         → POST to Coordinator             │
│    [verify: SHA256(Γᵢ ‖ nonce) == committed hash]                 │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│         MtA — MULTIPLICATIVE TO ADDITIVE (Paillier)                │
│         Runs in parallel for ALL pairs via FuturesUnordered        │
│                                                                    │
│  For each pair (i, j):                                             │
│                                                                    │
│  k·x cross-term:                                                   │
│  ┌─────────────────────────────────────────────────────────┐      │
│  │ Party i (initiator):                                    │      │
│  │   βᵢⱼ = random masking scalar                           │      │
│  │   c   = Enc_j(kᵢ·xᵢ - βᵢⱼ)  ← Paillier encrypt        │      │
│  │   POST c → Coordinator                                  │      │
│  │                                                         │      │
│  │ Party j (responder):                                    │      │
│  │   receives c, adds xⱼ homomorphically + masks βⱼᵢ      │      │
│  │   responds with αⱼᵢ                                    │      │
│  │                                                         │      │
│  │ Result: αᵢⱼ + βᵢⱼ = kᵢ · xⱼ  (additive shares)       │      │
│  └─────────────────────────────────────────────────────────┘      │
│                                                                    │
│  Same protocol for k·γ cross-term → αkγ_ij + βkγ_ij = kᵢ·γⱼ    │
│                                                                    │
│  Uses 2048-bit safe-prime Paillier                                 │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                    ROUND 2 — AGGREGATION                            │
│                                                                    │
│  Each party i computes:                                            │
│                                                                    │
│    δᵢ = kᵢ·γᵢ + Σⱼ (αkγ_ij + βkγ_ji)                            │
│         └──────── share of k·γ  (safe to reveal)                  │
│                                                                    │
│    σᵢ = kᵢ·xᵢ + Σⱼ (αkx_ij + βkx_ji)                            │
│         └──────── share of k·s  (NEVER revealed to anyone)        │
│                                                                    │
│  Commit-reveal δᵢ (same pattern as Γᵢ)                            │
│                                                                    │
│  On-chain:                                                         │
│    0x45  submit_delta(δᵢ)        ← × n parties                    │
│    0x46  submit_gamma_point(Γᵢ)  ← × n parties                    │
│    0x47  gg20_finalize_r()                                         │
│                                                                    │
│  Contract computes:                                                │
│    δ = Σδᵢ   = k·γ                                                │
│    Γ = ΣΓᵢ   = γ·G                                                │
│    R = δ⁻¹·Γ = (k·γ)⁻¹·(γ·G) = k⁻¹·γ⁻¹·γ·G = k⁻¹·G  ← magic  │
│    r = R.x mod N                                                   │
│                                                                    │
│  γ CANCELS OUT — nobody ever computed k or k⁻¹                    │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                     PARTIAL SIGNATURES                              │
│                                                                    │
│  Each party i:                                                     │
│    m  = message_hash as scalar                                     │
│    sᵢ = kᵢ⁻¹ · (m + r · σᵢ)  mod N                              │
│         └── partial sig using ephemeral kᵢ and secret σᵢ          │
│                                                                    │
│  Commit-reveal sᵢ:                                                 │
│    0x51  commit_partial_sig(SHA256(sᵢ))  ← × n parties            │
│    0x52  submit_partial_sig(sᵢ)          ← × n parties            │
│    0x53  finalize_gg20_sig()                                       │
│                                                                    │
│  Contract:                                                         │
│    σ = Σsᵢ               ← sum of partial sigs                   │
│    if σ > N/2: σ = N-σ   ← EIP-2 low-s normalization             │
│    verify ECDSA(P, m, r, σ) on-chain  ✓                           │
│    store (r, σ) on Partisia blockchain                             │
│                                                                    │
│  Frontend fetches (r, σ) → broadcasts to Ethereum Sepolia         │
└────────────────────────────────────────────────────────────────────┘
```

---

## 6. PQC Post-Quantum Layer

```
┌────────────────────────────────────────────────────────────────────┐
│              kosh-pqc service (Rust :50080)                        │
│                                                                    │
│  On first start → generate and persist:                            │
│    ML-KEM-768:  (kem_dk, kem_ek)  from 64-byte seed               │
│    ML-DSA-65:   (dsa_sk, dsa_vk)  from 32-byte seed               │
│    File: PQC_KEY_FILE=/data/pqc-identity.json                     │
│                                                                    │
│  GetIdentity() → (kyber_pk_b64, dilithium_pk_b64)  ← public only │
│  Encapsulate(recipient_pk) → (ciphertext, shared_secret)           │
│  Decapsulate(ciphertext)   → shared_secret                         │
│  Sign(message)             → ML-DSA-65 signature (3309 bytes)      │
│  Verify(pk, message, sig)  → bool                                  │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│              PQC APPROVAL FLOW (before GG20)                       │
│                                                                    │
│  Register once per key:                                            │
│    0x72  register_party_address(key_id, party, partisia_addr)      │
│    0x73  register_dilithium_pubkey(key_id, party, pk)              │
│    0x74  register_kyber_pubkey(key_id, party, pk)                  │
│                                                                    │
│  Before each signing session:                                      │
│    0x75  start_pqc_approval_session(key_id, task_id, subset)       │
│                                                                    │
│  Each party in signing subset:                                     │
│    approval_hash = SHA256(                                         │
│      "KOSH_PQC_APPROVAL_V1" ‖ key_id ‖ task_id ‖ msg_hash ‖      │
│      tx_tag ‖ party_index ‖ signing_subset ‖ challenge            │
│    )                                                               │
│    sig = ML-DSA-65.sign(approval_hash)                             │
│    ct  = ML-KEM-768.encapsulate(recipient_kyber_pk)                │
│    0x76  submit_pqc_approval(key_id, task_id, sig, ct)             │
│                                                                    │
│  0x77  finalize_pqc_approval(key_id, task_id)                      │
│        Contract verifies all Dilithium signatures on-chain         │
│        → GG20 signing unblocked                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 7. Microservices Architecture

The original TypeScript monolith (1339-line `party.ts`) is replaced by isolated services:

```
┌────────────────────────────────────────────────────────────────────┐
│  PROBLEM WITH MONOLITH          │  SOLUTION WITH MICROSERVICES     │
│                                 │                                  │
│  Crash = restart everything     │  Crash one → others keep going   │
│  Secrets + routing in 1 process │  Secrets isolated in keystore    │
│  No external API                │  REST API → any dApp can call    │
│  30s polling between parties    │  gRPC Watch streams = instant    │
│  All parties on 1 machine       │  Each party runs independently   │
└────────────────────────────────────────────────────────────────────┘

Service             Lang    Port      Secrets held          Role
─────────────────────────────────────────────────────────────────────
kosh-gateway        Go      8080      None          REST API + JWT auth
kosh-coordinator    Go      50051     None          Bulletin board + Watch
kosh-policy         Go      50052     None          Signing policy CRUD
kosh-monitor        Go      9090      None          Prometheus + health
kosh-party          Rust    50060-62  kᵢ,γᵢ (temp) DKG + GG20 + MtA
kosh-keystore       Rust    50070-72  xᵢ (Shamir)  AES-256-GCM shares
kosh-pqc            Rust    50080-82  KEM+DSA keys  ML-KEM + ML-DSA
kosh-chain-relay    Rust    50053     Partisia key  Tx queue + k256 sign

gRPC Protocol files (services/proto/):
  bulletin_board.proto  → Post, Read, Watch(stream), Clear, List
  party.proto           → StartDkg(stream), StartSign(stream), GetStatus
  keystore.proto        → GenerateShare, LoadShare, GetShareHalves
  pqc.proto             → GetIdentity, Encapsulate, Decapsulate, Sign, Verify
  chain_relay.proto     → Submit(stream), GetContractState
  policy.proto          → AddPolicy, RemovePolicy, ListPolicies, Validate
```

---

## 8. Frontend — UI Flow

```
frontend/KoshSignerUsingPartisiaZK/client/src/main.ts  (959 lines)

App renders 3 steps:

┌─────────────────────────────────────────────────────────────────┐
│                    KOSH THRESHOLD SIGNER                         │
│                                                                 │
│  Contract: 031fb3…   Key: ✓ Loaded   Auth: ✓ alice             │
│                                                                 │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║  STEP 1 — Authentication                                ║   │
│  ║                                                         ║   │
│  ║  [ Sign in with Passkey ]  [ Register Passkey ]         ║   │
│  ║                                                         ║   │
│  ║  Linked Keys:                                           ║   │
│  ║  [ Key #42 on 031fb3... ]  [ Key #1 on 03abc... ]      ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
│                                                                 │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║  Your Wallet                                            ║   │
│  ║                                                         ║   │
│  ║  Derived EVM Address:                                   ║   │
│  ║  ┌──────────────────────────────────────────────────┐  ║   │
│  ║  │  0x46fe38ef06876C3d76E03D1e5991eD28FF2714ad      │  ║   │
│  ║  └──────────────────────────────────────────────────┘  ║   │
│  ║  [ Copy Address ]  [ View on Etherscan ↗ ]             ║   │
│  ║                                                         ║   │
│  ║  Combined Public Key (P = P₁ + P₂ + P₃):              ║   │
│  ║  02abc1234...                                           ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
│                                                                 │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║  STEP 2 — Key                                           ║   │
│  ║                                                         ║   │
│  ║  Contract Address: [031fb3ede8b7274f...]                ║   │
│  ║  Backend URL:      [http://127.0.0.1:8080]              ║   │
│  ║                                                         ║   │
│  ║  [ Load Key ]  [ Create New Key ]                      ║   │
│  ║                                                         ║   │
│  ║  DKG Key Loaded ✓                                      ║   │
│  ║  EVM: 0x46fe38ef...   Key ID: 42                       ║   │
│  ║  Phase: Complete   Signatures: 3, 7, 12                ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
│                                                                 │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║  STEP 3 — Send                                          ║   │
│  ║                                                         ║   │
│  ║  Recipient (EVM): [0x1234...]                           ║   │
│  ║  Amount (wei):    [1000000000000000]                    ║   │
│  ║                                                         ║   │
│  ║  [ Build Transaction ]  [ Sign & Send ]                 ║   │
│  ║                                                         ║   │
│  ║  ✓ Transaction Sent                                     ║   │
│  ║  0x09ec739d1e7cf9a9...                                  ║   │
│  ║  [ View on Sepolia Etherscan ↗ ]                        ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
└─────────────────────────────────────────────────────────────────┘

SSE live phase stream (while signing):
  ⏳ DKG_START → DKG_COMMITTED → DKG_SUBSHARES → DKG_FINALIZED
  ⏳ GG20_ROUND1 → MTA_COMPLETE → GG20_ROUND2
  ⏳ PARTIAL_SIGS → ✓ SIGN_COMPLETE
```

### Running the frontend

```bash
# Terminal 1: Rust backend (required)
cargo run -p kosh-backend
# → listening on http://127.0.0.1:8080
# → CORS: allows localhost:5173 by default

# Terminal 2: Frontend dev server
cd frontend/KoshSignerUsingPartisiaZK/client
npm install
npm run dev
# → http://localhost:5173

# Or build for production:
npm run build
# → dist/ (serve with any static host)
```

Frontend connects to backend at `http://127.0.0.1:8080` (configurable in the UI).

---

## 9. Smart Contracts

All contracts are Rust compiled to WASM, deployed to Partisia. Not modified after deploy.

```
contracts/
├── kosh-zk-signer/         Main contract — DKG, GG20, PQC, policy
├── kosh-vault/             Asset vault — requires signer approval
└── kosh-account-registry/  Maps addresses → signer contracts
```

**kosh-zk-signer source files:**

| File | Purpose |
|------|---------|
| `lib.rs` | All 44+ action handlers |
| `signing_state.rs` | `KeyEntry`, `SigningTask`, `Phase` state types |
| `dkg.rs` | Commit/reveal, Schnorr verify, k256 EC point addition |
| `shamir.rs` | Lagrange interpolation (legacy path) |
| `off_chain.rs` | ZK node callbacks on encrypted share confirmation |
| `zk_compute.rs` | Partisia ZK framework integration |

---

## 10. API Endpoints

### Rust backend (port 8080) — used by frontend

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Liveness check → `{status:"ok"}` |
| GET | `/api/v1/runtime/preflight` | Check chain + key + gas readiness |
| GET | `/api/v1/runtime/active` | Current runtime state |
| POST | `/api/v1/passkeys/register/start` | WebAuthn register — start |
| POST | `/api/v1/passkeys/register/finish` | WebAuthn register — finish |
| POST | `/api/v1/passkeys/auth/start` | WebAuthn auth — start |
| POST | `/api/v1/passkeys/auth/finish` | WebAuthn auth — finish |
| GET | `/api/v1/passkeys/me` | Current passkey account + linked keys |
| POST | `/api/v1/passkeys/select-key` | Select active key |
| POST | `/api/v1/passkeys/link-key` | Link key to passkey account |
| POST | `/api/v1/passkeys/create-key` | **Trigger DKG** — create distributed key |
| POST | `/api/v1/passkeys/reuse-sign` | **Trigger GG20** — sign transaction |
| GET | `/api/v1/jobs/:id` | Job status (running/completed/failed) |
| GET | `/api/v1/jobs/:id/events` | SSE live phase stream |
| GET | `/api/v1/threshold/key-status` | Key phase on Partisia |
| GET | `/api/v1/threshold/task-signature` | Retrieve final (r,σ) |

### Go gateway (port 8080) — microservices path

All routes require `Authorization: Bearer <jwt>` except `/api/v1/health` and `/api/v1/token`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/token` | Issue JWT (`X-API-Key` header required) |
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/keys` | Trigger DKG — create key |
| GET | `/api/v1/keys/{id}` | Key status |
| POST | `/api/v1/sign` | Trigger GG20 — sign message hash |
| GET | `/api/v1/sign/{id}` | Sign session status |
| POST | `/api/v1/policies` | Add signing policy |
| GET | `/api/v1/policies` | List policies |
| DELETE | `/api/v1/policies/{id}` | Remove policy |

### Monitor (port 9090)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/metrics` | Prometheus metrics (9 custom kosh_* metrics) |
| GET | `/health` | JSON map of all service addresses |
| GET | `/ready` | Readiness probe → `"ready"` |

---

## 11. Contract Actions

### DKG (key creation)

| Shortname | Action | Effect |
|-----------|--------|--------|
| `0x20` | `dkg_create_key` | Open key slot, phase → Committing |
| `0x21` | `dkg_commit` | Store SHA256(Pᵢ) |
| `0x22` | `dkg_reveal` | Reveal Pᵢ, verify hash |
| `0x23` | `dkg_finalize` | P = P₁+P₂+P₃ computed on-chain |
| `0x10` | `submit_key_share` | Encrypt sᵢ halves to ZK nodes |
| `0x24` | `dkg_complete_keygen` | Key marked Complete |

### GG20 (signing)

| Shortname | Action | Effect |
|-----------|--------|--------|
| `0x50` | `gg20_start_signing` | Open signing session |
| `0x45` | `submit_delta` | Submit δᵢ (share of k·γ) |
| `0x46` | `submit_gamma_point` | Submit Γᵢ = γᵢ·G |
| `0x47` | `gg20_finalize_r` | R = δ⁻¹·Γ, r = R.x mod N |
| `0x51` | `commit_partial_sig` | Commit SHA256(σᵢ) |
| `0x52` | `submit_partial_sig` | Reveal σᵢ |
| `0x53` | `finalize_gg20_sig` | σ=Σσᵢ, low-s, ECDSA verify ✓ |
| `0x48` | `abort_signing` | Cancel session |

### PQC (post-quantum gating)

| Shortname | Action | Effect |
|-----------|--------|--------|
| `0x72` | `register_party_address` | Map party → Partisia address |
| `0x73` | `register_dilithium_pubkey` | Store ML-DSA-65 public key |
| `0x74` | `register_kyber_pubkey` | Store ML-KEM-768 public key |
| `0x75` | `start_pqc_approval_session` | Open PQC approval window |
| `0x76` | `submit_pqc_approval` | Submit Dilithium signature |
| `0x77` | `finalize_pqc_approval` | Verify all, ungate GG20 |

---

## 12. Setup & Running

### Prerequisites

```bash
# Rust
rustup target add wasm32-unknown-unknown
cargo install cargo-partisia-contract

# Go 1.23+
go version

# Node.js 18+
node --version
```

### Environment variables

```bash
# Partisia network
PARTISIA_NODE_URL=https://node1.testnet.partisiablockchain.com
SIGNER_ADDRESS=03...            # deployed kosh-zk-signer address

# One Partisia key per party (chain-relay holds all)
PARTISIA_SENDER_KEY_1=<64-char hex>
PARTISIA_SENDER_ADDRESS_1=<address>
PARTISIA_SENDER_KEY_2=...
PARTISIA_SENDER_ADDRESS_2=...
PARTISIA_SENDER_KEY_3=...
PARTISIA_SENDER_ADDRESS_3=...

# Share file encryption (one passphrase per party)
SHARE_FILE_KEY_1=party1-secret-passphrase
SHARE_FILE_KEY_2=party2-secret-passphrase
SHARE_FILE_KEY_3=party3-secret-passphrase

# Frontend ↔ backend connection
# Backend CORS default: http://localhost:5173,http://127.0.0.1:5173
KOSH_CORS_ALLOWED_ORIGINS=http://localhost:5173  # override if needed

# Gateway JWT
JWT_SECRET=change-me-in-production
```

### Option A — Rust backend + frontend (simplest, works today)

```bash
# Terminal 1: backend
cargo run -p kosh-backend

# Terminal 2: frontend
cd frontend/KoshSignerUsingPartisiaZK/client
npm install && npm run dev
# Open http://localhost:5173
```

### Option B — Full microservices stack

```bash
# Build all Rust services
cargo build --release \
  -p kosh-party -p kosh-pqc -p kosh-keystore -p kosh-chain-relay

# Go services
cd services/kosh-coordinator && PORT=50051 go run ./cmd/coordinator &
cd services/kosh-policy      && PORT=50052 POLICY_FILE= go run ./cmd/policy &

# PQC services (one per party)
PQC_KEY_FILE=/tmp/pqc1.json PORT=50080 ./target/release/kosh-pqc &
PQC_KEY_FILE=/tmp/pqc2.json PORT=50081 ./target/release/kosh-pqc &
PQC_KEY_FILE=/tmp/pqc3.json PORT=50082 ./target/release/kosh-pqc &

# Party daemons
PARTY_INDEX=1 PORT=50060 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &
PARTY_INDEX=2 PORT=50061 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &
PARTY_INDEX=3 PORT=50062 COORDINATOR_ADDR=http://localhost:50051 \
  ./target/release/kosh-party &

# Chain relay
PARTISIA_NODE_URLS=https://node1.testnet.partisiablockchain.com \
  PORT=50053 ./target/release/kosh-chain-relay &

# Gateway + monitor
cd services/kosh-gateway && PORT=8080 \
  COORDINATOR_ADDR=localhost:50051 POLICY_ADDR=localhost:50052 \
  PARTY_1_ADDR=localhost:50060 PARTY_2_ADDR=localhost:50061 \
  PARTY_3_ADDR=localhost:50062 JWT_SECRET=dev go run ./cmd/gateway &
cd services/kosh-monitor && PORT=9090 go run ./cmd/monitor &
```

### Option C — Docker Compose

```bash
cp deploy/.env.example deploy/.env
# Edit deploy/.env with your Partisia keys
docker-compose -f deploy/docker-compose.yml up
```

### Quick test (Option B/C)

```bash
# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/token \
  -H "X-API-Key: mykey" | jq -r .token)

# Create distributed key
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id": 1, "num_parties": 3, "threshold": 2}'
# → {"key_id":1,"combined_pk_hex":"02...","status":"complete"}

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
# → {"signature":"0x...","key_id":1}

# Prometheus metrics
curl http://localhost:9090/metrics | grep kosh_
```

---

## 13. Test Results — 27/27 Passing

```
Service               Tests   Time      What is verified
────────────────────────────────────────────────────────────────────
kosh-coordinator      6       0.8s ea   Post/Read/Watch/Clear/List gRPC
kosh-policy           5       0.7s ea   AddPolicy/Validate/Remove gRPC
cross-service         1       1.4s      coordinator + policy together
kosh-gateway          4       2–50s     Health, JWT auth, PolicyCRUD, DKG REST
kosh-monitor          4       2s ea     Ready, Health, /metrics, metric types
kosh-pqc              5       0.4s      GetIdentity, KEM, AES-GCM, ML-DSA, tamper
kosh-party            2       1.5–3s    GetStatus, 3-party DKG
────────────────────────────────────────────────────────────────────
TOTAL                 27                ALL PASS ✅
```

**Key proof — all 3 parties compute the same combined public key:**

```
Party 1 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
Party 2 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
Party 3 DKG complete: pk=020917fd177743509ed07873f81ed94772a45058d9723e7a474c3198d63eb03f7b
→ All three independently computed P = P₁ + P₂ + P₃  ✓
```

### Run all tests

```bash
# Go services
cd services/integration-test && go test ./... -timeout 60s
cd services/kosh-gateway     && go test -timeout 300s
cd services/kosh-monitor     && go test -timeout 60s

# Rust services
cargo test -p kosh-pqc   --test grpc_test
cargo test -p kosh-party --test party_grpc_test

# Frontend build check
cd frontend/KoshSignerUsingPartisiaZK/client
npm run build
# → ✓ built in 3.22s  (no errors)

# TypeScript tests (needs Partisia testnet keys)
cd client
npx tsx src/test-gg20-sign.ts    # Full DKG + GG20 on testnet (~3-5 min)
npx tsx src/test-policy.ts       # 20 assertions
npx tsx src/test-pqc.ts          # 28 assertions
npx tsc --noEmit                 # type check → 0 errors
```

---

## 14. Live Addresses

| Item | Value |
|------|-------|
| Contract (current) | `031fb3ede8b7274ffb94ef250ba3747e49b2706d12` |
| Contract (previous) | `03a1e8aba3ba45c1e42d01f688768436cb2b572de0` |
| Deployer | `002ee35cde26782f255b9550ea1ac53faeac2c71cd` |
| Explorer | `https://browser.testnet.partisiablockchain.com/contracts/<ADDR>` |

**Sepolia proof — signature produced by threshold MPC, private key never assembled:**

| Item | Value |
|------|-------|
| Tx hash | `0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41` |
| Block | 10432151 |
| From | `0x46fe38ef06876C3d76E03D1e5991eD28FF2714ad` |

---

## 15. Security

| Property | Status | How it is enforced |
|----------|--------|--------------------|
| Private key never assembled | ✅ | DKG additive shares — s = s₁+s₂+s₃ never computed |
| Nonce never assembled | ✅ | GG20 — kᵢ are additive nonce shares, k⁻¹ never exists |
| Rogue key attack prevented | ✅ | DKG commit-reveal + Schnorr proof of knowledge of sᵢ |
| Sub-share integrity | ✅ | Feldman VSS: fⱼ(i)·G == Cⱼ₀ + i·Cⱼ₁ verified before combining |
| Gamma bias prevented | ✅ | Commit-reveal for Γᵢ before delta submission |
| Delta manipulation prevented | ✅ | Commit-reveal for δᵢ |
| Partial sig manipulation | ✅ | Commit-reveal for σᵢ |
| Secret memory cleared | ✅ | Rust `ZeroizeOnDrop` on all key material structs |
| Secret process isolation | ✅ | Secrets never leave kosh-keystore / kosh-pqc services |
| ZK node isolation | ✅ | sᵢ split into two 128-bit halves, each encrypted per ZK node |
| Post-quantum gating | ✅ | ML-DSA-65 + ML-KEM-768 approval required before GG20 |
| EIP-2 low-s | ✅ | Contract normalizes σ if σ > N/2 |
| Policy enforcement | ✅ | Mandatory parties + min threshold enforced before fan-out |
| JWT authentication | ✅ | HS256 tokens required on all gateway routes |
| 2048-bit Paillier | ✅ | Upgraded from original 1024-bit in TypeScript monolith |
| CORS locked | ✅ | Only localhost:5173 allowed by default |

### Known gaps (pre-production)

| Priority | Gap | Fix |
|----------|-----|-----|
| Critical | No ZK range proofs in MtA | Add Πenc + Πaff-g proofs per GG20 paper, or use CGGMP21 |
| Critical | kosh-keystore not wired to kosh-party | Connect gRPC: party fetches xᵢ from keystore (placeholder used in tests) |
| Medium | kosh-chain-relay not called from kosh-party | Wire relay into party phase.rs (stubs present) |
| Medium | No identifiable abort protocol | Add per-submission ZK proofs |
| Low | Single coordinator (SPOF) | Add coordinator clustering |
