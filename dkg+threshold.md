# DKG + Threshold ECDSA — Complete Protocol (No Coordinator, Ever)

A **2-of-3 threshold** signing system where the private key **never exists** — not during creation, not during signing, not ever. Any 2 out of 3 parties can produce a valid Ethereum signature. If one party goes offline, the other two continue without them.

Uses **Pedersen/Feldman Distributed Key Generation (DKG)** + **GG20 Threshold ECDSA** with **Lagrange interpolation** — no single coordinator at any step.

---

## Table of Contents

- [Why Threshold? The Pizza vs. The Bank Vault](#why-threshold-the-pizza-vs-the-bank-vault)
- [Every Variable Explained — Complete Glossary](#every-variable-explained--complete-glossary)
- [Phase 1: Pedersen/Feldman DKG — Key Born Split](#phase-1-pedersenfeldman-dkg--key-born-split)
- [Phase 2: Threshold Signing — Any 2 of 3](#phase-2-threshold-signing--any-2-of-3)
- [Deep Dive: γ and δ — The Nonce Hiding Trick](#deep-dive-γ-gamma-and-δ-delta--the-nonce-hiding-trick)
- [Worked Example — Full Flow with Real Numbers](#worked-example--full-flow-with-real-numbers)
- [Visual Guide — ASCII Art Diagrams](#visual-guide--ascii-art-diagrams)
- [Math Proofs — Why Everything Works](#math-proofs--why-everything-works)
  - Proof 1: Lagrange Interpolation
  - Proof 2: Feldman Commitments
  - Proof 3: Combined Polynomial Structure
  - Proof 4: Threshold Signing Validity
  - Proof 5: Complete ECDSA Verification (Ethereum verifier u₁/u₂)
  - Proof 6: Ghost Key — s Never Needs to Exist
  - Proof 7: Partial Sig Commit-Reveal (Anti-Tampering)
  - Proof 8: Low-s Normalization (EIP-2)
- [Security Analysis — Zero Coordinator Proof](#security-analysis--zero-coordinator-proof)
- [Comparison — Additive (Old) vs Threshold (New)](#comparison--additive-old-vs-threshold-new)
- [Production Security — Complete Implementation Guide](#production-security--complete-implementation-guide)
  - Protection 1: MtA Range Proofs (Πenc and Πaff-g) — CRITICAL
  - Protection 2: Paillier Key Verification (Πmod and Πfac) — CRITICAL
  - Protection 3: Schnorr Proof of Knowledge (Anti-Rogue-Key) — CRITICAL
  - Protection 4: Identifiable Abort During Signing — HIGH
  - Protection 5: Session Isolation & Nonce Reuse Prevention — HIGH
  - Protection 6: Signing Timeout & Abort Protocol — HIGH
  - Protection 7: Key Refresh (Proactive Secret Sharing) — MEDIUM
  - Protection 8: Key Backup & Recovery (Re-Sharing) — MEDIUM
  - Protection 9: δᵢ and σᵢ Correctness Proofs (Πlog) — MEDIUM
  - Protection 10: Ring-Pedersen Parameters (Πprm) — CRITICAL (CGGMP21)
  - Protection 11: EIP-155 Chain ID & Signature Format — HIGH
  - Protection 12: Constant-Time Operations & Side-Channels — HIGH
  - Protection 13: Entropy Quality for Random Scalars — HIGH
  - Protection 14: Message Ordering & Front-Running — MEDIUM
  - Protection 15: On-Chain Storage & Gas Costs — MEDIUM

---

## Why Threshold? The Pizza vs. The Bank Vault

### The Pizza (Current: Additive 3-of-3)

Imagine a pizza cut into exactly 3 slices.

- **Party 1** holds slice 1
- **Party 2** holds slice 2
- **Party 3** holds slice 3

The full pizza is the private key. To sign a transaction, you need the full pizza — all 3 slices together.

**What happens if Party 3 goes offline?**

You have slice 1 and slice 2. That's only 2/3 of a pizza. You cannot sign. Done. Failed.

The current system splits the private key `s` as:

```
s = s₁ + s₂ + s₃
```

If anyone is missing, the sum is wrong and the signature is invalid. This is **3-of-3**: every single party must show up.

### The Bank Vault (New: Threshold 2-of-3)

Picture a bank vault that needs **2 out of 3 managers** to open it.

- Manager 1 + Manager 2 can open the vault. ✓
- Manager 1 + Manager 3 can open the vault. ✓
- Manager 2 + Manager 3 can open the vault. ✓
- Manager 1 alone cannot open it. ✗

This is **2-of-3 threshold**: any 2 out of 3 is enough. The system keeps working even when someone is offline.

### Why You Can't Just "Fix" Additive Shares

With concrete numbers — secret = 15, split additively:

```
s₁ = 4,  s₂ = 6,  s₃ = 5
4 + 6 + 5 = 15  ✓
```

Party 3 goes offline. Can parties 1 and 2 recover?

```
4 + 6 = 10  ✗   (not 15 — missing 5, which only Party 3 knows)
```

Could you "pad" shares so any 2 sum to 15?

- If {1,2} must sum to 15: s₁ + s₂ = 15 → s₁=4, s₂=11
- If {1,3} must sum to 15: s₁ + s₃ = 15 → s₃=11
- If {2,3} must sum to 15: 11 + 11 = 22 ≠ 15  ✗

**Mathematically impossible.** Additive shares are all-or-nothing. You need a completely different structure: **Shamir polynomial sharing**.

### How Shamir Solves What Additive Can't — The Operation Changes

The reason additive fails is the operation is FIXED: `s = shareᵢ + shareⱼ` (weights always 1). All pairs must satisfy the same equation. Impossible.

Shamir changes the operation to a **weighted sum** where the weights change per subset:

```
Additive: s = shareᵢ + shareⱼ               ← weights fixed at 1, same for all pairs
Shamir:   s = λᵢ · Xᵢ + λⱼ · Xⱼ            ← weights change per pair
```

Using one consistent example throughout this entire document:

```
Each party randomly picks their own secret and slope:
    Party 1 picks: s₁ = 3,  a₁ = 2   →  f₁(x) = 3 + 2x
    Party 2 picks: s₂ = 5,  a₂ = 1   →  f₂(x) = 5 + 1x
    Party 3 picks: s₃ = 4,  a₃ = 3   →  f₃(x) = 4 + 3x

    Combined secret:     s = s₁+s₂+s₃ = 3+5+4 = 12
    Combined polynomial: F(x) = 12 + 6x

    Final shares (x-coordinates 1, 2, 3 on the combined line):
        X₁ = F(1) = f₁(1)+f₂(1)+f₃(1) = (3+2)+(5+1)+(4+3) = 5+6+7  = 18
        X₂ = F(2) = f₁(2)+f₂(2)+f₃(2) = (3+4)+(5+2)+(4+6) = 7+7+10 = 24
        X₃ = F(3) = f₁(3)+f₂(3)+f₃(3) = (3+6)+(5+3)+(4+9) = 9+8+13 = 30
```

**WHY x = 1, 2, 3?  Why not x = 7, 42, 999?**

```
The secret s lives at x = 0:       F(0) = s = 12

To HIDE the secret, we need points AWAY from x = 0.
We pick x = 1, 2, 3 because:

    1. They are NON-ZERO  →  F(1), F(2), F(3) ≠ F(0) = s
       (if we used x=0, the share WOULD BE the secret — defeats the purpose)

    2. They are ALL DIFFERENT  →  each party gets a unique point on the line
       (if two parties had the same x, they'd have the same share — useless)

    3. They are PUBLIC and FIXED  →  everyone knows which x goes to which party
       (Party 1 always uses x=1, Party 2 uses x=2, Party 3 uses x=3)

    4. They are SIMPLE  →  makes Lagrange coefficient computation easy
       (λ₁ for {1,2} = (0-2)/(1-2) = 2 — clean integer)

Could we use x = 7, 42, 999?  YES — the math works with ANY distinct non-zero values.
Lagrange interpolation works for any set of distinct x-coordinates.
But 1, 2, 3 is the convention because:

    - Simpler computation (smaller numbers in the Lagrange formula)
    - Natural mapping: Party i uses x = i
    - No security benefit from using larger x values
    - Every MPC library uses this convention

The x-values are NOT secret — they are public identifiers.
Only the Y-values (X₁=18, X₂=24, X₃=30) are secret — those are the actual shares.

CRITICAL: x = 0 is RESERVED for the secret.  No party ever uses x = 0.
          If any party had x = 0, their share would equal s directly.
```

So `secret = 12` and `shares X₁=18, X₂=24, X₃=30` are NOT separate numbers —
X₁/X₂/X₃ are DERIVED from the polynomials. Now Shamir's weighted sum:

```
Subset {1,2} uses weights  λ₁=2,   λ₂=-1:
    2×18 + (-1)×24 = 36 - 24 = 12  ✓

Subset {1,3} uses weights  λ₁=3/2, λ₃=-1/2:
    (3/2)×18 + (-1/2)×30 = 27 - 15 = 12  ✓

Subset {2,3} uses weights  λ₂=3,   λ₃=-2:
    3×24 + (-2)×30 = 72 - 60 = 12  ✓
```

Different weights, same result. Every 2-of-3 subset gives 12 — without ever computing 12 directly.

**Why do the right weights always exist?** Because the shares are POINTS ON A LINE. The Lagrange weights are mathematically derived to cancel out the "extra" that the line structure bakes into each share, leaving only the secret at x=0.

---

### Why Each Party Needs BOTH a Secret AND a Slope

This is the single most important insight. **The secret alone is not enough.**

```
WITHOUT slope (additive — what current system does):

    Party 1 just picks: s₁ = 3   ← one number
    Party 2 just picks: s₂ = 5   ← one number
    Party 3 just picks: s₃ = 4   ← one number

    No polynomial. No line. Just 3 random numbers.
    → Only 3-of-3 possible (must add all 3 to get secret)


WITH slope (Shamir — what threshold requires):

    Party 1 picks: s₁ = 3, a₁ = 2  → f₁(x) = 3 + 2x   ← a LINE
    Party 2 picks: s₂ = 5, a₂ = 1  → f₂(x) = 5 + 1x   ← a LINE
    Party 3 picks: s₃ = 4, a₃ = 3  → f₃(x) = 4 + 3x   ← a LINE

    Lines combine: F(x) = 12 + 6x  (the combined secret line)
    → Any 2 points on a line reconstruct the line → 2-of-3 works  ✓
```

**What is the slope's job?**

The slope `aᵢ` has exactly ONE purpose: to give each party's share a polynomial structure. Without it, shares are just raw numbers that can only be added. With it, shares are points on a line that can be interpolated.

```
The slope aᵢ is:
    ✓ Random (chosen fresh, not derived from anything)
    ✓ Secret during DKG (hidden via Feldman commitment aᵢ·G)
    ✓ DISCARDED after DKG completes — never used again
    ✗ NOT part of the private key
    ✗ NOT needed for signing
```

Its only job is to bake the line structure into the shares. Once shares X₁, X₂, X₃ are computed and stored in ZK, the slopes a₁, a₂, a₃ are irrelevant forever.

---

### Two Types of "Curve" — Different Jobs

There are TWO completely different mathematical objects called "curve" in this system. They do completely different things:

| | Polynomial Line `F(x) = s + b·x` | Elliptic Curve secp256k1 |
|---|---|---|
| **Shape** | A line in modular arithmetic | A curve: y² = x³ + 7 over a finite field |
| **What it stores** | The secret `s` at x=0, shares at x=1,2,3 | Public keys as EC points (P = s·G) |
| **Job** | Enables threshold — any 2 points reconstruct the line | Hides secrets — easy to multiply, impossible to reverse |
| **Where used** | Sub-share distribution, Lagrange interpolation | Feldman commitments, ECDSA signing |
| **Who can see it** | Nobody sees the full polynomial | Everyone sees the public EC points |

```
POLYNOMIAL LINE (threshold source):
    F(x) = s + b·x

         s=12
          │            ●  X₃=30
          │         ●  X₂=24
          │      ●  X₁=18
          │
          ●─────────────── x
         x=0   x=1  x=2  x=3

    2 points → defines the line → find secret at x=0
    1 point  → infinitely many lines → learn nothing


ELLIPTIC CURVE (cryptographic hiding):
    y² = x³ + 7  (over finite field)

    s₁ = 3  →  C₁₀ = 3·G  (a point on the curve, visible)
    a₁ = 2  →  C₁₁ = 2·G  (a point on the curve, visible)

    Seeing 3·G doesn't tell you 3.
    Seeing 2·G doesn't tell you 2.
    Discrete log is computationally infeasible.
```

**Each party uses BOTH:**
- The **polynomial line** to generate sub-shares `fᵢ(j)` and receive shares `Xⱼ`
- The **elliptic curve** to publish Feldman commitments `Cᵢ₀, Cᵢ₁` and sign transactions

---

## Every Variable Explained — Complete Glossary

### The Curve and Constants

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **secp256k1** | The elliptic curve | The mathematical curve used by Bitcoin and Ethereum. The "playing field" where all the math happens. |
| **G** | Generator point | A fixed, publicly known point on the curve. Everyone uses the same G. Multiply it by a number to get a new point. |
| **n** | Curve order | How many valid points exist. n ≈ 2²⁵⁶ ≈ 10⁷⁷. All arithmetic is done "mod n" (wraps around like a clock). |
| **× G** | Point multiplication | "Multiply a number by G" = slide along the curve. Easy forward (number → point), impossible to reverse (point → number). |

### DKG Variables — Each Party's Polynomial

Each party `i` independently picks a degree-1 polynomial: **fᵢ(x) = sᵢ + aᵢ·x**

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **sᵢ** | Party i's secret contribution | Only Party i | The constant term of Party i's polynomial. A random 256-bit number. |
| **aᵢ** | Party i's random slope | Only Party i | The coefficient of Party i's polynomial. Another random 256-bit number. Hides sᵢ from the shares. |
| **fᵢ(x)** | Party i's polynomial | Only Party i knows the full polynomial | fᵢ(x) = sᵢ + aᵢ·x. A degree-1 line in modular arithmetic. |
| **fᵢ(j)** | Sub-share from Party i to Party j | Sent secretly from i to j | Party i evaluates their polynomial at j's index. This is Party i's contribution to Party j's final share. |

### Feldman Commitments — Public Verification Points

| Symbol | What It Is | Who Sees It | Plain English |
|--------|-----------|-------------|---------------|
| **Cᵢ₀** | Party i's constant commitment | Everyone (on-chain) | Cᵢ₀ = sᵢ·G — the EC point for Party i's secret. You can see the point but can't figure out sᵢ. |
| **Cᵢ₁** | Party i's slope commitment | Everyone (on-chain) | Cᵢ₁ = aᵢ·G — the EC point for Party i's slope. Lets anyone verify sub-shares without learning aᵢ. |

### Combined Key — The Ghost Key

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **s** | The "full" private key | **NOBODY — never exists!** | s = s₁ + s₂ + s₃ mod n. This sum is NEVER computed. It's a mathematical ghost. |
| **P** | Combined public key | Everyone (on-chain) | P = C₁₀ + C₂₀ + C₃₀ = (s₁+s₂+s₃)·G = s·G. The Ethereum wallet address. |
| **F(x)** | Combined polynomial | **NOBODY — never assembled** | F(x) = f₁(x)+f₂(x)+f₃(x) = s + (a₁+a₂+a₃)·x. The ghost polynomial. |

### Final Shares — Points on the Combined Line

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **X₁** | Party 1's final Shamir share | Only Party 1's ZK node | X₁ = F(1) = f₁(1)+f₂(1)+f₃(1). Evaluated at x=1. WHY x=1: public non-zero identifier for Party 1. |
| **X₂** | Party 2's final Shamir share | Only Party 2's ZK node | X₂ = F(2) = f₁(2)+f₂(2)+f₃(2). Evaluated at x=2. WHY x=2: public non-zero identifier for Party 2. |
| **X₃** | Party 3's final Shamir share | Only Party 3's ZK node | X₃ = F(3) = f₁(3)+f₂(3)+f₃(3). Evaluated at x=3. WHY x=3: public non-zero identifier for Party 3. |

> **WHY these x-values?** The secret lives at x=0: F(0)=s. Shares must be at x≠0 (otherwise the share IS the secret). We use x=1,2,3 by convention — any distinct non-zero values work. The x-values are public; only the Y-values (X₁, X₂, X₃) are secret.

### Lagrange Coefficients — The Threshold Magic

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **λᵢ** | Lagrange coefficient for party i | A weight that depends on WHICH parties are signing. Different subset → different weights. |
| **x̃ᵢ** | Adjusted share | x̃ᵢ = λᵢ · Xᵢ. The share multiplied by the Lagrange weight. When you sum adjusted shares: Σ x̃ᵢ = s (the secret). |

### Lagrange Coefficients for All Subsets (x-coordinates {1,2,3})

| Signing Subset | λ₁ | λ₂ | λ₃ | Formula verification |
|----------------|----|----|-----|---------------------|
| **{1, 2}** | 2 | -1 (= n-1) | — | λ₁·X₁ + λ₂·X₂ = s |
| **{1, 3}** | 3/2 | — | -1/2 (= (n-1)/2) | λ₁·X₁ + λ₃·X₃ = s |
| **{2, 3}** | — | 3 | -2 (= n-2) | λ₂·X₂ + λ₃·X₃ = s |
| **{1, 2, 3}** | 3 | -3 (= n-3) | 1 | λ₁·X₁ + λ₂·X₂ + λ₃·X₃ = s |

The Lagrange coefficient formula for evaluating at x=0, party i in subset S:

```
λᵢ = ∏(j ∈ S, j≠i)  (0 - j) / (i - j)  mod n
```

### Signing Variables — Same as README.md

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **kᵢ** | Party i's nonce share | Only Party i | Random number picked independently by each party for this signing session. Fresh every time. k = k₁+k₂ is NEVER assembled — same reason s is never assembled: if k is known, private key can be extracted. |
| **γᵢ** | Party i's gamma (mask) | Only Party i | Random masking scalar. WHY: to let the contract compute k⁻¹·G without k ever being a number. γ enters as k·γ (safe to open), then cancels algebraically. Fresh random every session. |
| **Γᵢ** | Party i's gamma point | Everyone (on-chain) | Γᵢ = γᵢ·G. Safe public version of γᵢ — EC point, reveals nothing about γᵢ. WHY: EC points add linearly (Γ₁+Γ₂=γ·G) so the contract can get γ·G without knowing γ. |
| **δᵢ** | Party i's delta share | Submitted to contract | δᵢ = kᵢ·γᵢ + Σ(MtA cross-terms). Share of k×γ. WHY: contract needs δ = k·γ to compute R = δ⁻¹·Γ = k⁻¹·G. Safe to open because γ hides k. |
| **τᵢ** | Party i's MtA share of k×x̃ | Only Party i (from MtA) | τᵢ = kᵢ·x̃ᵢ + MtA cross-terms. Σ τᵢ = k·s. WHY: feeds the partial signature σᵢ = z·kᵢ + r·τᵢ without any party computing k·s directly. |
| **σᵢ** | Party i's partial signature | Submitted to contract | σᵢ = z·kᵢ + r·τᵢ. WHY this formula: z·kᵢ is Party i's share of z·k; r·τᵢ is their share of r·k·s. Sum gives σ = k·(z+r·s). |
| **R** | Nonce point | Computed on-chain | R = δ⁻¹·Γ = k⁻¹·G. WHY: r = R.x is the first component of the ECDSA signature. Computed without k ever existing. |
| **r** | x-coordinate of R | Part of signature | r = R.x mod n. First half of the ECDSA signature (r, σ). |
| **(r, σ)** | Final ECDSA signature | On-chain | Valid Ethereum signature. Same format as any single-party ECDSA sig — Ethereum cannot tell it came from threshold signing. |

---

## Phase 1: Pedersen/Feldman DKG — Key Born Split

The private key is NEVER created — it's born already split across 3 independent parties. No coordinator, no trusted dealer, no single point of failure.

### Round 1: Each Party Generates Independently (No Communication)

Each party `i` (i ∈ {1, 2, 3}), acting completely alone:

1. Picks two random scalars: `sᵢ` (secret contribution) and `aᵢ` (random slope)
2. Defines their polynomial: `fᵢ(x) = sᵢ + aᵢ·x  (mod n)`
3. Computes Feldman commitments: `Cᵢ₀ = sᵢ·G` and `Cᵢ₁ = aᵢ·G`

```
Party 1:  f₁(x) = s₁ + a₁·x    →    C₁₀ = s₁·G,  C₁₁ = a₁·G
Party 2:  f₂(x) = s₂ + a₂·x    →    C₂₀ = s₂·G,  C₂₁ = a₂·G
Party 3:  f₃(x) = s₃ + a₃·x    →    C₃₀ = s₃·G,  C₃₁ = a₃·G

Nobody knows anyone else's polynomial. No coordinator involved.
```

### Round 2: Commit Feldman Commitments (On-Chain)

Each party commits a hash of their Feldman commitments:

```
Party 1:  hash₁ = SHA-256(C₁₀ ‖ C₁₁)  →  on-chain
Party 2:  hash₂ = SHA-256(C₂₀ ‖ C₂₁)  →  on-chain
Party 3:  hash₃ = SHA-256(C₃₀ ‖ C₃₁)  →  on-chain
```

**Why commit first?** Without commitments, a malicious party could wait to see others' commitments and choose their polynomial to control the combined key. The commit forces everyone to lock in their choice before seeing others.

### Round 3: Reveal Feldman Commitments (On-Chain)

After all 3 commits are collected, each party reveals their actual Feldman commitments:

```
Party 1 reveals: C₁₀ = s₁·G,  C₁₁ = a₁·G
    Contract verifies: SHA-256(C₁₀ ‖ C₁₁) == hash₁  ✓

Party 2 reveals: C₂₀ = s₂·G,  C₂₁ = a₂·G
    Contract verifies: SHA-256(C₂₀ ‖ C₂₁) == hash₂  ✓

Party 3 reveals: C₃₀ = s₃·G,  C₃₁ = a₃·G
    Contract verifies: SHA-256(C₃₀ ‖ C₃₁) == hash₃  ✓
```

Now everyone can see all 6 Feldman commitment points, but nobody can learn any secret scalar from them (discrete log problem).

### Round 4: Sub-Share Distribution (Via ZK Secret Inputs)

Each party evaluates their polynomial at every party's index and sends the result secretly:

```
Party 1 sends:
    f₁(1) = s₁ + a₁·1  →  keeps for self
    f₁(2) = s₁ + a₁·2  →  ZK secret input to Party 2's node
    f₁(3) = s₁ + a₁·3  →  ZK secret input to Party 3's node

Party 2 sends:
    f₂(1) = s₂ + a₂·1  →  ZK secret input to Party 1's node
    f₂(2) = s₂ + a₂·2  →  keeps for self
    f₂(3) = s₂ + a₂·3  →  ZK secret input to Party 3's node

Party 3 sends:
    f₃(1) = s₃ + a₃·1  →  ZK secret input to Party 1's node
    f₃(2) = s₃ + a₃·2  →  ZK secret input to Party 2's node
    f₃(3) = s₃ + a₃·3  →  keeps for self
```

9 sub-shares total. Each travels encrypted via Partisia's ZK infrastructure. The on-chain contract never sees these raw values.

**Why Party 1 sends f₁(2) to Party 2 specifically:** Party 2's index is 2. The combined polynomial F evaluated at 2 must equal X₂. By linearity: F(2) = f₁(2) + f₂(2) + f₃(2). So Party 2 needs a contribution from every party's polynomial evaluated at index 2.

### Round 5: Feldman Verification (Inside ZK Nodes)

Before accepting any sub-share, the ZK nodes verify it against the public Feldman commitments.

When Party 2 receives f₁(2) from Party 1, the check is:

```
Left side:   f₁(2) · G                     (scale received value by G)
Right side:  C₁₀ + 2 · C₁₁                 (evaluate commitment polynomial at index 2)
           = s₁·G + 2·(a₁·G)
           = (s₁ + 2·a₁)·G
           = f₁(2)·G                        ← must match left side!
```

The general Feldman verification formula:

```
For party j receiving fᵢ(j) from party i:

    fᵢ(j) · G  ==  Cᵢ₀ + j · Cᵢ₁

If this fails → Party i is cheating → DKG aborts.
```

**Why this works:** EC scalar multiplication is linear: `(a + bx)·G = a·G + x·(b·G)`. If Party 1 sent a wrong sub-share, the left and right sides won't match.

**What Party 2 cannot do:** Learn s₁ from seeing C₁₀ = s₁·G. The discrete log problem makes this computationally infeasible. The commitment is binding (can't cheat) but hiding (doesn't reveal the secret).

### Round 6: Combine Sub-Shares into Final Shares (Inside ZK Nodes)

After all sub-shares pass Feldman verification, each party's ZK node computes their final Shamir share:

```
Party 1's final share:  X₁ = f₁(1) + f₂(1) + f₃(1)
Party 2's final share:  X₂ = f₁(2) + f₂(2) + f₃(2)
Party 3's final share:  X₃ = f₁(3) + f₂(3) + f₃(3)
```

Each Xⱼ is stored encrypted on Party j's ZK node. Nobody sees anyone else's final share.

### Round 7: Compute Combined Public Key (On-Chain)

The contract computes the combined public key. There are **two valid methods** — both give the same P = s·G:

**Method A — Direct Feldman Sum (uses the constant Feldman terms Cᵢ₀):**

```
P = C₁₀ + C₂₀ + C₃₀
  = s₁·G + s₂·G + s₃·G
  = (s₁ + s₂ + s₃)·G
  = s·G   ✓

This is simple point addition of the 3 constant Feldman commitment points.
Works because Cᵢ₀ = sᵢ·G directly encodes each party's secret contribution.
```

**Method B — Lagrange Interpolation (uses the final share images Xᵢ·G):**

```
The final shares X₁=F(1), X₂=F(2), X₃=F(3) are points on the combined polynomial.
Their EC images are: P₁ = X₁·G = F(1)·G,  P₂ = X₂·G,  P₃ = X₃·G.

To recover F(0)·G = s·G, use Lagrange on ALL 3 shares (3-of-3 reconstruction):

    Lagrange coefficients for subset {1,2,3} at x=0:
    λ₁ = 3,  λ₂ = -3 (= n-3),  λ₃ = 1

    P = λ₁·P₁ + λ₂·P₂ + λ₃·P₃
      = 3·F(1)·G + (n-3)·F(2)·G + 1·F(3)·G
      = (3·F(1) + (n-3)·F(2) + F(3))·G
      = F(0)·G
      = s·G  ✓

Note: These are 3-of-3 Lagrange coefficients (all 3 parties present at DKG finalize).
They are DIFFERENT from the 2-of-3 signing coefficients used later.
```

**Which method does the contract use?**
The current implementation uses Method B (Lagrange on the revealed public key shares) because the contract has access to the Xᵢ·G images from the DKG ceremony, not the raw Cᵢ₀ Feldman terms. Both methods are mathematically equivalent and give the same P = s·G — the Ethereum wallet address.

### Result of DKG

```
✓ Public key P = s·G is on-chain  (Ethereum address derivable)
✓ Each party holds their final share Xⱼ  (encrypted on ZK nodes)
✓ The private key s = s₁+s₂+s₃  was NEVER computed by anyone
✓ No coordinator at any step
✓ Any cheating detected via Feldman verification
✓ Any 2 shares can reconstruct s  (but we never will — threshold signing avoids this)
```

---

## Phase 2: Threshold Signing — Any 2 of 3

Party 3 is offline? No problem. Parties 1 and 2 sign together.

> **Quick orientation — why each piece exists:**
>
> | Step | What happens | WHY it's needed |
> |------|-------------|-----------------|
> | Lagrange coefficients | Compute λᵢ for the signing subset | Raw shares Xᵢ are points on a line — λᵢ are the weights to extract the secret at x=0 |
> | Adjusted shares x̃ᵢ | x̃ᵢ = λᵢ·Xᵢ | So the shares behave as if the private key s is split additively — makes GG20 work |
> | kᵢ generated | Each party picks random kᵢ | k = k₁+k₂ is the signing nonce — NEVER assembled, or private key is exposed |
> | γᵢ generated | Each party picks random γᵢ | Masks k so the contract can compute k⁻¹·G without seeing k |
> | MtA protocol | Cross-products split additively | Need k×γ and k×x̃ as additive shares — no party can compute these products alone |
> | δᵢ assembled | δᵢ = kᵢγᵢ + MtA pieces | Additive share of k·γ — when opened, lets contract compute R = k⁻¹·G via γ cancellation |
> | Γᵢ = γᵢ·G submitted | EC point of γᵢ | Safe public version of γ — EC addition gives γ·G without revealing γ |
> | R computed on-chain | R = δ⁻¹·Γ = k⁻¹·G | Nonce point for ECDSA — r = R.x is first half of signature |
> | σᵢ computed | σᵢ = z·kᵢ + r·τᵢ | Each party's share of the full ECDSA equation k·(z+r·s) |
> | σ = Σσᵢ | Contract adds partials | Linear addition of shares gives the valid full signature |

### Step 1: Choose Signing Subset

Any 2 parties agree to sign. Let's say the signing subset is S = {1, 2}.

### Step 2: Compute Lagrange Coefficients

For subset S = {1, 2}, evaluated at x = 0:

```
λ₁ = (0 - 2) / (1 - 2)  =  (-2) / (-1)  =  2
λ₂ = (0 - 1) / (2 - 1)  =  (-1) / (1)   = -1  =  n-1 (mod n)
```

### Step 3: Adjust Shares

Each signing party multiplies their Shamir share by their Lagrange coefficient:

```
Party 1:  x̃₁ = λ₁ · X₁ = 2 · X₁  mod n
Party 2:  x̃₂ = λ₂ · X₂ = (n-1) · X₂  mod n
```

**Why this works:** The adjusted shares sum to the secret:

```
x̃₁ + x̃₂ = λ₁·X₁ + λ₂·X₂
           = λ₁·F(1) + λ₂·F(2)
           = F(0)                    ← Lagrange interpolation at x=0
           = s                       ← the private key!
```

The private key `s` is NEVER computed — but the math guarantees the partial signatures will add up correctly.

### Step 4: Run GG20 with Adjusted Shares

Each signing party uses their **adjusted share x̃ᵢ** (not raw Xᵢ) in the standard GG20 protocol.

---

**Yes — k (the nonce) is ALSO split across parties, exactly like the private key s.**

```
Just like the private key:           The nonce works the same way:

s = s₁ + s₂ + s₃                    k = k₁ + k₂
  (never assembled)                      (never assembled)

Each party generated their sᵢ        Each party generates their kᵢ
independently during DKG.            independently at signing time.
```

**WHY is k split?**
Because if k is ever assembled by anyone — even the contract — an attacker with two signatures using the same k can extract the private key:
```
σ₁ = k·(z₁ + r₁·s)
σ₂ = k·(z₂ + r₂·s)      ← both use same k
→  s = (σ₁ - σ₂) / (r₁ - r₂) / k    ← private key exposed
```
So k is NEVER a single number anywhere. Each party picks their own kᵢ fresh for every signing session, discards it immediately after, and k = k₁ + k₂ is never computed.

---

```
STEP 1 ─ Each party independently picks two random secrets:
──────────────────────────────────────────────────────────

   Party 1 picks: k₁ (nonce share)   and   γ₁ (masking value)
   Party 2 picks: k₂ (nonce share)   and   γ₂ (masking value)

   Both are fresh random numbers chosen independently. No communication needed.

   WHY kᵢ?  The nonce k = k₁ + k₂ must be random and secret for every signature.
            Splitting it means no single party knows k — even if Party 1 is corrupted,
            they only have k₁, not k.

   WHY γᵢ?  Needed to compute R = k⁻¹·G WITHOUT revealing k. The gamma is a
            random blinding factor that hides k inside the product k·γ.
            After γ serves its purpose, it cancels out algebraically. (See Deep Dive.)


STEP 2 ─ MtA rounds (Multiply-then-Add, using Paillier encryption):
────────────────────────────────────────────────────────────────────

   WHY MtA?  We need the product k×γ and k×x̃ (as additive shares), but neither
             party can compute k×γ alone — they only have half of each (k₁, γ₁).
             MtA is a cryptographic protocol that splits a product a×b into two
             additive pieces WITHOUT either party learning the other's value.

   MtA converts: a×b  →  α + β = a×b
                           ↑   ↑
                        Party A  Party B  (each gets only one piece)

   For pair (1,2), four MtA calls are needed:
     MtA(k₁, γ₂): α₁₂ + β₁₂ = k₁×γ₂   ← cross-product for δ
     MtA(k₂, γ₁): α₂₁ + β₂₁ = k₂×γ₁   ← cross-product for δ
     MtA(k₁, x̃₂): μ₁₂ + ν₁₂ = k₁×x̃₂  ← cross-product for τ (k×share)
     MtA(k₂, x̃₁): μ₂₁ + ν₂₁ = k₂×x̃₁  ← cross-product for τ (k×share)

   After MtA, each party has one piece of each cross-product.
   No party learned the other's kᵢ, x̃ᵢ, or γᵢ.


STEP 3 ─ Each party builds two intermediate values δᵢ and τᵢ:
─────────────────────────────────────────────────────────────

   δᵢ = kᵢ·γᵢ + (their α/β pieces from MtA k×γ)   ← additive share of k·γ
   τᵢ = kᵢ·x̃ᵢ + (their μ/ν pieces from MtA k×x̃)  ← additive share of k·x̃

   Note: τᵢ is a NEW symbol — the MtA share of k×x̃. It is NOT the partial signature.

   WHY δᵢ?  δᵢ is Party i's share of the product k·γ. When combined: δ = δ₁+δ₂ = k·γ.
            This product is safe to open publicly (γ masks k). The contract needs δ
            to compute R = δ⁻¹·Γ = k⁻¹·G via the gamma cancellation trick.

   WHY τᵢ?  τᵢ is Party i's share of the product k·x̃ (= k times the adjusted private key share).
            When combined: τ₁+τ₂ = k·s. This feeds the partial signature formula.
            Neither party learns k·s as a whole — they only compute their τᵢ piece.

   Property after combining:
      δ₁ + δ₂ = k·γ        (used to compute R on-chain)
      τ₁ + τ₂ = k·(x̃₁+x̃₂) = k·s   (used in partial signatures — never computed directly)


STEP 4 ─ Submit δᵢ and Γᵢ = γᵢ·G to contract:
──────────────────────────────────────────────

   WHY submit Γᵢ (gamma point) instead of γᵢ (gamma scalar)?
   Because Γᵢ = γᵢ·G reveals nothing about γᵢ (discrete log). It's the safe public
   version of the mask. The contract can add EC points: Γ = Γ₁+Γ₂ = (γ₁+γ₂)·G = γ·G.

   WHY submit δᵢ (scalar) and not just the combined δ?
   Each party computes their own δᵢ and submits it. The contract adds them to get δ = k·γ.
   This avoids any single party having to compute or send the combined k·γ product.


STEP 5 ─ Contract computes R (nobody knows k or k⁻¹ as a number):
──────────────────────────────────────────────────────────────────

   δ = δ₁ + δ₂ = k×γ
   Γ = Γ₁ + Γ₂ = γ·G
   R = δ⁻¹ · Γ = k⁻¹·G       ← γ cancels out (see Deep Dive section)
   r = R.x mod n

   WHY does R = δ⁻¹·Γ give k⁻¹·G?
   δ⁻¹ · Γ  =  (k·γ)⁻¹ · (γ·G)  =  (1/kγ) · (γ·G)  =  (1/k)·G  =  k⁻¹·G
   The γ in the denominator cancels the γ in the EC point. Brilliant trick.
   The contract computed k⁻¹·G without k ever being a number anywhere.


STEP 6 ─ Each party computes their partial signature using their OWN kᵢ and τᵢ:
──────────────────────────────────────────────────────────────────────────────────

   σᵢ = z·kᵢ + r·τᵢ   mod n

   WHY this formula?
   The full ECDSA equation is: σ = k·(z + r·s) = z·k + r·k·s
   Party i contributes: z·kᵢ (their piece of z·k) + r·τᵢ (their piece of r·k·s)
   Each party uses ONLY their own kᵢ and τᵢ — never the combined k or k·s.

   ─────────────────────────────────────────────────────────────────────
   σᵢ only uses:   kᵢ (Party i's nonce share — never shared)
                   τᵢ (Party i's MtA share — computed locally from MtA output)
                   r  (public — from the contract)
                   z  (public — hash of the message)
   ─────────────────────────────────────────────────────────────────────


STEP 7 ─ Contract combines partial signatures:
───────────────────────────────────────────────

   σ = σ₁ + σ₂ mod n
     = (z·k₁ + r·τ₁) + (z·k₂ + r·τ₂)
     = z·(k₁+k₂) + r·(τ₁+τ₂)
     = z·k         + r·k·s          ← because Σkᵢ=k and Στᵢ=k·s
     = k·(z + r·s)                   ← valid ECDSA!  ✓

   WHY does this work?
   The magic of additive splitting: the sum of partial formulas equals the full formula.
   Just like (2+3)×7 = 2×7 + 3×7, the sigma terms add linearly.
   No party computed k·(z+r·s) directly — but the sum of their pieces equals it exactly.
```

**Why this is valid ECDSA:** In the GG20 protocol, what is called `k` here plays the role of `k⁻¹` in standard ECDSA. The nonce point is `R = k⁻¹·G` (computed via δ⁻¹·Γ). The final signature `σ = k·(z + r·s)` satisfies the standard ECDSA equation because from the verifier's perspective, `R = k_actual·G` where `k_actual = 1/k`, and `σ = k_actual⁻¹·(z + r·s)`. (See Proof 5 and 6 for full verification algebra.)

### Step 5: Any Subset Works

The same process works for ANY 2-of-3 subset. Different Lagrange coefficients, same result:

```
Subset {1,3}: λ₁ = 3/2, λ₃ = -1/2
    x̃₁ + x̃₃ = (3/2)·X₁ + (-1/2)·X₃ = F(0) = s  ✓

Subset {2,3}: λ₂ = 3, λ₃ = -2
    x̃₂ + x̃₃ = 3·X₂ + (-2)·X₃ = F(0) = s  ✓
```

**Same public key. Same Ethereum address. Different parties.**

---

## Deep Dive: γ (Gamma) and δ (Delta) — The Nonce Hiding Trick

This is the most misunderstood part of GG20. Why do we need gamma at all? Why not just submit kᵢ directly and let the contract compute k = Σkᵢ?

> **Short answer:** If k is ever assembled (even by the contract), an attacker can extract the private key.
> Gamma is the elegant solution — it lets the contract compute k⁻¹·G (what it actually needs)
> without k ever existing as a number anywhere.

### The Problem: k Must Never Be Assembled

In standard ECDSA (one party, simple case):

```
k    — a random nonce (known to signer)
R    = k · G        (the nonce point)
r    = R.x mod n
σ    = k⁻¹ · (z + r·s) mod n   ← the signature (standard convention)
```

In GG20 (the convention used throughout this document):

```
k    — nonce (GG20 calls this k, but it plays the role of k⁻¹ from standard ECDSA)
R    = k⁻¹ · G     (the nonce point — same R, different labelling of k)
r    = R.x mod n
σ    = k · (z + r·s) mod n     ← the signature (GG20 convention)
      (because k_GG20 = k_standard⁻¹, so k_GG20·(z+r·s) = k_standard⁻¹·(z+r·s) ✓)
```

In threshold ECDSA, if we let each party submit kᵢ openly:

```
k = k₁ + k₂     ← any observer sees k directly
k⁻¹ computed    ← still ok?
```

**No — k must stay secret forever.** If an attacker sees two different signatures (r₁, σ₁) and (r₂, σ₂) and somehow recovers k, they can solve for the private key:

```
σ₁ = k·(z₁ + r₁·s)
s  = (σ₁/k - z₁) / r₁    ← private key exposed!
```

So k must NEVER be assembled by anyone. But the contract needs to compute R = k⁻¹·G. How?

---

### γᵢ — The Masking Value

**WHY do we need γᵢ at all?**

The contract needs R = k⁻¹·G to produce the signature. The only way to compute this is:
- Option A: Compute k⁻¹ (requires knowing k → private key exposed)
- Option B: Use a mask γ that cancels algebraically → **this is what GG20 does**

Each party introduces a random **masking scalar** γᵢ (gamma_i):

```
Party 1 picks:  k₁ (nonce share)   and   γ₁ (random mask)
Party 2 picks:  k₂ (nonce share)   and   γ₂ (random mask)
```

γᵢ has one job: to let the parties jointly compute k⁻¹·G WITHOUT revealing k.

**WHY is γᵢ random (not derived from something)?**
Gamma must be fresh random every signing session. If it were predictable, the masking trick
fails — an attacker who guesses γ can compute k = δ/γ and then extract the private key.

The trick works because:

```
k · γ  =  (k₁ + k₂) · (γ₁ + γ₂)
       =  k₁γ₁ + k₁γ₂ + k₂γ₁ + k₂γ₂
```

And if we ALSO compute the sum of Γᵢ = γᵢ·G:

```
Γ = Γ₁ + Γ₂  =  γ₁·G + γ₂·G  =  (γ₁ + γ₂)·G  =  γ·G
```

Then:

```
R  =  (k·γ)⁻¹ · Γ
   =  (k·γ)⁻¹ · (γ·G)
   =  k⁻¹ · γ⁻¹ · γ · G
   =  k⁻¹ · G          ← the gamma cancels out!
```

**Nobody computed k⁻¹ as a number.** The contract computed R = k⁻¹·G by combining public EC points (the Γᵢ values) and a publicly-opened scalar (δ = k·γ). The γ masks k in the scalar, then cancels in the EC point.

---

### Γᵢ = γᵢ·G — The Public Version of Gamma

**WHY submit Γᵢ (EC point) and not γᵢ (the scalar directly)?**

Because Γᵢ = γᵢ·G reveals nothing about γᵢ. The discrete logarithm problem makes it
computationally infeasible to go backwards from Γᵢ to γᵢ.

This is the same reason a public key P = s·G is safe to share — you see the point, not the scalar.

```
Safe to share:    Γᵢ = γᵢ · G    ← EC point (33 bytes, on the curve)
NEVER share:      γᵢ              ← the actual scalar that generated it
```

Each party publishes their Γᵢ point on-chain:

```
Party 1 submits: Γ₁ = γ₁ · G       (a compressed EC point, 33 bytes)
Party 2 submits: Γ₂ = γ₂ · G       (a compressed EC point, 33 bytes)
```

The contract adds them:

```
Γ = Γ₁ + Γ₂ = (γ₁ + γ₂) · G = γ · G
```

Nobody learns γ₁ or γ₂ from seeing Γ₁ and Γ₂ — discrete log is computationally infeasible.
Nobody learns γ from seeing Γ = γ·G either.

So γ (the actual masking scalar) is secret. Γ (its EC point image) is public and safe.

**WHY is the EC point version useful?**
Because EC points support addition: Γ₁ + Γ₂ = (γ₁+γ₂)·G = γ·G. The contract can combine
the Γᵢ points to get γ·G without ever knowing γ — exactly what it needs for the cancellation trick.

---

### δᵢ — The Share of k·γ

**WHY do we need δᵢ at all? What is it for?**

The contract needs to compute δ⁻¹ (the modular inverse of k·γ) to get R = δ⁻¹·Γ = k⁻¹·G.
So δ = k·γ must be computed and opened publicly.
But neither party can compute k·γ alone — Party 1 only has k₁ and γ₁, not k₂ and γ₂.
So MtA is used to split the cross-products, and δᵢ accumulates all pieces for party i.

Each party computes their **δᵢ** (delta_i), which is their additive share of the product k·γ.

For 2 parties:

```
k · γ = (k₁ + k₂)(γ₁ + γ₂)
      = k₁γ₁ + k₁γ₂ + k₂γ₁ + k₂γ₂
```

Each party starts with their own self-product, then adds MtA cross-terms for the cross products:

```
δ₁ = k₁·γ₁  +  MtA(k₁, γ₂) share for party 1  +  MtA(k₂, γ₁) share for party 1
           ╰──────── k₁γ₁ (self) ───────────╯    ╰── α₁₂ ──╯               ╰── β₂₁ ──╯

δ₂ = k₂·γ₂  +  MtA(k₁, γ₂) share for party 2  +  MtA(k₂, γ₁) share for party 2
           ╰──────── k₂γ₂ (self) ───────────╯    ╰── β₁₂ ──╯               ╰── α₂₁ ──╯
```

Where MtA(a, b) splits a·b into two additive pieces α + β = a·b, using Paillier encryption so neither party sees both.

The key property:

```
δ₁ + δ₂  =  k₁γ₁ + k₁γ₂ + k₂γ₁ + k₂γ₂
           =  (k₁+k₂)(γ₁+γ₂)
           =  k · γ
```

So δ = δ₁ + δ₂ is the product k·γ, assembled from additive shares. It's safe to open this product because:

- Seeing k·γ tells you nothing about k (γ is a random mask you don't know)
- Seeing k·γ tells you nothing about γ either (k is a random mask you don't know)
- You'd need to know one to find the other — and both are secret

---

### The Full Gamma-Delta Cancellation — Step by Step

```
WHAT PARTIES DO:

    Party 1: knows k₁, γ₁
    Party 2: knows k₂, γ₂

WHAT PARTIES COMPUTE (via MtA):

    δ₁, δ₂  such that  δ₁ + δ₂ = k·γ

WHAT PARTIES SUBMIT TO CONTRACT:

    δ₁, δ₂   (the delta shares  — scalar values, 32 bytes each)
    Γ₁, Γ₂   (the gamma points  — EC points, 33 bytes each compressed)

WHAT CONTRACT COMPUTES:

    δ   = δ₁ + δ₂           = k·γ           (scalar, safe to open)
    Γ   = Γ₁ + Γ₂           = γ·G           (EC point)
    δ⁻¹ = modular inverse of δ mod n        (scalar)
    R   = δ⁻¹ · Γ

EXPAND R:

    R = δ⁻¹ · Γ
      = (k·γ)⁻¹ · (γ·G)
      = (1/(k·γ)) · (γ·G)
      = (γ/(k·γ)) · G
      = (1/k) · G
      = k⁻¹ · G              ← the γ cancels! ✓

    r = R.x mod n            (the r value of the ECDSA signature)

WHAT CONTRACT LEARNED:

    R and r — yes, these are the signature's r component (public)
    k       — NO (was never computed as a number by anyone)
    k⁻¹     — NO (was never computed as a number by anyone)
    γ       — NO (never opened)
    k₁, k₂  — NO (never opened)
    γ₁, γ₂  — NO (never opened)
```

---

### Why Is It Safe to Open δ = k·γ?

Opening δ means every observer can compute:

```
δ = k · γ    ← attacker sees this
```

Can they recover k?

```
k = δ / γ
```

But they don't know γ! γ is the sum of two random secrets (γ₁ from Party 1, γ₂ from Party 2), each discarded after this signing round. γ is as secret as a private key.

Can they recover γ?

```
γ = δ / k
```

But they don't know k either! k is the sum of two random secrets (k₁, k₂), never assembled by anyone.

**It's a chicken-and-egg secret.** You need one to find the other, and both are unknown. This is why opening k·γ is safe.

---

### Worked Numeric Example: Gamma Cancellation

Use small numbers (real crypto uses 256-bit integers mod n):

```
Setup (2-of-3, parties 1 and 2 signing):

    k₁ = 3,   γ₁ = 5    (Party 1's secrets)
    k₂ = 4,   γ₂ = 2    (Party 2's secrets)

    k  = k₁ + k₂ = 7    ← NEVER COMPUTED by anyone
    γ  = γ₁ + γ₂ = 7    ← NEVER COMPUTED by anyone

---
Step 1: Each party computes their self-product:

    k₁ · γ₁ = 3 · 5 = 15
    k₂ · γ₂ = 4 · 2 = 8

---
Step 2: MtA cross-products

    MtA(k₁=3, γ₂=2):  3 · 2 = 6  →  α₁₂ + β₁₂ = 6
                                       e.g. α₁₂ = 2,  β₁₂ = 4

    MtA(k₂=4, γ₁=5):  4 · 5 = 20 →  α₂₁ + β₂₁ = 20
                                       e.g. α₂₁ = 9,  β₂₁ = 11

    (Party 1 gets α₁₂ and β₂₁;  Party 2 gets β₁₂ and α₂₁)

---
Step 3: Each party computes their delta share:

    δ₁ = k₁γ₁ + α₁₂ + β₂₁ = 15 + 2 + 11 = 28
    δ₂ = k₂γ₂ + β₁₂ + α₂₁ = 8  + 4 + 9  = 21

---
Step 4: Contract opens delta:

    δ = δ₁ + δ₂ = 28 + 21 = 49

    Check: k · γ = 7 · 7 = 49  ✓

---
Step 5: Each party computes their gamma point:

    Γ₁ = γ₁ · G = 5·G
    Γ₂ = γ₂ · G = 2·G

    Contract: Γ = Γ₁ + Γ₂ = 5·G + 2·G = 7·G = γ·G  ✓

---
Step 6: Contract computes R (the nonce point):

    δ⁻¹ = 49⁻¹ mod n   (modular inverse)
    R    = δ⁻¹ · Γ
         = 49⁻¹ · 7·G
         = (7/49) · G
         = (1/7) · G
         = k⁻¹ · G        ← because k=7, so k⁻¹ = 1/7  ✓

---
Attacker sees: δ=49, Γ=7·G, R=k⁻¹·G, r=R.x
Attacker CANNOT find: k=7, γ=7, k⁻¹ as a number
    (they'd need k=δ/γ but don't know γ; or γ=δ/k but don't know k)
```

---

### Summary: What Each Variable Does in Signing

```
┌─────────┬───────────────────────────────────────────────────────┐
│ Variable│ Job                                                   │
├─────────┼───────────────────────────────────────────────────────┤
│  kᵢ     │ Party i's secret nonce share. Never opened.           │
│         │ k = Σkᵢ is never assembled by anyone.                 │
├─────────┼───────────────────────────────────────────────────────┤
│  γᵢ     │ Party i's random masking scalar. Never opened.        │
│         │ Exists ONLY to hide k in the product k·γ.             │
│         │ Discarded after this signing round.                   │
├─────────┼───────────────────────────────────────────────────────┤
│  Γᵢ     │ γᵢ·G  — the public EC point version of γᵢ.           │
│         │ Safe to submit on-chain (discrete log hides γᵢ).      │
│         │ Contract adds them: Γ = Σ Γᵢ = γ·G                   │
├─────────┼───────────────────────────────────────────────────────┤
│  δᵢ     │ Party i's additive share of k·γ (via MtA).            │
│         │ Contract adds them: δ = Σ δᵢ = k·γ                   │
│         │ Safe to open (γ masks k; k masks γ).                  │
├─────────┼───────────────────────────────────────────────────────┤
│  δ      │ k·γ — opened publicly on-chain.                       │
│         │ Nobody learns k from seeing k·γ (γ is unknown).       │
├─────────┼───────────────────────────────────────────────────────┤
│  Γ      │ γ·G — the combined gamma point (public).              │
├─────────┼───────────────────────────────────────────────────────┤
│  R      │ δ⁻¹·Γ = (k·γ)⁻¹·(γ·G) = k⁻¹·G                      │
│         │ The ECDSA nonce point. γ cancels.                      │
│         │ k⁻¹ never computed as a scalar. Never known.          │
├─────────┼───────────────────────────────────────────────────────┤
│  r      │ R.x mod n — the r value of the ECDSA signature.       │
│         │ Part of the final (r, σ) signature pair.              │
└─────────┴───────────────────────────────────────────────────────┘
```

---

## Worked Example — Full Flow with Real Numbers

We'll use small numbers for clarity. In real crypto, all numbers are 256-bit integers mod n.

### DKG with Numbers

**Setup: 3 parties, threshold 2.**

**Round 1: Each party picks independently**

```
Party 1: picks s₁ = 3, a₁ = 2  →  f₁(x) = 3 + 2x
Party 2: picks s₂ = 5, a₂ = 1  →  f₂(x) = 5 + 1x
Party 3: picks s₃ = 4, a₃ = 3  →  f₃(x) = 4 + 3x

Combined secret: s = s₁ + s₂ + s₃ = 3 + 5 + 4 = 12
Combined polynomial: F(x) = f₁(x)+f₂(x)+f₃(x) = 12 + 6x

NOBODY computes 12. It's a ghost.
```

**Round 2: Feldman commitments (on-chain)**

```
Party 1 publishes: C₁₀ = 3·G,   C₁₁ = 2·G
Party 2 publishes: C₂₀ = 5·G,   C₂₁ = 1·G
Party 3 publishes: C₃₀ = 4·G,   C₃₁ = 3·G
```

**Round 3: Sub-share distribution (secret)**

```
Party 1 evaluates f₁(x) = 3 + 2x:
    f₁(1) = 3 + 2(1) = 5   →  keeps for self
    f₁(2) = 3 + 2(2) = 7   →  sends to Party 2 (encrypted)
    f₁(3) = 3 + 2(3) = 9   →  sends to Party 3 (encrypted)

Party 2 evaluates f₂(x) = 5 + 1x:
    f₂(1) = 5 + 1(1) = 6   →  sends to Party 1 (encrypted)
    f₂(2) = 5 + 1(2) = 7   →  keeps for self
    f₂(3) = 5 + 1(3) = 8   →  sends to Party 3 (encrypted)

Party 3 evaluates f₃(x) = 4 + 3x:
    f₃(1) = 4 + 3(1) = 7   →  sends to Party 1 (encrypted)
    f₃(2) = 4 + 3(2) = 10  →  sends to Party 2 (encrypted)
    f₃(3) = 4 + 3(3) = 13  →  keeps for self
```

**Round 4: Feldman verification**

Party 2 received f₁(2) = 7 from Party 1. Verify:

```
Left:   f₁(2) · G = 7·G
Right:  C₁₀ + 2·C₁₁ = 3·G + 2·(2·G) = 3·G + 4·G = 7·G  ✓  (match!)
```

Party 1 received f₃(1) = 7 from Party 3. Verify:

```
Left:   f₃(1) · G = 7·G
Right:  C₃₀ + 1·C₃₁ = 4·G + 1·(3·G) = 4·G + 3·G = 7·G  ✓  (match!)
```

All 9 sub-shares verified. No cheating detected.

**Round 5: Combine into final shares**

```
X₁ = f₁(1) + f₂(1) + f₃(1) = 5 + 6 + 7  = 18
X₂ = f₁(2) + f₂(2) + f₃(2) = 7 + 7 + 10 = 24
X₃ = f₁(3) + f₂(3) + f₃(3) = 9 + 8 + 13 = 30
```

**Verify: These are points on the combined polynomial F(x) = 12 + 6x:**

```
F(1) = 12 + 6(1) = 18 = X₁  ✓
F(2) = 12 + 6(2) = 24 = X₂  ✓
F(3) = 12 + 6(3) = 30 = X₃  ✓
F(0) = 12 = s  (the secret, NEVER computed)  ✓
```

**Combined public key:**

```
P = C₁₀ + C₂₀ + C₃₀ = 3·G + 5·G + 4·G = 12·G = s·G  ✓
```

### Threshold Signing with Numbers

**Signing with subset {1, 2} (Party 3 is offline)**

**Step 1: Lagrange coefficients for {1, 2}:**

```
λ₁ = (0 - 2)/(1 - 2) = (-2)/(-1) = 2
λ₂ = (0 - 1)/(2 - 1) = (-1)/(1)  = -1
```

**Step 2: Adjust shares:**

```
x̃₁ = λ₁ · X₁ = 2 × 18 = 36
x̃₂ = λ₂ · X₂ = (-1) × 24 = -24
```

**Step 3: Verify — adjusted shares sum to secret:**

```
x̃₁ + x̃₂ = 36 + (-24) = 12 = s  ✓
```

The private key 12 is NEVER computed by any party. Party 1 only knows x̃₁ = 36. Party 2 only knows x̃₂ = -24. Neither can determine that the sum is 12.

**Step 4: GG20 signing uses x̃₁ and x̃₂ as the "effective key shares":**

```
Party 1 computes partial sig using x̃₁ = 36
Party 2 computes partial sig using x̃₂ = -24
Contract combines → σ = k⁻¹(z + r·(x̃₁ + x̃₂)) = k⁻¹(z + r·12) = k⁻¹(z + r·s)  ✓
```

Valid ECDSA signature for the key with private key 12, produced without either party knowing 12.

### Signing with a Different Subset: {1, 3}

```
λ₁ = (0-3)/(1-3) = (-3)/(-2) = 3/2
λ₃ = (0-1)/(3-1) = (-1)/(2) = -1/2

x̃₁ = (3/2) × 18 = 27
x̃₃ = (-1/2) × 30 = -15

x̃₁ + x̃₃ = 27 + (-15) = 12 = s  ✓
```

### Signing with Subset {2, 3}

```
λ₂ = (0-3)/(2-3) = (-3)/(-1) = 3
λ₃ = (0-2)/(3-2) = (-2)/(1) = -2

x̃₂ = 3 × 24 = 72
x̃₃ = (-2) × 30 = -60

x̃₂ + x̃₃ = 72 + (-60) = 12 = s  ✓
```

**Every 2-of-3 subset reconstructs the same secret 12. Same public key. Same Ethereum address.**

### What About 1 Party Alone?

Party 1 has X₁ = 18. Can they figure out s = 12?

Party 1 knows X₁ is on the line F(x) = s + bx, where F(1) = 18.
So s + b = 18, meaning s = 18 - b.

But b could be anything! If b = 6, then s = 12. If b = 10, then s = 8. If b = 100, then s = -82. Infinitely many possible lines pass through the single point (1, 18). Party 1 learns absolutely nothing about s.

**This is the core of Shamir's threshold security: t-1 parties learn nothing.**

---

## Visual Guide — ASCII Art Diagrams

### Diagram 1: Pedersen/Feldman DKG — Full Flow

```
    Party 1                      Party 2                      Party 3
    ────────                     ────────                     ────────
    picks s₁, a₁                 picks s₂, a₂                 picks s₃, a₃
    (TWO random numbers)         (TWO random numbers)         (TWO random numbers)
    f₁(x) = s₁ + a₁·x          f₂(x) = s₂ + a₂·x          f₃(x) = s₃ + a₃·x
         │                            │                            │
         │  s₁·G, a₁·G               │  s₂·G, a₂·G               │  s₃·G, a₃·G
         │  (Feldman commits)         │  (Feldman commits)         │  (Feldman commits)
         ▼                            ▼                            ▼
        C₁₀, C₁₁                    C₂₀, C₂₁                    C₃₀, C₃₁
         │                            │                            │
    ┌────┴────────────────────────────┴────────────────────────────┴────┐
    │                PARTISIA CONTRACT — Commit Phase                    │
    │    Stores hash(C₁₀‖C₁₁), hash(C₂₀‖C₂₁), hash(C₃₀‖C₃₁)         │
    │    Nobody can change their commitments now.                       │
    └────┬────────────────────────────┬────────────────────────────┬────┘
         │ reveal C₁₀,C₁₁            │ reveal C₂₀,C₂₁            │ reveal C₃₀,C₃₁
         ▼                            ▼                            ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                PARTISIA CONTRACT — Reveal Phase                   │
    │    Verifies each set of commitments matches its hash.            │
    │    All commitments now public on-chain.                          │
    └──────────────────────────────────────────────────────────────────┘
         │                            │                            │
         │ SECRETLY via ZK:           │ SECRETLY via ZK:           │ SECRETLY via ZK:
         │ f₁(2) → Party 2           │ f₂(1) → Party 1           │ f₃(1) → Party 1
         │ f₁(3) → Party 3           │ f₂(3) → Party 3           │ f₃(2) → Party 2
         ▼                            ▼                            ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                    ZK NODES — Verify & Combine                   │
    │                                                                  │
    │  For each sub-share fᵢ(j):                                      │
    │      Check: fᵢ(j)·G == Cᵢ₀ + j·Cᵢ₁  (Feldman verification)    │
    │      If fails → ABORT (Party i is cheating)                      │
    │                                                                  │
    │  All pass? Compute final shares:                                 │
    │      X₁ = f₁(1) + f₂(1) + f₃(1)                                │
    │      X₂ = f₁(2) + f₂(2) + f₃(2)                                │
    │      X₃ = f₁(3) + f₂(3) + f₃(3)                                │
    │                                                                  │
    │  Store X₁, X₂, X₃ as encrypted ZK secrets (one per node)        │
    └──────────────────────────┬───────────────────────────────────────┘
                               │
                               │  Combined Public Key (on-chain)
                               │  P = C₁₀ + C₂₀ + C₃₀ = s·G
                               ▼
                    ┌─────────────────────┐
                    │  Combined Public    │
                    │  Key P = s·G        │
                    │                     │
                    │  Ethereum address   │
                    │  derived from P     │
                    │                     │
                    │  s NEVER computed   │
                    │  by anyone, ever    │
                    └─────────────────────┘
```

### Diagram 2: Threshold Signing — 2 of 3 Parties

```
    Party 3 is OFFLINE ───────────────────── doesn't matter!

    Party 1                                  Party 2
    ────────                                 ────────
    Has: X₁ (Shamir share)                  Has: X₂ (Shamir share)
         │                                        │
         │  Compute Lagrange coeff               │  Compute Lagrange coeff
         │  λ₁ = 2 (for subset {1,2})            │  λ₂ = n-1 (for subset {1,2})
         │                                        │
         │  Adjust share:                         │  Adjust share:
         │  x̃₁ = 2 · X₁                          │  x̃₂ = (n-1) · X₂
         │                                        │
         │  (x̃₁ + x̃₂ = s, but                    │
         │   neither party computes this)         │
         ▼                                        ▼
    ═══════════════════════════════════════════════════════
    GG20 ROUND 1: BUILD THE NONCE (same as README.md)
    ═══════════════════════════════════════════════════════

    picks k₁, γ₁                            picks k₂, γ₂
         │                                        │
         │ Γ₁ = γ₁·G                              │ Γ₂ = γ₂·G
         │                                        │
         │   ┌─── MtA (Paillier encrypted) ───┐   │
         │   │  k₁×γ₂ → α₁₂ + β₁₂            │   │
         │   │  k₂×γ₁ → α₂₁ + β₂₁            │   │
         │   │  k₁×x̃₂ → μ₁₂ + ν₁₂           │   │
         │   │  k₂×x̃₁ → μ₂₁ + ν₂₁           │   │
         │   └─────────────────────────────────┘   │
         │                                        │
         │  δ₁ = k₁γ₁ + MtA terms               │  δ₂ = k₂γ₂ + MtA terms
         ▼                                        ▼
    ┌──────────────────────────────────────────────────────┐
    │  CONTRACT collects δ₁, δ₂ and Γ₁, Γ₂                │
    │                                                      │
    │  δ = δ₁ + δ₂ = k×γ                                  │
    │  Γ = Γ₁ + Γ₂ = γ·G                                  │
    │  R = δ⁻¹ × Γ = k⁻¹·G      ← γ cancels out!         │
    │  r = R.x mod n                                       │
    └──────────────────────┬───────────────────────────────┘
                           │
    ═══════════════════════════════════════════════════════
    GG20 ROUND 2: PARTIAL SIGNATURES
    ═══════════════════════════════════════════════════════
                           │
    Party 1                │                 Party 2
    has: x̃₁, k₁, τ₁, r, z │                 has: x̃₂, k₂, τ₂, r, z
    (τ₁ = MtA share        │                 (τ₂ = MtA share
     of k×x̃, from step 3) │                  of k×x̃, from step 3)
         │                 │                      │
         │ σ₁ = z·k₁ +    │                      │ σ₂ = z·k₂ +
         │       r·τ₁      │                      │       r·τ₂
         ▼                 │                      ▼
    ┌──────────────────────▼──────────────────────────────┐
    │  CONTRACT combines:                                  │
    │     σ = σ₁ + σ₂ mod n                                │
    │                                                      │
    │  Why this works (GG20 convention):                   │
    │     σ = (z·k₁ + r·τ₁) + (z·k₂ + r·τ₂)             │
    │       = z·(k₁+k₂)  + r·(τ₁+τ₂)                     │
    │       = z·k         + r·k·s     (since Στᵢ = k·s)   │
    │       = k·(z + r·s)  ← valid ECDSA! ✓               │
    │                                                      │
    │  (In GG20, R = k⁻¹·G, so σ = k·(z+r·s) is correct  │
    │   — same as standard σ = k_ecdsa⁻¹·(z+r·s))        │
    │                                                      │
    │  ECDSA verify(P, z, r, σ) → ✓ VALID!                │
    │  Party 3 was never involved. Key never assembled.    │
    └──────────────────────────────────────────────────────┘
```

### Diagram 3: Why Lagrange Coefficients Change Per Subset

```
    The combined polynomial: F(x) = 12 + 6x  (secret = 12 at x=0)

    Points on the line:
        X₁ = F(1) = 18    at x = 1
        X₂ = F(2) = 24    at x = 2
        X₃ = F(3) = 30    at x = 3

    ═══════════════════════════════════════════════════════
    SUBSET {1, 2}: Use points (1, 18) and (2, 24)
    ═══════════════════════════════════════════════════════

        λ₁ = (0-2)/(1-2) = 2       λ₂ = (0-1)/(2-1) = -1

        Reconstruction:
            λ₁·X₁ + λ₂·X₂ = 2·18 + (-1)·24 = 36 - 24 = 12 = s  ✓


    ═══════════════════════════════════════════════════════
    SUBSET {1, 3}: Use points (1, 18) and (3, 30)
    ═══════════════════════════════════════════════════════

        λ₁ = (0-3)/(1-3) = 3/2     λ₃ = (0-1)/(3-1) = -1/2

        Reconstruction:
            λ₁·X₁ + λ₃·X₃ = (3/2)·18 + (-1/2)·30 = 27 - 15 = 12 = s  ✓


    ═══════════════════════════════════════════════════════
    SUBSET {2, 3}: Use points (2, 24) and (3, 30)
    ═══════════════════════════════════════════════════════

        λ₂ = (0-3)/(2-3) = 3       λ₃ = (0-2)/(3-2) = -2

        Reconstruction:
            λ₂·X₂ + λ₃·X₃ = 3·24 + (-2)·30 = 72 - 60 = 12 = s  ✓


    Different weights, same answer. EVERY 2-of-3 subset works!
```

### Diagram 4: Feldman Verification — Catching a Cheater

```
    ═══════════════════════════════════════════════════════
    HONEST Party 1: f₁(x) = 3 + 2x
    ═══════════════════════════════════════════════════════

    Publishes: C₁₀ = 3·G, C₁₁ = 2·G

    Sends f₁(2) = 7 to Party 2

    Party 2 checks:
        Left:   7·G
        Right:  C₁₀ + 2·C₁₁ = 3·G + 2·(2·G) = 7·G
        7·G == 7·G  ✓  MATCH — sub-share is valid


    ═══════════════════════════════════════════════════════
    CHEATING Party 1: commits f₁(x) = 3 + 2x but sends WRONG value
    ═══════════════════════════════════════════════════════

    Publishes: C₁₀ = 3·G, C₁₁ = 2·G  (locked in by hash commitment)

    Sends f₁(2) = 99 to Party 2  (WRONG — real value is 7)

    Party 2 checks:
        Left:   99·G
        Right:  C₁₀ + 2·C₁₁ = 3·G + 2·(2·G) = 7·G
        99·G ≠ 7·G  ✗  MISMATCH — CAUGHT! DKG ABORTS!


    Party 1 cannot cheat because:
    ✗ Cannot change C₁₀, C₁₁ (already committed via hash)
    ✗ Cannot send wrong sub-share (Feldman verification catches it)
    ✗ Cannot learn s₂ from C₂₀ = s₂·G (discrete log is impossible)
```

### Diagram 5: What Each Party Knows — Zero Coordinator

```
    ┌──────────────────────────────────────────────────────────────┐
    │                    KNOWLEDGE MAP                              │
    │                                                              │
    │           Public          Secret         Would Need          │
    │           (everyone)      (only them)    (to steal key)      │
    │                                                              │
    │  Party 1: P, all Cᵢⱼ     s₁, a₁, X₁    X₂ (or X₃)         │
    │           Γ₁, Γ₂         f₁(·)          + 1 other share     │
    │           r, z, σ                                            │
    │                                                              │
    │  Party 2: P, all Cᵢⱼ     s₂, a₂, X₂    X₁ (or X₃)         │
    │           Γ₁, Γ₂         f₂(·)          + 1 other share     │
    │           r, z, σ                                            │
    │                                                              │
    │  Party 3: P, all Cᵢⱼ     s₃, a₃, X₃    X₁ (or X₂)         │
    │           (offline)       f₃(·)          + 1 other share     │
    │                                                              │
    │  Contract: P, all Cᵢⱼ    nothing         ALL 3 of:          │
    │            δ, Γ, R       (just math)     X₁, X₂, X₃         │
    │            r, σ, z                       (from 3 ZK nodes)   │
    │                                                              │
    │  ZK Node 1: encrypted    fragment of     decryption keys     │
    │             ciphertexts  X₁ only         of other 2 nodes    │
    │                                                              │
    │  Coordinator: DOES NOT EXIST                                 │
    │                                                              │
    │  Attacker needs: 2 of {X₁, X₂, X₃} from 2 different        │
    │                  ZK node clusters  (breach 2 of 3 nodes)     │
    └──────────────────────────────────────────────────────────────┘
```

### Diagram 6: Full Transaction Flow — Bird's Eye View

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                 PEDERSEN/FELDMAN DKG PHASE                      │
    │                                                                 │
    │  Tx 1:   Create key slot (threshold=2, parties=3)               │
    │                                                                 │
    │  Tx 2-4: Each party commits hash(Cᵢ₀ ‖ Cᵢ₁)                   │
    │          (Feldman commitment hashes — locked in)                │
    │                                                                 │
    │  Tx 5-7: Each party reveals Cᵢ₀, Cᵢ₁                          │
    │          (Contract verifies against committed hashes)           │
    │                                                                 │
    │  Tx 8-16: Each party sends 3 sub-shares as ZK secrets          │
    │           (9 total: fᵢ(j) for all i,j ∈ {1,2,3})              │
    │                                                                 │
    │  ZK nodes: Feldman verify all sub-shares                       │
    │            Combine: Xⱼ = Σᵢ fᵢ(j) for each party j            │
    │                                                                 │
    │  Tx 17:  Finalize DKG                                          │
    │          P = λ₁·(X₁·G) + λ₂·(X₂·G) + λ₃·(X₃·G)              │
    │          (Lagrange interpolation → master public key)           │
    │                                                                 │
    │  Tx 18:  Complete keygen → ready for signing ✓                  │
    └────────────────────────────────┬────────────────────────────────┘
                                     │
                                     ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │              THRESHOLD SIGNING PHASE (2 of 3)                   │
    │              Party 3 is offline — no problem!                    │
    │                                                                 │
    │  Tx 19:  Start signing with message hash z                      │
    │          signingParties = [1, 2]                                 │
    │                                                                 │
    │  Client: Compute λ₁=2, λ₂=n-1 for subset {1,2}                │
    │          Adjust: x̃₁ = 2·X₁,  x̃₂ = (n-1)·X₂                   │
    │          Run GG20 with x̃₁, x̃₂ (MtA, deltas, gammas)           │
    │                                                                 │
    │  Tx 20:  GG20 start (num_parties=2, NOT 3)                      │
    │                                                                 │
    │  Tx 21-22: Submit δ₁, δ₂ (delta shares)                        │
    │  Tx 23-24: Submit Γ₁, Γ₂ (gamma points)                        │
    │  Tx 25:    Finalize R = δ⁻¹·Γ = k⁻¹·G, extract r              │
    │                                                                 │
    │  Tx 26-27: Commit hash(σ₁), hash(σ₂)                           │
    │  Tx 28-29: Reveal σ₁, σ₂ (partial signatures)                  │
    │                                                                 │
    │  Contract: σ = σ₁ + σ₂ = k⁻¹(z + r·s)                         │
    │            ECDSA verify(P, z, r, σ) → ✓ VALID!                  │
    └────────────────────────────────┬────────────────────────────────┘
                                     │
                                     ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    ETHEREUM TRANSACTION                         │
    │                                                                 │
    │  Signature (r, σ) produced by 2 parties on Partisia             │
    │       + EVM transaction data                                    │
    │       = valid Ethereum transaction                              │
    │                                                                 │
    │  The Ethereum network verifies (r, σ) against P                 │
    │  and accepts it. It has NO IDEA:                                │
    │    - The private key never existed                              │
    │    - Only 2 of 3 parties signed                                 │
    │    - The 3rd party was offline                                  │
    │    - The key was born split via Shamir polynomials              │
    └─────────────────────────────────────────────────────────────────┘
```

---

## Math Proofs — Why Everything Works

### Proof 1: Lagrange Interpolation Reconstructs the Secret

**Given:** A degree-1 polynomial F(x) = s + bx (where b = a₁+a₂+a₃ and s = s₁+s₂+s₃)

**Given:** Two points (i, Xᵢ) and (j, Xⱼ) on this polynomial.

**Claim:** λᵢ·Xᵢ + λⱼ·Xⱼ = F(0) = s, where λᵢ = -j/(i-j), λⱼ = -i/(j-i).

**Proof:**

```
λᵢ·Xᵢ + λⱼ·Xⱼ
= λᵢ·F(i) + λⱼ·F(j)
= λᵢ·(s + b·i) + λⱼ·(s + b·j)
= s·(λᵢ + λⱼ) + b·(λᵢ·i + λⱼ·j)

For this to equal s, we need:
    (1) λᵢ + λⱼ = 1          (coefficients of s sum to 1)
    (2) λᵢ·i + λⱼ·j = 0      (coefficients of b sum to 0)

Verify for subset {1, 2}:
    λ₁ = (0-2)/(1-2) = 2     λ₂ = (0-1)/(2-1) = -1

    (1) λ₁ + λ₂ = 2 + (-1) = 1  ✓
    (2) λ₁·1 + λ₂·2 = 2·1 + (-1)·2 = 2 - 2 = 0  ✓

Therefore: λ₁·X₁ + λ₂·X₂ = s·1 + b·0 = s  ✓

This holds for ANY degree-1 polynomial and ANY 2-point subset.  □
```

### Proof 2: Feldman Commitments Prevent Cheating

**Claim:** If Party i publishes Cᵢ₀ = sᵢ·G and Cᵢ₁ = aᵢ·G, then any recipient can verify fᵢ(j) without learning sᵢ or aᵢ.

**Proof:**

```
fᵢ(j) = sᵢ + aᵢ·j   (definition of polynomial evaluation)

Multiply both sides by G:
fᵢ(j)·G = sᵢ·G + aᵢ·j·G = Cᵢ₀ + j·Cᵢ₁

The verifier computes:
    Left:   fᵢ(j)·G           (from the received sub-share)
    Right:  Cᵢ₀ + j·Cᵢ₁       (from public Feldman commitments)

If Party i sent the correct fᵢ(j): Left == Right  ✓
If Party i sent a wrong value v ≠ fᵢ(j): v·G ≠ fᵢ(j)·G  ✗
    (because EC point multiplication is injective: a ≠ b → a·G ≠ b·G)

The verifier learns nothing about sᵢ because:
    Cᵢ₀ = sᵢ·G → finding sᵢ requires solving the discrete log
    problem, which is computationally infeasible on secp256k1.  □
```

### Proof 3: The Combined Polynomial Has the Right Structure

**Claim:** If F(x) = f₁(x) + f₂(x) + f₃(x), then F(0) = s₁+s₂+s₃ and F is degree-1.

**Proof:**

```
f₁(x) = s₁ + a₁·x     (degree 1)
f₂(x) = s₂ + a₂·x     (degree 1)
f₃(x) = s₃ + a₃·x     (degree 1)

F(x) = f₁(x) + f₂(x) + f₃(x)
     = (s₁+s₂+s₃) + (a₁+a₂+a₃)·x
     = s + b·x          where s = s₁+s₂+s₃, b = a₁+a₂+a₃

F is degree-1 (sum of degree-1 polynomials is degree-1)  ✓
F(0) = s = s₁+s₂+s₃  (the combined secret)  ✓
Any 2 evaluations of F determine it uniquely  ✓
    → any 2 shares reconstruct s via Lagrange  □
```

### Proof 4: Threshold Signing Produces Valid ECDSA

**Claim:** If each signing party uses adjusted share x̃ᵢ = λᵢ·Xᵢ in GG20, the combined signature is valid ECDSA.

**Proof (using GG20 convention where R = k⁻¹·G):**

```
Standard ECDSA: σ = k·(z + r·s) mod n
    (where k here is what ECDSA calls k⁻¹ — see Proof 5 for full verification)

With 2-of-3 threshold (subset S):
    Σᵢ∈S x̃ᵢ = Σᵢ∈S λᵢ·Xᵢ = s       (by Lagrange interpolation)

Each party computes intermediate τᵢ (additive share of k×x̃):
    τᵢ = kᵢ·x̃ᵢ + MtA cross-terms

Property: Σ τᵢ = k · (Σ x̃ᵢ) = k · s

Each party computes partial signature:
    σᵢ = z·kᵢ + r·τᵢ

Sum:
    Σσᵢ = z·(Σkᵢ) + r·(Στᵢ)
         = z·k     + r·k·s           (Σkᵢ=k, Στᵢ=k·s)
         = k·(z + r·s)               ← valid ECDSA!  ✓

From the Ethereum verifier's perspective (Proof 5):
    R = k⁻¹·G  →  k_ecdsa = 1/k  →  σ_ecdsa = k_ecdsa⁻¹·(z+r·s) = k·(z+r·s)  ✓

The signature is mathematically identical to what a single signer
with private key s would produce. Ethereum cannot tell the difference.  □
```

### Proof 5: Complete ECDSA Signature Verification — Every Step Open

This section explains everything from the ground up: the curve equation, what a public key is, how a signature is created, and exactly how Ethereum verifies it — with every single step explained in plain language and backed by algebra.

---

#### Part A — The Curve: What secp256k1 Actually Is

ECDSA does not work on regular numbers. It works on **points on an elliptic curve**. The curve used by Ethereum and Bitcoin is called **secp256k1**, defined by this equation:

```
y² = x³ + 7   (mod p)

where p = 2²⁵⁶ − 2³² − 977   (a specific huge prime number, ~10⁷⁷)
```

Every valid "point" in the system is a pair (x, y) that satisfies this equation. For example, if x = 5, then y² = 5³ + 7 = 132, and y = √132 mod p. If that square root exists mod p, then (5, √132 mod p) is a valid point on the curve.

**What the curve looks like (conceptual — over real numbers, not mod p):**

```
    y
    │
    │          *  *
    │        *      *
    │       *        *
    │        *      *
    │─────────*──────── x
    │       *
    │      *
    │     *
    │      *
    │
    │   y² = x³ + 7
```

Over real numbers it looks like that smooth S-shape. Over the finite field mod p, it becomes a scattered set of ~10⁷⁷ discrete (x, y) integer pairs. But the math works the same way.

**Three critical properties of this curve:**

```
Property 1: POINT ADDITION
    Take any two points A and B on the curve.
    Draw a line through them. That line hits the curve at a third point.
    Reflect that third point over the x-axis → you get C = A + B.
    C is also on the curve. Always.

Property 2: POINT MULTIPLICATION (scalar × point)
    n × P  means "add P to itself n times"
    3 × P  =  P + P + P
    This is very fast to compute forward (n × P → result).
    IMPOSSIBLE to reverse: given the result, you cannot find n.
    This is the "discrete logarithm problem" — hardness of secp256k1.

Property 3: THE GENERATOR POINT G
    One specific point on the curve is chosen as the "starting point": G.
    It is fixed and public. Everyone uses the same G.
    G = (x_G, y_G) where both are known 256-bit numbers.
    All public keys are computed as: P = s × G  (s = secret scalar).
```

**Why "multiply by G" hides the secret:**

```
    s = 12  (your private key — a number)
    P = 12 × G  (your public key — a point on the curve)

    Given P and G, finding 12 is the discrete log problem.
    On secp256k1 with p ≈ 10⁷⁷, this is computationally infeasible.
    That's the entire security of the system.

    Forward:  12 × G = P   ← trivial (just add G twelve times)
    Reverse:  P / G = ?    ← infeasible (no division on EC points)
```

---

#### Part B — The Three Numbers in an ECDSA Signature

Before signing, everyone agrees on:
- `G` — the generator point (fixed, public)
- `n` — the curve order (number of valid points, ≈ 2²⁵⁶, fixed, public)
- `P` — the signer's public key = `s·G` (the Ethereum address comes from P)

A signature is the pair `(r, σ)`. Here is where each number comes from:

```
┌─────────────────────────────────────────────────────────────┐
│                    HOW r IS BORN                            │
│                                                             │
│  Signer picks a random nonce k  (or via MtA in threshold)   │
│  Computes: R = k × G                                        │
│                                                             │
│  R is a point on the curve: R = (x_R, y_R)                  │
│  r = x_R mod n    ← just take the x-coordinate of R         │
│                                                             │
│  r is public — it IS part of the signature.                 │
│  It encodes "which point on the curve the nonce landed on". │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    HOW σ IS BORN                            │
│                                                             │
│  z  = keccak256(transaction)   ← message hash              │
│  s  = private key              ← ghost in threshold         │
│  k  = nonce                    ← ghost in threshold         │
│                                                             │
│  σ = k⁻¹ × (z + r × s)  mod n                             │
│                                                             │
│  Plain English:                                             │
│    "Take the message hash z, add r times the private key,   │
│     then scale the whole thing by k⁻¹ (the inverse nonce)" │
│                                                             │
│  σ is the scalar component. It ties z, r, and s together.  │
└─────────────────────────────────────────────────────────────┘
```

Nobody sends the private key `s` or nonce `k` in the signature. Only `(r, σ)` is sent. The verifier must recover the fact that you know `s` using only `(r, σ)`.

---

#### Part C — The Full Verification Algorithm (What Ethereum Runs)

The verifier has: `P` (public key), `z` (message hash), `r` (from signature), `σ` (from signature).
The verifier does NOT have: `s`, `k`, `k⁻¹`.

```
═══════════════════════════════════════════════════════════════
ECDSA VERIFICATION ALGORITHM — FULL STEP BY STEP
═══════════════════════════════════════════════════════════════

INPUT:
    P  — public key EC point  (known from Ethereum address)
    z  — keccak256(transaction)  (computed by verifier)
    r  — first half of signature  (given)
    σ  — second half of signature  (given)

STEP 1: Sanity check
    r must be in range [1, n-1]   → reject if not
    σ must be in range [1, n-1]   → reject if not
    (A signature with r=0 or σ=0 is degenerate/forged)

STEP 2: Compute σ⁻¹ mod n
    This is the modular inverse of σ.
    σ × σ⁻¹ ≡ 1 (mod n)
    Computed via extended Euclidean algorithm.

    Why? Because σ = k⁻¹·(z + r·s), so σ⁻¹ = k/(z + r·s).
    The verifier uses σ⁻¹ to "undo" what the signer did with k⁻¹.

STEP 3: Compute u₁ and u₂
    u₁ = σ⁻¹ · z  mod n
    u₂ = σ⁻¹ · r  mod n

    u₁ is: "the message hash weighted by σ⁻¹"
    u₂ is: "the signature's r value weighted by σ⁻¹"

STEP 4: Compute EC point X
    X = u₁ · G  +  u₂ · P

    This is two EC scalar multiplications plus one EC point addition.
    G and P are both points on y² = x³ + 7.
    u₁·G means "slide along the curve from G by u₁ steps".
    u₂·P means "slide along the curve from P by u₂ steps".
    Then add those two resulting points together (EC point addition).

STEP 5: Extract x-coordinate and compare
    If X.x mod n  ==  r  →  VALID  ✓
    If X.x mod n  ≠   r  →  INVALID ✗

═══════════════════════════════════════════════════════════════
```

---

#### Part D — Why the Algorithm Works: The Algebra Opened Up

Here is every step of the algebra, written out completely with no steps hidden:

```
WHAT WE KNOW ABOUT σ (the signing equation):
    σ = k⁻¹ × (z + r × s)   mod n           ... (1)

GOAL: Show that if we compute X = u₁·G + u₂·P, then X.x = r.

───────────────────────────────────────────────────────────────
STEP A: Rearrange equation (1) to isolate k
───────────────────────────────────────────────────────────────

    σ               = k⁻¹ × (z + r × s)
    σ × k           = (z + r × s)             (multiply both sides by k)
    k               = (z + r × s) × σ⁻¹       (multiply both sides by σ⁻¹)
    k               = z × σ⁻¹  +  r × s × σ⁻¹ (distribute σ⁻¹)
    k               = u₁       +  u₂ × s        (substitute u₁=z·σ⁻¹, u₂=r·σ⁻¹)

So:     k  =  u₁ + u₂ × s                      ... (2)

───────────────────────────────────────────────────────────────
STEP B: Convert equation (2) to an EC point equation
───────────────────────────────────────────────────────────────

Multiply both sides of (2) by G (the generator point):

    k × G  =  (u₁ + u₂ × s) × G
    k × G  =  u₁ × G  +  u₂ × s × G            (distribute × G)
    k × G  =  u₁ × G  +  u₂ × (s × G)          (regroup)
    k × G  =  u₁ × G  +  u₂ × P                 (because P = s × G)

So:     k × G  =  u₁ × G  +  u₂ × P            ... (3)

The right side is exactly what the verifier computes as X!

    X = u₁ × G + u₂ × P = k × G

───────────────────────────────────────────────────────────────
STEP C: Show X.x = r
───────────────────────────────────────────────────────────────

We defined r = R.x where R = k × G  (standard ECDSA convention).

From Step B: X = k × G = R

Therefore:  X.x = R.x = r  ✓

The verifier's computed point X lands on the SAME curve point R that
the signer used to create r — without the verifier ever knowing k!

───────────────────────────────────────────────────────────────
CONCLUSION
───────────────────────────────────────────────────────────────

If and only if the signature was created with private key s, then:
    The verifier's X = k × G = R
    And X.x = R.x = r matches what's in the signature.

If someone fakes a signature without knowing s, they cannot make
X.x = r because they can't compute the correct σ that ties
the real R (from k×G) to the real s (the private key).
```

---

#### Part E — Visual Diagram: Signer vs Verifier Side by Side

```
SIGNER (knows s and k)              VERIFIER (knows only P, z, r, σ)
──────────────────────              ────────────────────────────────

Curve:  y² = x³ + 7  (mod p)       Same curve: y² = x³ + 7  (mod p)

Private key:  s   (secret)          Public key: P = s·G  (given)
Nonce:        k   (fresh random)    (does NOT know s or k)


Compute nonce point:                Compute σ⁻¹ mod n:
    R = k · G                           σ⁻¹ = modInverse(σ, n)
    (point on y²=x³+7)


Extract r from R:                   Compute weights:
    r = R.x mod n                       u₁ = σ⁻¹ · z  mod n
    (x-coordinate of the point R)       u₂ = σ⁻¹ · r  mod n


Compute σ using r, z, s, k⁻¹:      Compute EC point X:
    σ = k⁻¹ · (z + r · s)  mod n       X  = u₁ · G  +  u₂ · P
                                        (two multiplications on y²=x³+7,
                                         then one point addition)

                                    Check:
Output signature:  (r, σ)               X.x  mod n  ==  r  ?

                    ┌────────────────────────────────┐
                    │  YES → signature VALID   ✓     │
                    │  NO  → signature INVALID ✗     │
                    └────────────────────────────────┘

WHY IT WORKS:
    Signer produced X = k·G (via k⁻¹·(z+r·s) algebra).
    Verifier reconstructed X = u₁·G + u₂·P (via σ⁻¹ algebra).
    Both arrive at k·G without the verifier ever knowing k.
    The curve equation y²=x³+7 is the "arena" where all this math happens.
```

---

#### Part F — Complete Worked Numeric Example (All Steps)

We'll use a tiny modulus to keep numbers readable. Real secp256k1 uses p ≈ 10⁷⁷ and n ≈ 10⁷⁷ but the math is identical.

```
SETUP (tiny example, same algebra as real secp256k1):
    Private key:  s = 12
    Nonce:        k = 7
    Public key:   P = s·G = 12·G    (a point on y²=x³+7)
    Message hash: z = 5             (think of this as keccak256(tx))

───────────────────────────────────────────────────────────────
SIGNER SIDE — Creating the signature (r, σ)
───────────────────────────────────────────────────────────────

Step S1: Compute nonce point R = k·G
    R = 7·G   (slide along y²=x³+7 from G by 7 steps)
    R = (x_R, y_R)   ← some (x, y) pair on the curve

Step S2: Extract r
    r = R.x mod n    ← just the x-coordinate
    (For this example, let's say r = 3)

Step S3: Compute σ
    σ = k⁻¹ · (z + r · s)  mod n
    σ = 7⁻¹  · (5 + 3 · 12)  mod n
    σ = 7⁻¹  · (5 + 36)      mod n
    σ = 7⁻¹  · 41            mod n
    σ = 41 · 7⁻¹             mod n    ← modular arithmetic

    (In real arithmetic: σ = 41/7. In modular arithmetic: σ = 41 · modInverse(7, n))

SIGNATURE = (r=3,  σ=41·7⁻¹ mod n)

Signer sends this. Does NOT send s, k, or k⁻¹.

───────────────────────────────────────────────────────────────
VERIFIER SIDE — Checking the signature
───────────────────────────────────────────────────────────────

Verifier has: P = 12·G,  z = 5,  r = 3,  σ = 41·7⁻¹ mod n

Step V1: Check r and σ in range [1, n-1]  ✓

Step V2: Compute σ⁻¹
    σ      = 41 · 7⁻¹
    σ⁻¹    = (41 · 7⁻¹)⁻¹
           = 7 · 41⁻¹
           = 7/41 mod n

Step V3: Compute u₁ and u₂
    u₁ = σ⁻¹ · z = (7/41) · 5 = 35/41  mod n
    u₂ = σ⁻¹ · r = (7/41) · 3 = 21/41  mod n

Step V4: Compute X = u₁·G + u₂·P
    X  = (35/41)·G  +  (21/41)·P
       = (35/41)·G  +  (21/41)·(12·G)    ← substitute P = 12·G
       = (35/41)·G  +  (252/41)·G        ← scalar · scalar · G = combined scalar
       = (35/41 + 252/41)·G              ← combine over common denominator
       = (287/41)·G
       = 7·G                             ← 287 ÷ 41 = 7  ✓

    So X = 7·G = k·G = R

Step V5: Check X.x mod n == r
    X.x = (7·G).x = R.x = r = 3  ✓

RESULT: Signature VALID ✓

WHY IT WORKED:
    Verifier reconstructed R = k·G = 7·G using only P, z, r, σ.
    They never needed k=7 or s=12 as raw numbers.
    The algebra with σ⁻¹ naturally cancels out the unknown k.

───────────────────────────────────────────────────────────────
WHAT IF THE SIGNATURE IS FORGED?
───────────────────────────────────────────────────────────────

Attacker tries to sign message z=5 for public key P=12·G,
but they don't know s=12.

They forge: r = 3, σ = 999 (random fake σ)

Verifier checks:
    σ⁻¹ = 999⁻¹  mod n
    u₁  = 999⁻¹ · 5   mod n
    u₂  = 999⁻¹ · 3   mod n
    X   = u₁·G + u₂·P

    X will be some random point (u₁ + 12·u₂)·G.
    For X.x to equal r=3, the attacker would need:
        u₁ + 12·u₂ = k   (where k·G has x-coordinate 3)
    That means:
        5/999 + 12·(3/999) = k
        (5 + 36)/999 = k
        41/999 = k

    But the REAL r=3 was computed from k_real·G where k_real·G has x-coordinate 3.
    The k computed above (41/999) is different from k_real.
    So (41/999)·G has a DIFFERENT x-coordinate than 3.

    X.x ≠ 3 = r  →  INVALID  ✗

The attacker cannot make X.x = r without knowing s (to get the right k via
the real signing equation σ = k⁻¹·(z + r·s)).
```

---

#### Part G — The Curve Equation's Role in Every Operation

To make it fully clear: every single operation in ECDSA happens ON the curve y² = x³ + 7. Here is a table of every operation and which part of the curve it uses:

```
┌─────────────────────┬─────────────────────────────────────────────────┐
│ Operation           │ How the curve y²=x³+7 is used                  │
├─────────────────────┼─────────────────────────────────────────────────┤
│ P = s · G           │ Scalar mult: add G to itself s times on curve.  │
│ (keygen)            │ Each addition uses the chord-and-tangent rule.  │
│                     │ Result: a point (x, y) satisfying y²=x³+7.     │
├─────────────────────┼─────────────────────────────────────────────────┤
│ R = k · G           │ Same as above. Nonce point. R.x becomes r.     │
│ (signing, nonce)    │ In threshold: R = δ⁻¹·Γ (γ cancels, see above) │
├─────────────────────┼─────────────────────────────────────────────────┤
│ r = R.x mod n       │ Extract x-coordinate from the curve point R.   │
│ (signing)           │ Discard y. r is a scalar, not a curve point.   │
├─────────────────────┼─────────────────────────────────────────────────┤
│ σ = k⁻¹·(z+r·s)    │ Pure scalar arithmetic (mod n). No curve used.  │
│ (signing)           │ k⁻¹, z, r, s are all scalars (integers mod n). │
├─────────────────────┼─────────────────────────────────────────────────┤
│ X = u₁·G + u₂·P    │ Two scalar mults on the curve, then point add.  │
│ (verification)      │ u₁·G: slide from G. u₂·P: slide from P.        │
│                     │ Add: chord-and-tangent rule on y²=x³+7.        │
├─────────────────────┼─────────────────────────────────────────────────┤
│ X.x mod n == r      │ Extract x-coordinate from X, compare to r.     │
│ (verification)      │ If it matches, the algebra closed correctly.   │
├─────────────────────┼─────────────────────────────────────────────────┤
│ Feldman: Cᵢ₀=sᵢ·G  │ Scalar mult on curve. Hides sᵢ behind the      │
│ (DKG verification)  │ discrete log problem on y²=x³+7.               │
├─────────────────────┼─────────────────────────────────────────────────┤
│ Γᵢ = γᵢ·G          │ Scalar mult on curve. Hides γᵢ. Safe to submit │
│ (GG20 nonce hiding) │ on-chain. Combined as Γ = Σ Γᵢ = γ·G.         │
└─────────────────────┴─────────────────────────────────────────────────┘

THE SECURITY FOUNDATION:
    Everything collapses to one assumption:
    Given a·G (a point on y²=x³+7), finding a is computationally infeasible.
    This is the elliptic curve discrete logarithm problem (ECDLP).
    Breaking secp256k1 requires ~2¹²⁸ operations. Quantum computers
    would need ~10³⁴ seconds. Classical computers: longer than the universe.
```

---

### Proof 6: The Ghost Key — Why s Never Needs to Exist (Threshold Version)

This proof uses the **standard ECDSA convention** (σ = k⁻¹·(z+r·s), R = k·G) to show conceptually how s can be split. The actual GG20 implementation uses the flipped convention (σ = k·(z+r·s), R = k⁻¹·G) as shown in Proof 4 — both are mathematically equivalent. The key idea below is identical in both conventions.

This is the core insight: you can produce σ = k⁻¹·(z + r·s) without any party knowing s, by algebraically splitting it into additive partial signatures.

**For standard 3-of-3 additive (README.md version):**

```
σ = k⁻¹ × (z + r × s)

Substitute s = s₁ + s₂ + s₃:
σ = k⁻¹ × (z + r×s₁ + r×s₂ + r×s₃)

Distribute k⁻¹:
σ = k⁻¹×z + k⁻¹×r×s₁ + k⁻¹×r×s₂ + k⁻¹×r×s₃

Split z equally: z = z/3 + z/3 + z/3:
σ = k⁻¹(z/3 + r×s₁)  +  k⁻¹(z/3 + r×s₂)  +  k⁻¹(z/3 + r×s₃)
    ─────────────────     ─────────────────     ─────────────────
           σ₁                    σ₂                    σ₃

Party 1 computes σ₁ using only: z, r, k⁻¹, s₁
Party 2 computes σ₂ using only: z, r, k⁻¹, s₂
Party 3 computes σ₃ using only: z, r, k⁻¹, s₃

σ₁ + σ₂ + σ₃ = k⁻¹(z + r·s)   ← perfect ECDSA, s never computed!
```

**For 2-of-3 threshold (this document's approach):**

```
Instead of sᵢ, each signing party uses their Lagrange-adjusted share x̃ᵢ = λᵢ·Xᵢ

Property: x̃₁ + x̃₂ = λ₁·X₁ + λ₂·X₂ = s   (Lagrange reconstruction)

σ = k⁻¹ × (z + r × s)

Substitute s = x̃₁ + x̃₂ (for subset {1,2}):
σ = k⁻¹ × (z + r×x̃₁ + r×x̃₂)

Split z equally: z = z/2 + z/2:
σ = k⁻¹(z/2 + r×x̃₁)  +  k⁻¹(z/2 + r×x̃₂)
    ────────────────────     ────────────────────
            σ₁                       σ₂

Party 1 computes σ₁ using only: z, r, k⁻¹, x̃₁  (where x̃₁ = λ₁·X₁)
Party 2 computes σ₂ using only: z, r, k⁻¹, x̃₂  (where x̃₂ = λ₂·X₂)

σ₁ + σ₂ = k⁻¹(z + r·(x̃₁+x̃₂))
         = k⁻¹(z + r·s)   ← same ECDSA! ✓

Nobody ever computed s = x̃₁ + x̃₂ = 12.
Party 1 knows x̃₁ = 36. Party 2 knows x̃₂ = -24.
Neither can determine their sum is 12.
```

**The key difference between 3-of-3 and 2-of-3:**

```
3-of-3 (additive):   each party uses raw sᵢ     z split 3 ways: z/3 each
2-of-3 (threshold):  each party uses λᵢ·Xᵢ     z split 2 ways: z/2 each
All-3 (threshold):   each party uses λᵢ·Xᵢ     z split 3 ways: z/3 each

The MATH is identical. Only the input share changes (sᵢ → x̃ᵢ = λᵢ·Xᵢ).
```

---

### Proof 7: Partial Signature Commit-Reveal (Anti-Tampering)

If parties submitted partial sigs directly without committing first:

```
ATTACK:
    Party 1 submits σ₁ openly.
    Malicious Party 2 sees σ₁, then computes what σ₂ they'd need to
    make the combined σ = σ₁ + σ₂ equal any target value they want.

    σ₂ = target_σ - σ₁    ← trivial to compute!

    Party 2 submits their crafted σ₂.
    Contract combines: σ = σ₁ + σ₂ = target_σ.
    Signature is forged for a different message.
```

**The fix (commit-reveal):**

```
Step 1: Each party COMMITS  hash(σᵢ)   →   on-chain (locked in)
Step 2: After all commitments collected,
        each party REVEALS  σᵢ         →   contract checks hash(σᵢ) matches

Now Party 2 cannot craft a different σ₂ because:
    - They already committed hash(σ₂) before seeing σ₁
    - If they reveal a different value, hash won't match → REJECTED

This is the same commit-reveal pattern used in DKG for Feldman commitments.
```

---

### Proof 8: Low-s Normalization (EIP-2 / BIP-62)

ECDSA signatures are mathematically malleable: if (r, σ) is a valid signature, so is (r, n - σ). Both are valid. This is a problem because:

```
Original tx hash:     H(tx₁)  →  ECDSA sig (r, σ)
Malleated tx hash:    H(tx₁)  →  ECDSA sig (r, n-σ)   ← different txid, same content!

In old Bitcoin: same transaction could have two different txids (tx malleability).
This broke payment channels, Lightning Network precursors, etc.
```

**The fix (standardized by EIP-2 and BIP-62):**

```
After computing σ:
    if σ > n/2:
        σ = n - σ          ← flip to the "lower" valid value
        recovery_id ^= 1   ← flip the recovery bit too

This ensures there is only ONE valid form of each signature.
All Ethereum nodes reject signatures where σ > n/2.
```

**Why this works:**

```
Both (r, σ) and (r, n-σ) verify correctly:
    u₁·G + u₂·P computed with σ    → X.x = r  ✓
    u₁·G + u₂·P computed with n-σ  → X.x = r  ✓   (because n-σ is also valid)

But only the form with σ ≤ n/2 is accepted by Ethereum.
The contract must apply this normalization before storing the signature.
```

**Verification of the flip:**

```
σ = 41 mod n (example)

If 41 > n/2 → σ_normalized = n - 41

Check: using n - 41 in the verifier equation:
    (n-41)⁻¹ mod n = -(41)⁻¹ mod n = n - 41⁻¹ mod n

The algebra still works because:
    σ_normalized⁻¹ = -(σ⁻¹) mod n

And negating σ⁻¹ simply negates u₁ and u₂, which negates the Y-coordinate of X.
But X.x is unchanged (negating a point flips Y, not X). So r = X.x still holds. ✓
```

---

## Security Analysis — Zero Coordinator Proof

### Step-by-Step: Who Acts at Each Step?

| Step | Who acts | Coordinator? | What they need |
|------|----------|-------------|----------------|
| Generate polynomial fᵢ | Each party independently | **No** | Random number generator |
| Commit Feldman hashes | Each party independently | **No** | Their own Cᵢ₀, Cᵢ₁ |
| Reveal Feldman points | Each party independently | **No** | Their own Cᵢ₀, Cᵢ₁ |
| Send sub-shares fᵢ(j) | Each party to every other | **No** | Their own polynomial |
| Verify sub-shares | ZK nodes automatically | **No** | Public Feldman commitments |
| Combine final shares | ZK nodes automatically | **No** | Received sub-shares |
| Compute combined public key | Contract automatically | **No** | Public Feldman commitments |
| Choose signing subset | Any 2 parties agree | **No** | Mutual agreement |
| Compute Lagrange weights | Each signing party locally | **No** | Knowledge of which subset |
| Generate nonce kᵢ, γᵢ | Each party independently | **No** | Random number generator |
| MtA rounds | Each pair bilaterally | **No** | Paillier keys |
| Submit δᵢ, Γᵢ | Each party independently | **No** | Their MtA results |
| Compute R | Contract automatically | **No** | Submitted δ and Γ values |
| Compute partial sig σᵢ | Each party independently | **No** | Their x̃ᵢ, kᵢ, r, z |
| Combine final sig | Contract automatically | **No** | Submitted partial sigs |

**No single entity at any step knows enough to reconstruct the key or unilaterally produce a signature.**

### Attack Scenarios

```
Attack: Compromise 1 party
    Attacker gets: Xᵢ (one Shamir share)
    Attacker learns about s: NOTHING
        (one point doesn't define a line — infinitely many
         polynomials pass through one point)
    Can sign? NO (need 2 shares)

Attack: Compromise 1 ZK node
    Attacker gets: encrypted fragment of one share
    Attacker learns about s: NOTHING
        (ZK nodes split each share across multiple nodes)
    Can sign? NO

Attack: Compromise contract
    Attacker gets: P (public key), all Cᵢⱼ, δ, Γ, r, σ
    Attacker learns about s: NOTHING
        (all values are public anyway)
    Can sign new message? NO (needs private shares)

Attack: Malicious party sends wrong sub-share
    Result: Feldman verification catches it instantly
    Impact: DKG aborts, nobody's key is compromised

Attack: Party tries to bias combined key
    Result: Commit-then-reveal prevents seeing others' choices
    Impact: Cannot choose polynomial based on others' commitments

Attack: Malicious party submits wrong δᵢ during signing
    Result: R is computed incorrectly → σ fails ECDSA verification
    Impact: Signing round fails (DoS), but no secrets leak
    Gap: Cannot identify WHO cheated without identifiable abort (Issue 4)

Attack: Party reuses same kᵢ across two signing sessions
    Result: If same k used for messages M₁ and M₂:
        σ_A - σ_B = k·(z₁ - z₂ + r₁·s - r₂·s)
        → can solve for s (private key)
    Impact: FULL KEY COMPROMISE
    Gap: No session isolation / nonce reuse prevention described (Issue 5)

Attack: Party uses malformed Paillier key in MtA
    Result: Can decrypt other parties' MtA ciphertexts
    Impact: FULL KEY COMPROMISE — learns other parties' kᵢ and x̃ᵢ
    Gap: No Paillier key verification described (Issue 2)

Attack: MtA without range proofs — party injects huge value
    Result: Overflow mod N (Paillier) vs mod n (secp256k1) leaks bits
    Impact: GRADUAL KEY COMPROMISE — bits of kᵢ leak per signing session
    Gap: No MtA range proofs described (Issue 1)
```

> **See [Production Security Checklist](#production-security-checklist--whats-missing-for-real-deployment) for full details on each gap and how to fix it.**

---

## Comparison — Additive (Old) vs Threshold (New)

| Aspect | Additive DKG (README.md) | Threshold DKG + Signing (This doc) |
|--------|-------------------------|-----------------------------------|
| **Key splitting** | `s = s₁ + s₂ + s₃` (additive) | Shamir polynomial `F(x) = s + bx` |
| **Each party picks** | 1 random scalar `sᵢ` | 2 random scalars `sᵢ, aᵢ` → polynomial `fᵢ(x)` |
| **Sub-shares** | Not needed | Each party sends `fᵢ(j)` to every other party |
| **Verification** | SHA-256 commitment only | Feldman VSS: `fᵢ(j)·G == Cᵢ₀ + j·Cᵢ₁` |
| **Combined key** | `P = P₁ + P₂ + P₃` (point addition) | `P = λ₁·P₁ + λ₂·P₂ + λ₃·P₃` (Lagrange) |
| **Signing requires** | ALL 3 parties | Any 2 of 3 |
| **Party offline** | BROKEN — cannot sign | FINE — other 2 continue |
| **Signing change** | Use `sᵢ` directly | Multiply `Xᵢ` by Lagrange weight `λᵢ` first |
| **Coordinator** | None for DKG, none for signing | **None at any step** |
| **Private key assembled** | Never | **Never** |
| **EVM compatible** | Yes (standard ECDSA) | Yes (identical ECDSA signatures) |
| **DKG transactions** | ~12 (commit, reveal, finalize, shares) | ~18 (+ Feldman commits + 9 sub-shares) |
| **Signing transactions** | ~12 (3 parties always) | ~10 (2 parties sufficient) |
| **Security model** | All 3 must be honest and online | Tolerates 1 offline/malicious party |

### The Bottom Line

```
    ADDITIVE (OLD):
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Party 1  │  │ Party 2  │  │ Party 3  │    ALL 3 needed
    │    s₁    │  │    s₂    │  │    s₃    │    to sign
    └────┬─────┘  └────┬─────┘  └────┬─────┘
         │             │             │
         └──────┬──────┘             │
                │                    │
         Must have ALL THREE → s₁ + s₂ + s₃ = s
         Missing one? BROKEN.


    THRESHOLD (NEW):
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Party 1  │  │ Party 2  │  │ Party 3  │    ANY 2 enough
    │    X₁    │  │    X₂    │  │  OFFLINE  │    to sign
    └────┬─────┘  └────┬─────┘  └──────────┘
         │             │
         │  λ₁·X₁     │  λ₂·X₂
         │             │
         └──────┬──────┘
                │
         λ₁·X₁ + λ₂·X₂ = s  ← Lagrange magic
         Same key. Same address. Party 3 didn't need to show up.
```

---

## Production Security — Complete Implementation Guide

The math in this document is correct and complete. But **math correctness ≠ production security**. This section describes every security measure needed, HOW to implement it, the exact protocol steps, and what happens without it.

---

### Protection 1: MtA Range Proofs (Πenc and Πaff-g)

**Severity: CRITICAL — without this, a single malicious party can extract other parties' private key shares.**

#### The Problem

MtA uses Paillier encryption. Paillier works mod N (a 2048+ bit modulus). secp256k1 works mod n (a 256-bit prime). This size mismatch is dangerous:

```
Paillier ciphertext space:  mod N²  (where N ≈ 2²⁰⁴⁸)
secp256k1 scalar space:     mod n   (where n ≈ 2²⁵⁶)

The ciphertext can hold values WAY larger than n.
```

#### The Attack (Without Range Proofs)

```
Party 1 encrypts k₁ under Paillier:  c = Enc(k₁)

Malicious Party 2 receives c and computes:
    c' = c ⊕ Enc(q)     where q is MUCH larger than n (e.g., 2²⁰⁰⁰)

    Paillier decryption gives: k₁ + q  mod N
    But the protocol expects:  k₁ + q  mod n    ← DIFFERENT VALUE

    The difference:  (k₁ + q mod N) - (k₁ + q mod n) = m·n  for some m

    By varying q and observing the output δ values, Party 2 can
    determine m, and from m recover k₁ mod n — the actual nonce share.

    With k₁ known: s can be extracted from the signature.
```

#### How to Implement the Fix

Each MtA call requires TWO zero-knowledge proofs:

```
PROOF Πenc (Paillier Encryption Range Proof):
─────────────────────────────────────────────

When Party 1 sends ciphertext c = Enc(k₁) to Party 2, Party 1 ALSO sends
a zero-knowledge proof that:

    "The plaintext inside c is in the range [0, 2^ℓ)
     where ℓ = 256 + security_parameter (e.g., ℓ = 256 + 80 = 336)"

The proof does NOT reveal k₁. It only convinces Party 2 that k₁ is small
enough that mod-N and mod-n behave identically.

Protocol (Schnorr-like Sigma protocol over Paillier):

    1. Prover (Party 1) picks random r in [0, 2^(ℓ+ε))
       Computes commitment: A = Enc(r) under same Paillier key

    2. Verifier (Party 2) sends random challenge e ∈ {0,1}^κ

    3. Prover computes response: z = r + e·k₁
       If z ≥ 2^(ℓ+ε): ABORT and restart (rejection sampling)
       Sends z to verifier

    4. Verifier checks:
       - Enc(z) == A ⊕ (c^e)   mod N²     (Paillier homomorphism)
       - z < 2^(ℓ+ε)                       (range check)

    If both pass → k₁ is in range with overwhelming probability.


PROOF Πaff-g (Affine Operation Range Proof):
─────────────────────────────────────────────

When Party 2 performs the MtA homomorphic operation:
    c' = (c ^γ₂) ⊕ Enc(β)     (computing k₁·γ₂ + β under encryption)

Party 2 ALSO proves:
    "γ₂ is in range [0, 2^ℓ)  AND  β is in range [0, 2^(ℓ'))"

This prevents Party 2 from injecting a large γ₂ or β that causes overflow.

Protocol: Similar sigma protocol but over the affine operation.
    - Commitment phase: random masking of both γ₂ and β
    - Challenge: random from Party 1
    - Response: masked values with rejection sampling for range
    - Verification: check Paillier homomorphism AND EC point consistency:
          γ₂·G must match the committed Γ₂ point

Together, Πenc and Πaff-g ensure that ALL values inside MtA ciphertexts
are small enough that the Paillier mod-N and secp256k1 mod-n never diverge.
```

#### Where in the Protocol

```
Phase 2, STEP 2 (MtA rounds) becomes:

    For each MtA(k₁, γ₂):
        Party 1 sends:  c₁ = Enc(k₁)  +  Πenc proof that k₁ < 2^336
        Party 2 computes: c' = c₁^γ₂ ⊕ Enc(β₁₂)
        Party 2 sends:  c'  +  Πaff-g proof that γ₂ < 2^336 AND β₁₂ < 2^(ℓ')
        Party 1 decrypts: α₁₂ = Dec(c') = k₁·γ₂ + β₁₂

    Same for all 4 MtA calls (k×γ and k×x̃ pairs).
    Total: 8 range proofs per signing session (4 MtA calls × 2 proofs each).
```

---

### Protection 2: Paillier Key Verification (Πmod and Πfac)

**Severity: CRITICAL — without this, a malicious party can decrypt all MtA ciphertexts.**

#### The Problem

MtA only works if each party's Paillier key is well-formed. If Party 1 uses a weak Paillier modulus, they can factor it and decrypt everything Party 2 sends.

#### The Attack (Without Verification)

```
Party 1 generates a WEAK Paillier key:
    N = 15  (= 3 × 5)    ← trivially factorable!

Party 2 encrypts x̃₂ under Party 1's public key for MtA:
    c = Enc_N(x̃₂)

Party 1 factors N = 3 × 5, computes the private key, decrypts:
    x̃₂ = Dec(c)         ← Party 2's adjusted share is now known!

With x̃₂ and their own x̃₁, Party 1 computes:
    s = x̃₁ + x̃₂         ← FULL PRIVATE KEY
```

#### How to Implement the Fix

Each party generates their Paillier key ONCE (during setup, before first signing), then proves it's well-formed:

```
PAILLIER KEY GENERATION (each party independently):
────────────────────────────────────────────────────

1. Generate two safe primes:
       p = 2p' + 1    where p' is a 1024-bit prime
       q = 2q' + 1    where q' is a 1024-bit prime
   (Safe prime = prime where (prime-1)/2 is also prime)

2. Compute:  N = p · q       (the Paillier modulus, ≥ 2048 bits)
3. Compute:  λ = lcm(p-1, q-1)   (the private key)
4. Publish:  N  (the public key)
5. Keep secret: p, q, λ


PROOF Πmod (Modulus is a Product of Safe Primes):
─────────────────────────────────────────────────

Party i proves to all other parties:
    "N = p·q where p and q are both safe primes, and N ≥ 2048 bits"

Protocol (non-interactive, Fiat-Shamir heuristic):

    1. Prover computes w = random 4th root mod N
       (exists only if N = p·q with p ≡ q ≡ 3 mod 4)

    2. For i = 1..κ (security parameter iterations):
       - Pick random yᵢ ∈ Z*_N
       - Compute: zᵢ = yᵢ^N mod N²

    3. Challenge: e = Hash(N, w, {yᵢ, zᵢ})

    4. For each bit eᵢ of e:
       - If eᵢ = 0: reveal yᵢ
       - If eᵢ = 1: reveal xᵢ = yᵢ^(N⁻¹ mod λ) mod N

    5. Verifier checks each response against the commitment.
       Also checks: len(N) ≥ 2048 bits.

If N is not a product of two safe primes, the prover cannot consistently
produce valid responses for all challenge bits.


PROOF Πfac (Prover Knows Factorization):
────────────────────────────────────────

Party i proves: "I know p and q such that N = p·q"

This is a standard discrete-log-style proof over Z*_N:
    - Prover demonstrates ability to compute square roots mod N
      (which requires knowing the factorization)
    - Verifier cannot factor N from the proof transcript


WHEN to run these proofs:
    - ONCE during party setup (before first signing)
    - Proofs are stored on-chain or verified by all other parties
    - If a party's Paillier key changes → must re-prove
    - Contract stores: Party i's Paillier public key N_i + proof hash
```

#### Contract Changes Required

```
New on-chain state per party:
    paillier_pubkey: Vec<u8>     // the N value (256 bytes for 2048-bit key)
    paillier_proof:  Vec<u8>     // the Πmod + Πfac proof (verified once)
    paillier_verified: bool      // true after proof passes

New action (shortname 0x25):  register_paillier_key
    Args: party_index, paillier_pubkey, proof_bytes
    Contract verifies: proof is valid for the given N
    Contract stores: paillier_pubkey, sets paillier_verified = true

Signing REFUSES to start unless all signing parties have paillier_verified = true.
```

---

### Protection 3: Schnorr Proof of Knowledge in DKG (Anti-Rogue-Key)

**Severity: CRITICAL — without this, one party can take over the entire key.**

#### The Problem

During DKG, each party publishes Cᵢ₀ = sᵢ·G. The commit-reveal scheme prevents seeing others' values before committing. But if a party can abort and retry (or if reveal order is flexible), they can craft a rogue key.

#### The Attack

```
ROGUE KEY ATTACK:
    Party 3 somehow learns C₁₀ and C₂₀ (e.g., by aborting after reveal,
    or by colluding with the reveal transaction ordering).

    Party 3 picks arbitrary s₃_fake, then computes:
        C₃₀ = s₃_fake·G  -  C₁₀  -  C₂₀

    Combined key: P = C₁₀ + C₂₀ + C₃₀
                    = C₁₀ + C₂₀ + (s₃_fake·G - C₁₀ - C₂₀)
                    = s₃_fake · G

    Party 3 now knows the FULL private key (s₃_fake) for the combined key!
    They can sign anything without the other parties.
```

#### How to Implement the Fix

```
SCHNORR PROOF OF KNOWLEDGE (added to DKG Round 2):
───────────────────────────────────────────────────

When each party commits Cᵢ₀ = sᵢ·G, they ALSO submit a Schnorr proof
that they KNOW the discrete log sᵢ behind Cᵢ₀.

Protocol (non-interactive, using Fiat-Shamir):

    1. Party i picks random nonce: rᵢ ← random scalar
    2. Computes commitment point:   Rᵢ = rᵢ · G
    3. Computes challenge:          eᵢ = Hash(G, Cᵢ₀, Rᵢ, party_index_i)
    4. Computes response:           zᵢ = rᵢ + eᵢ · sᵢ  mod n
    5. Submits:  (Cᵢ₀, Rᵢ, zᵢ)    to contract

    Contract verifies:
        zᵢ · G  ==  Rᵢ + eᵢ · Cᵢ₀
        where eᵢ = Hash(G, Cᵢ₀, Rᵢ, party_index_i)

    If this equation holds → Party i knows sᵢ (the discrete log of Cᵢ₀).

WHY this prevents the rogue key attack:

    Party 3 would need C₃₀ = s₃_fake·G - C₁₀ - C₂₀

    But to produce the Schnorr proof, Party 3 needs to know the discrete
    log of C₃₀. The discrete log of (s₃_fake·G - C₁₀ - C₂₀) is
    (s₃_fake - s₁ - s₂), which requires knowing s₁ and s₂.

    Party 3 does NOT know s₁ and s₂ → CANNOT produce a valid Schnorr proof
    → Contract rejects the commitment → Attack fails!

SAME proof is also done for Cᵢ₁ = aᵢ·G (the slope commitment):
    - Proves Party i knows aᵢ
    - Prevents the same rogue key attack on the slope term
```

#### Contract Changes Required

```
DKG Round 2 (commit) modified:

    BEFORE (current):
        Party submits: commitment_hash = SHA-256(compressed_Cᵢ₀)

    AFTER (production):
        Party submits: commitment_hash = SHA-256(compressed_Cᵢ₀)
                       schnorr_R:  Vec<u8>   (33 bytes, compressed EC point)
                       schnorr_z:  Vec<u8>   (32 bytes, scalar)

DKG Round 3 (reveal) modified:

    Contract verifies BOTH:
        1. SHA-256(Cᵢ₀) == commitment_hash           (commit-reveal check)
        2. zᵢ·G == Rᵢ + Hash(G, Cᵢ₀, Rᵢ, i)·Cᵢ₀    (Schnorr proof check)

    If either fails → DKG aborts for this party.
```

#### Worked Example

```
Party 1: s₁ = 3
    C₁₀ = 3·G

    Pick random nonce: r₁ = 17
    R₁ = 17·G

    Challenge: e₁ = Hash(G, C₁₀, R₁, 1)  →  suppose e₁ = 42

    Response: z₁ = 17 + 42·3 = 17 + 126 = 143  mod n

    Submit: (C₁₀, R₁, z₁) = (3·G, 17·G, 143)

    Contract checks: 143·G  ==  17·G + 42·(3·G)
                     143·G  ==  17·G + 126·G
                     143·G  ==  143·G   ✓

Party 3 tries rogue key:
    Wants C₃₀ = s₃_fake·G - C₁₀ - C₂₀

    Discrete log of C₃₀ = s₃_fake - s₁ - s₂ = s₃_fake - 3 - 5

    Party 3 does NOT know s₁=3 or s₂=5 → cannot compute z₃ → CAUGHT!
```

---

### Protection 4: Identifiable Abort During Signing

**Severity: HIGH — without this, one malicious party can block all signing forever.**

#### The Problem

If a party submits a wrong δᵢ or σᵢ, the combined signature fails. But the contract cannot tell WHO cheated — only that the result is invalid.

#### How to Implement the Fix

```
IDENTIFIABLE ABORT PROTOCOL:
─────────────────────────────

The key insight: each party's δᵢ and Γᵢ must satisfy a PUBLIC equation.
If the combined signature fails, the contract checks each party individually.

NORMAL FLOW (no cheating):

    1. Each party submits: δᵢ, Γᵢ = γᵢ·G, σᵢ
    2. Contract computes: δ = Σδᵢ, Γ = ΣΓᵢ, R = δ⁻¹·Γ, σ = Σσᵢ
    3. Contract verifies ECDSA: check σ against (r, z, P)
    4. If valid → done! ✓

ABORT FLOW (signature failed verification):

    5. Contract enters "blame" mode
    6. For each party i, contract checks:

       CHECK A — Γᵢ consistency:
           Each party already submitted Γᵢ = γᵢ·G.
           During MtA, Party i also produced ciphertexts that encrypted γᵢ.
           Using the MtA transcripts (stored on-chain), verify that Γᵢ is
           consistent with the encrypted γᵢ used in MtA.

           How: Party i must open their γᵢ (only in blame mode).
                Contract checks: γᵢ·G == Γᵢ   (if not → Party i cheated on Γᵢ)

       CHECK B — δᵢ consistency:
           δᵢ should equal kᵢ·γᵢ + (MtA cross-terms).
           Party i opens kᵢ (only in blame mode).
           Contract checks:
               kᵢ·Γᵢ should be consistent with δᵢ contribution.
               Specifically: kᵢ·G must match the Kᵢ point from MtA setup.

       CHECK C — σᵢ consistency:
           σᵢ = z·kᵢ + r·τᵢ
           Using the opened kᵢ and the MtA transcripts, contract reconstructs
           what σᵢ SHOULD be and compares with what was submitted.

    7. The first party whose values fail any check → IDENTIFIED as cheater.
    8. Cheater is excluded from future signing rounds.
    9. Remaining honest parties restart signing without the cheater.

IMPORTANT: Opening kᵢ and γᵢ in blame mode is safe because:
    - The signing round ALREADY FAILED — the nonce k is never used in a valid signature
    - The kᵢ and γᵢ from a failed round cannot be used to extract s
    - A new round will use completely fresh kᵢ' and γᵢ' values
```

#### Contract Changes Required

```
New contract state:
    signing_status: enum { InProgress, Completed, Blame }
    blame_deadline: u64     // block number by which blame must complete

New action (shortname 0x32):  initiate_blame
    Triggers: when combined σ fails ECDSA verification
    Effect: sets signing_status = Blame, stores deadline

New action (shortname 0x33):  submit_blame_opening
    Args: party_index, k_i (scalar), gamma_i (scalar)
    Contract checks: kᵢ·G and γᵢ·G against stored values
    Contract checks: δᵢ and σᵢ consistency
    Result: identifies cheater OR clears this party

If a party refuses to open during blame → they are the cheater by default.
```

---

### Protection 5: Signing Session Isolation & Nonce Reuse Prevention

**Severity: HIGH — nonce reuse = full private key extraction.**

#### The Problem

If a party uses the same kᵢ in two different signing sessions, the private key is exposed.

#### How to Implement the Fix

```
THREE-LAYER DEFENSE against nonce reuse:

LAYER 1 — Unique Session ID (contract-enforced):
─────────────────────────────────────────────────

    session_id = SHA-256(key_id ‖ message_hash ‖ sorted_party_indices ‖ nonce_counter)

    Where:
        key_id:                 the DKG key being used (u32)
        message_hash:           z = SHA-256(message) (32 bytes)
        sorted_party_indices:   e.g., [1, 2] (canonical order)
        nonce_counter:          auto-incrementing per key (u64)

    Contract stores: set of used session_ids
    Contract rejects: any signing request with a session_id that already exists

    This prevents: replaying messages from old sessions.


LAYER 2 — Deterministic Nonce via RFC 6979 (client-enforced):
─────────────────────────────────────────────────────────────

    Instead of picking kᵢ from random, derive it deterministically:

        kᵢ = HMAC-DRBG(x̃ᵢ, z, session_id)

    Where HMAC-DRBG is the deterministic RNG from RFC 6979:
        - Seed: x̃ᵢ (Party i's adjusted share — their secret)
        - Message: z (hash of the message being signed)
        - Additional data: session_id (unique per session)

    This guarantees:
        - Same (x̃ᵢ, z, session_id) → same kᵢ  (deterministic, repeatable)
        - Different session_id → different kᵢ    (no reuse across sessions)
        - RNG failure is impossible               (no random number generator used)

    CRITICAL: Different sessions have different session_ids (because of nonce_counter),
    so even signing the SAME message twice produces different kᵢ values.


LAYER 3 — Contract State Machine (protocol-enforced):
─────────────────────────────────────────────────────

    Contract tracks signing state per key:

    enum SigningState {
        Idle,                          // ready for new signing request
        AwaitingDeltas(session_id),    // waiting for δᵢ, Γᵢ
        AwaitingPartialSigs(session_id), // waiting for σᵢ
        Complete(session_id),          // signature produced
        Aborted(session_id),           // round cancelled
    }

    Rules:
        - Only ONE active signing session per key at a time
        - Cannot start new session while one is in AwaitingDeltas or AwaitingPartialSigs
        - Must wait for Complete or Aborted before starting next
        - This prevents concurrent sessions that could lead to nonce reuse

    Combined with Layer 1 (session_id uniqueness) and Layer 2 (deterministic nonce),
    nonce reuse is structurally impossible even if client code has bugs.
```

#### Where in the Protocol

```
Phase 2, STEP 1 (Choose Signing Subset) becomes:

    1. Parties agree on: message_hash z, subset S = {1, 2}
    2. Client requests new signing session from contract
    3. Contract generates session_id = SHA-256(key_id ‖ z ‖ [1,2] ‖ counter++)
    4. Contract sets state = AwaitingDeltas(session_id)
    5. Each party derives: kᵢ = HMAC-DRBG(x̃ᵢ, z, session_id)
    6. Each party picks: γᵢ = random()   (gamma need not be deterministic)

    Proceeds to STEP 2 (MtA) with these kᵢ and γᵢ.
```

---

### Protection 6: Signing Timeout & Abort Protocol

**Severity: HIGH — without this, a party going offline mid-signing permanently blocks the key.**

#### How to Implement the Fix

```
TIMEOUT STATE MACHINE:
──────────────────────

Each signing session has TWO deadlines:

    delta_deadline:   Block number by which ALL δᵢ/Γᵢ must be submitted
    sigma_deadline:   Block number by which ALL σᵢ must be submitted

Concrete values (configurable per deployment):
    delta_deadline  = start_block + 50   (≈ 5 minutes on Partisia)
    sigma_deadline  = delta_deadline + 50

STATE TRANSITIONS:

    Idle
      │
      ├── start_signing(session_id, deadline) ──→ AwaitingDeltas
      │
    AwaitingDeltas
      │
      ├── all δᵢ/Γᵢ received before deadline ──→ AwaitingPartialSigs
      │
      ├── deadline passed, missing δᵢ ──→ Aborted
      │   (contract records which parties failed to submit)
      │
    AwaitingPartialSigs
      │
      ├── all σᵢ received before deadline ──→ Verifying
      │
      ├── deadline passed, missing σᵢ ──→ Aborted
      │   (contract records which parties failed to submit)
      │
    Verifying
      │
      ├── σ passes ECDSA check ──→ Complete  ✓
      │
      ├── σ fails ECDSA check ──→ Blame (see Protection 4)
      │
    Aborted
      │
      ├── Any 2 parties can immediately start a new session
      │   with fresh kᵢ, γᵢ (possibly different subset)


SAFETY OF ABORTED ROUNDS:
──────────────────────────

    Q: If Party 1 submitted δ₁ and Γ₁ but Party 2 disappeared,
       is it safe that δ₁ was publicly revealed?

    A: YES — because:
       - δ₁ is Party 1's share of k·γ
       - Without δ₂, nobody can compute δ = k·γ
       - Even if δ₁ is known, it reveals nothing about k₁ or γ₁
         (it's one equation with two unknowns: δ₁ = k₁·γ₁ + MtA terms)
       - The next signing round will use completely fresh k₁', γ₁'
       - δ₁ from the aborted round is useless forever


CONTRACT CHANGES:
─────────────────

    New fields in signing state:
        delta_deadline:   u64    // block number
        sigma_deadline:   u64    // block number
        submitted_delta:  Vec<u8>  // bitfield of which parties submitted
        submitted_sigma:  Vec<u8>  // bitfield of which parties submitted

    New action (shortname 0x34):  check_timeout
        Anyone can call this after a deadline passes.
        Contract checks current block against deadline.
        If deadline passed and not all submissions received → Aborted.
        Records which parties failed to submit (for reputation tracking).

    New action (shortname 0x35):  restart_signing
        Available only in Aborted or Idle state.
        Starts a new session with a new session_id.
        Previous session's δ/Γ values are wiped from state.
```

---

### Protection 7: Key Refresh (Proactive Secret Sharing)

**Severity: MEDIUM — without this, slow compromise over months can accumulate enough shares.**

#### The Problem

If shares never change, an attacker who compromises Party 1 in January and Party 2 in March has both shares — enough to reconstruct s.

#### How to Implement the Fix

```
KEY REFRESH PROTOCOL (runs periodically, e.g., every 30 days):
──────────────────────────────────────────────────────────────

The idea: add a "zero polynomial" to every party's share.
The combined key stays the same, but individual shares change.

STEP 1 — Each party generates a ZERO-SECRET polynomial:
    Party 1 picks: random slope b₁, defines g₁(x) = 0 + b₁·x
    Party 2 picks: random slope b₂, defines g₂(x) = 0 + b₂·x
    Party 3 picks: random slope b₃, defines g₃(x) = 0 + b₃·x

    NOTE: the constant term is ZERO for all parties.
    Combined: G(x) = 0 + (b₁+b₂+b₃)·x
    G(0) = 0  →  the secret doesn't change!

STEP 2 — Sub-share distribution (same as DKG Round 4):
    Party 1 sends g₁(2) to Party 2, g₁(3) to Party 3
    Party 2 sends g₂(1) to Party 1, g₂(3) to Party 3
    Party 3 sends g₃(1) to Party 1, g₃(2) to Party 2

STEP 3 — Each party updates their share:
    X₁' = X₁ + g₁(1) + g₂(1) + g₃(1)
    X₂' = X₂ + g₁(2) + g₂(2) + g₃(2)
    X₃' = X₃ + g₁(3) + g₂(3) + g₃(3)

STEP 4 — Feldman verification (same as DKG Round 5):
    Each party publishes: D_i1 = bᵢ·G  (commitment to their slope)
    Verify: gᵢ(j)·G == 0·G + j·D_i1 = j·D_i1
    (Note: constant commitment is 0·G = identity point — because secret contribution is 0)

STEP 5 — Confirm new shares work:
    New combined polynomial: F'(x) = F(x) + G(x) = s + (b + b₁+b₂+b₃)·x
    F'(0) = s + 0 = s   ← same secret!
    But X₁' ≠ X₁, X₂' ≠ X₂, X₃' ≠ X₃  ← different shares!

    Old shares are NOW USELESS — they no longer lie on the new polynomial.


WORKED EXAMPLE:
───────────────

    Current shares: X₁ = 18, X₂ = 24, X₃ = 30  (from F(x) = 12 + 6x)

    Refresh polynomials (zero-secret):
        g₁(x) = 0 + 4x    (Party 1 picks random slope 4)
        g₂(x) = 0 + 2x    (Party 2 picks random slope 2)
        g₃(x) = 0 + 1x    (Party 3 picks random slope 1)

    Combined refresh: G(x) = 0 + 7x

    Sub-share sums each party collects:
        Party 1: g₁(1)+g₂(1)+g₃(1) = 4+2+1 = 7
        Party 2: g₁(2)+g₂(2)+g₃(2) = 8+4+2 = 14
        Party 3: g₁(3)+g₂(3)+g₃(3) = 12+6+3 = 21

    New shares:
        X₁' = 18 + 7  = 25
        X₂' = 24 + 14 = 38
        X₃' = 30 + 21 = 51

    Verify: new polynomial F'(x) = 12 + 13x
        F'(1) = 25 ✓   F'(2) = 38 ✓   F'(3) = 51 ✓
        F'(0) = 12 ✓   ← same secret!

    Old shares (18, 24, 30) no longer on the line y = 12 + 13x.
    Compromised Party 1's old X₁ = 18 is useless.


FREQUENCY: Every 30 days or after any security incident.
```

---

### Protection 8: Key Backup & Recovery (Re-Sharing)

**Severity: MEDIUM — without this, losing one party permanently degrades fault tolerance.**

#### How to Implement the Fix

```
SCENARIO: Party 3 permanently lost their share. Parties 1 and 2 remain.
GOAL: Issue a new share to replacement Party 3' WITHOUT revealing s.

RE-SHARING PROTOCOL (requires threshold = 2 parties):
─────────────────────────────────────────────────────

STEP 1 — Parties 1 and 2 agree to re-share:
    They know: subset S = {1, 2}, with Lagrange coefficients λ₁=2, λ₂=-1
    They compute: x̃₁ = 2·X₁, x̃₂ = (-1)·X₂  (adjusted shares that sum to s)

STEP 2 — Each party generates a NEW degree-1 polynomial through their adjusted share:

    Party 1 picks random slope c₁, defines:
        h₁(x) such that h₁(0) = x̃₁  and slope = c₁
        h₁(x) = x̃₁ + c₁·x

    Party 2 picks random slope c₂, defines:
        h₂(x) such that h₂(0) = x̃₂  and slope = c₂
        h₂(x) = x̃₂ + c₂·x

    Combined: H(x) = h₁(x) + h₂(x) = (x̃₁+x̃₂) + (c₁+c₂)·x = s + c·x
    → This is a NEW degree-1 polynomial with the SAME secret s!

STEP 3 — Distribute sub-shares of new polynomial:
    Party 1 sends h₁(1) to new Party 1', h₁(2) to new Party 2', h₁(3) to new Party 3'
    Party 2 sends h₂(1) to new Party 1', h₂(2) to new Party 2', h₂(3) to new Party 3'

    New shares:
        X₁_new = h₁(1) + h₂(1) = H(1)
        X₂_new = h₁(2) + h₂(2) = H(2)
        X₃_new = h₁(3) + h₂(3) = H(3)

    All three new shares lie on H(x), which has H(0) = s. ✓

STEP 4 — Feldman verification for new polynomial:
    Commitments: E₁₀ = x̃₁·G, E₁₁ = c₁·G, E₂₀ = x̃₂·G, E₂₁ = c₂·G
    New parties verify sub-shares against these commitments.

RESULT:
    - New Party 3' has a valid share X₃_new
    - Old Party 3's share X₃_old is on the OLD polynomial — useless with new shares
    - Same public key P, same Ethereum address
    - System is back to full 2-of-3 fault tolerance
```

---

### Protection 9: δᵢ and σᵢ Correctness Proofs (Πlog)

**Severity: MEDIUM — without this, a malicious party can DoS signing with no accountability.**

#### How to Implement the Fix

```
CORRECTNESS PROOF FOR Γᵢ (Proof of Discrete Log Equality — Πlog):
─────────────────────────────────────────────────────────────────

When Party i submits Γᵢ = γᵢ·G, they also prove they used the SAME γᵢ in MtA.

During MtA, Party i encrypted γᵢ under Paillier as c_γᵢ = Enc(γᵢ).
The proof shows: "The value inside c_γᵢ and the discrete log of Γᵢ are the same."

Protocol (Proof of Plaintext-Discrete-Log Equality):

    1. Party i picks random: r
    2. Computes:
       A = r · G                  (EC commitment)
       B = Enc(r)                 (Paillier commitment)

    3. Challenge: e = Hash(G, Γᵢ, A, B, c_γᵢ)

    4. Response: z = r + e·γᵢ  mod n

    5. Verifier checks:
       z · G  ==  A + e · Γᵢ                     (EC side)
       Enc(z) ==  B ⊕ (c_γᵢ ^ e)  mod N²        (Paillier side)

    If both hold → the same γᵢ was used in both the EC point and the ciphertext.


CORRECTNESS PROOF FOR δᵢ:
─────────────────────────

The MtA output values (α, β) are committed during the MtA protocol.
After δᵢ = kᵢ·γᵢ + α₁₂ + β₂₁ is submitted, the contract can verify:

    - kᵢ·Γᵢ should equal kᵢ·γᵢ·G  (known from Γᵢ and Kᵢ = kᵢ·G)
    - The MtA transcripts provide commitments to α₁₂ and β₂₁
    - δᵢ·G should equal kᵢ·Γᵢ + (committed MtA terms)·G

If verification fails → Party i submitted a wrong δᵢ → identified as cheater.

This is essentially the same as identifiable abort (Protection 4),
but done PROACTIVELY before the signature is computed — catching cheaters early.
```

---

### Protection 10: Ring-Pedersen Parameters & Auxiliary Info (CGGMP21)

**Severity: CRITICAL (if using CGGMP21) / HIGH (if using GG20) — required for composable security.**

#### The Problem

CGGMP21 (the recommended production protocol) requires each party to set up **auxiliary information** — a Ring-Pedersen commitment scheme — in addition to their Paillier key. Without this, the ZK proofs in MtA are not simulation-extractable and the protocol loses its UC-security guarantee.

Even in GG20, the Πenc and Πaff-g proofs implicitly rely on a trusted setup parameter. In production, this must be made explicit and verifiable.

#### How to Implement the Fix

```
RING-PEDERSEN SETUP (each party, during initial key setup):
───────────────────────────────────────────────────────────

Each party i generates:

    1. Paillier key: (Nᵢ, pᵢ, qᵢ) — already covered in Protection 2

    2. Ring-Pedersen parameters:
       - Pick random: sᵢ, tᵢ ∈ Z*_Nᵢ  such that  tᵢ = sᵢ^λᵢ mod Nᵢ
         where λᵢ = lcm(pᵢ-1, qᵢ-1)  (the Paillier private key)

       - Publish: (Nᵢ, sᵢ, tᵢ)

    3. Prove correctness with Πprm (Ring-Pedersen Parameters Proof):
       - Proves: the prover knows λ such that tᵢ = sᵢ^λ mod Nᵢ
       - This is a proof of knowledge of the discrete log in Z*_N
       - Prevents a malicious party from choosing (s, t) that break
         the binding property of the commitment scheme

Protocol (Πprm — Schnorr-like over Z*_N):

    1. Prover picks random a ∈ Z*_N
    2. Computes: A = sᵢ^a mod Nᵢ
    3. Challenge: e = Hash(Nᵢ, sᵢ, tᵢ, A)
    4. Response: z = a + e·λᵢ  (in Z, no modular reduction)
    5. Verifier checks:
       sᵢ^z mod Nᵢ  ==  A · tᵢ^e mod Nᵢ


WHERE RING-PEDERSEN IS USED:

    Every ZK proof in MtA (Πenc, Πaff-g from Protection 1) uses the
    Ring-Pedersen parameters as the commitment scheme base. Specifically:

    - The "commitment" in the sigma protocol is computed as:
          S = sᵢ^value · tᵢ^randomness  mod Nᵢ

    - This replaces simple Pedersen commitments (which need a trusted
      "nothing up my sleeve" group generator)

    - Ring-Pedersen over Z*_N is provably binding under the factoring
      assumption — no trusted setup needed!


CONTRACT CHANGES:

    Extend Protection 2's paillier key registration:

    Action register_paillier_key (shortname 0x25) now includes:
        Args: party_index, N_i, s_i, t_i, proof_mod, proof_prm
        Contract verifies: Πmod proof (N is well-formed)
                          Πprm proof (Ring-Pedersen params are valid)
        Contract stores: (N_i, s_i, t_i, verified=true)
```

---

### Protection 11: EIP-155 Chain ID & Signature Format

**Severity: HIGH — without this, signatures can be replayed across different EVM chains.**

#### The Problem

A valid ECDSA signature (r, σ, v) on Ethereum mainnet is ALSO valid on Polygon, BSC, Arbitrum, etc. — unless the chain ID is encoded into the signature. Without EIP-155, a signed transaction on one chain can be replayed on another.

#### How to Implement the Fix

```
EIP-155 SIGNATURE FORMAT:
─────────────────────────

Standard ECDSA produces: (r, σ) + recovery_id (0 or 1)

EIP-155 modifies the v value:
    v = recovery_id + 35 + 2 × chain_id

    Ethereum mainnet (chain_id = 1):   v = 37 or 38
    Polygon (chain_id = 137):          v = 309 or 310
    Sepolia (chain_id = 11155111):     v = 22310257 or 22310258

The message hash z also changes — it includes the chain_id:
    z = keccak256(RLP(nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0))
                                                                   ^^^^^^^^^^^^^^^^
                                                       EIP-155 appends chain_id, 0, 0
                                                       before hashing

WHERE IN THE PROTOCOL:

    Phase 2, STEP 6 (partial signature computation):
        z must be the EIP-155 transaction hash (includes chain_id)
        The contract must know which chain the signature targets

    Phase 2, STEP 7 (combine signatures):
        After computing σ and applying low-s normalization (Proof 8),
        the contract computes:
            v = recovery_id + 35 + 2 × chain_id
        The final output is (v, r, σ) — a complete EIP-155 signature.

CONTRACT CHANGES:
    - Store target chain_id per key (set during DKG or signing request)
    - Signing action includes chain_id parameter
    - Output signature includes v value (not just r, σ)
```

---

### Protection 12: Constant-Time Operations & Side-Channel Resistance

**Severity: HIGH — timing/power side channels can leak secret scalars.**

#### The Problem

If scalar operations (multiplication, inversion, comparison) take different amounts of time depending on the value, an attacker measuring timing can extract bits of the secret.

```
TIMING ATTACK EXAMPLE:
    Party 1 computes: σ₁ = z·k₁ + r·τ₁  mod n

    If the modular multiplication takes longer when k₁ has more 1-bits,
    an attacker monitoring network timing can determine k₁ bit by bit.

    With k₁ known → private key extracted (same as nonce reuse).
```

#### How to Implement the Fix

```
CONSTANT-TIME REQUIREMENTS:
───────────────────────────

ALL secret scalar operations must be constant-time:

1. Scalar multiplication (k₁ · γ₁):
   Use Montgomery ladder or fixed-window method — NOT double-and-add
   (double-and-add branches on bits of the scalar → timing leak)

2. Modular inversion (δ⁻¹ mod n):
   Use Fermat's little theorem: δ⁻¹ = δ^(n-2) mod n
   With constant-time modular exponentiation (square-and-multiply
   with dummy operations for 0-bits)

3. Comparison (if σ > n/2):
   Use constant-time comparison: result = (σ - n/2) >> 255
   Do NOT use branching if/else on secret values

4. Memory access:
   Do NOT use secret values as array indices
   (cache-timing attacks can detect which cache line was accessed)

5. EC point multiplication (kᵢ · G):
   Use complete addition formulas (no special cases for point-at-infinity)
   Use constant-time scalar multiplication (e.g., wNAF with dummy adds)

IMPLEMENTATION IN RUST (contract side):
   k256 crate already provides constant-time operations via the
   `subtle` crate (ConstantTimeEq, ConditionallySelectable).
   Ensure: never use raw if/else on `Scalar` or `FieldElement` values.

IMPLEMENTATION IN TYPESCRIPT (client side):
   @noble/curves already provides constant-time scalar arithmetic.
   Ensure: never use BigInt comparison operators (>, <, ==) on secrets.
   Use the library's built-in comparison functions instead.

WHAT TO AUDIT:
   - Every line that touches: kᵢ, γᵢ, x̃ᵢ, sᵢ, aᵢ, τᵢ, σᵢ, δᵢ
   - Any if/else or loop that depends on a secret value
   - Any array indexing by a secret value
   - Any early-return based on a secret value
```

---

### Protection 13: Entropy Quality for Random Scalar Generation

**Severity: HIGH — weak RNG = predictable nonces = key extraction.**

#### The Problem

kᵢ, γᵢ, sᵢ, aᵢ all require cryptographically secure random scalars. If the RNG is weak (predictable, low entropy, biased), an attacker can guess these values.

```
REAL-WORLD FAILURES:
    - Android SecureRandom (2013): weak PRNG seed → Bitcoin wallets drained
    - ROCA vulnerability (2017): RSA keys on smartcards had predictable primes
    - Debian OpenSSL (2008): only 32,768 possible keys due to RNG bug
```

#### How to Implement the Fix

```
ENTROPY REQUIREMENTS:
─────────────────────

1. DKG scalars (sᵢ, aᵢ) — generated ONCE per key:
   Source: crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js)
   Both use OS-level CSPRNG (urandom on Linux, CryptGenRandom on Windows)
   Minimum: 256 bits of entropy per scalar

2. Signing nonces (kᵢ) — generated per signing session:
   PREFERRED: Deterministic via RFC 6979 (Protection 5, Layer 2)
       kᵢ = HMAC-DRBG(x̃ᵢ, z, session_id)
       → No RNG needed! Entropy comes from the share itself.
       → Eliminates RNG failure as an attack vector entirely.

   FALLBACK (if RFC 6979 not used): Must use CSPRNG with full 256-bit entropy.

3. Masking values (γᵢ) — generated per signing session:
   Source: CSPRNG (crypto.getRandomValues)
   γᵢ does NOT need to be deterministic (unlike kᵢ)
   But must be unpredictable — if γᵢ is guessable, k can be extracted from δ.

4. Paillier primes (p, q) — generated ONCE per party:
   Source: CSPRNG
   Each prime must be independently generated with full entropy
   Use probabilistic primality testing (Miller-Rabin, ≥ 40 rounds)

MODULAR REDUCTION BIAS:
───────────────────────
   When generating a random scalar mod n:
       DO NOT: pick random 256-bit number and compute % n
               (this biases toward smaller values because 2^256 > n)

       DO:     pick random 512-bit number and compute % n
               (bias is negligible: 2^512 / n ≈ 2^256 possible values
                for each residue class — difference < 2^{-256})

       OR:     use rejection sampling: pick 256-bit random,
               reject if ≥ n, retry (expected <2 attempts)

   The @noble/curves library handles this correctly internally.
   If implementing manually, use the 512-bit reduction method.
```

---

### Protection 14: Message Ordering & Front-Running on Partisia

**Severity: MEDIUM — transaction ordering attacks can disrupt DKG or signing.**

#### The Problem

On any blockchain, transaction ordering is controlled by validators/miners. A malicious validator (or MEV bot) could:

```
ATTACK 1 — DKG front-running:
    Party 3 submits their Feldman reveal transaction.
    A malicious validator sees the reveal in the mempool BEFORE it's confirmed.
    They extract C₃₀ and craft a rogue key response.
    → Mitigated by Protection 3 (Schnorr proof) — even with front-running,
      the rogue key attack fails because the Schnorr proof was committed earlier.

ATTACK 2 — Signing reordering:
    Party 1 submits δ₁. Party 2 submits δ₂.
    A malicious validator reorders so δ₂ arrives first.
    → NOT an issue: δ values are additive (order doesn't matter).

ATTACK 3 — Selective censorship:
    A malicious validator consistently drops Party 1's transactions.
    → Party 1 can never participate in signing.
    → Mitigated by timeout (Protection 6): after timeout, remaining
      parties restart with a different subset that excludes the
      censored party.
```

#### How to Handle

```
PARTISIA-SPECIFIC MITIGATIONS:
──────────────────────────────

1. Partisia uses BFT consensus — no single validator controls ordering.
   Front-running is harder than on Ethereum (no public mempool by default).

2. All commit-reveal schemes (DKG + signing) already prevent the most
   dangerous ordering attacks.

3. The timeout mechanism (Protection 6) handles censorship.

4. For additional safety: use encrypted mempool / threshold encryption
   for DKG reveal transactions (Partisia supports shielded transactions).

RECOMMENDED: No additional protocol changes needed beyond Protections 3 and 6.
```

---

### Protection 15: On-Chain Storage & Gas Costs

**Severity: MEDIUM — must be planned for production deployment budget.**

#### Cost Analysis

```
DKG STORAGE PER KEY:
────────────────────

    Per party (3 parties):
        Feldman commitment Cᵢ₀:           33 bytes (compressed EC point)
        Feldman commitment Cᵢ₁:           33 bytes
        Schnorr proof (Rᵢ, zᵢ):          33 + 32 = 65 bytes   (Protection 3)
        Sub-shares to other parties:       2 × 32 = 64 bytes    (via ZK)
        Paillier public key Nᵢ:           256 bytes             (Protection 2)
        Ring-Pedersen (sᵢ, tᵢ):           2 × 256 = 512 bytes  (Protection 10)
        Paillier proofs (Πmod, Πfac, Πprm): ~2 KB              (one-time)

    Combined public key P:                33 bytes
    DKG state tracking:                   ~100 bytes

    Total per key (one-time):             ~8 KB

SIGNING STORAGE PER SESSION:
────────────────────────────

    Per signing party (2 parties):
        δᵢ:                               32 bytes
        Γᵢ:                               33 bytes
        σᵢ:                               32 bytes
        Commitment hashes (commit-reveal): 2 × 32 = 64 bytes
        MtA range proofs (Πenc, Πaff-g):   ~1 KB per MtA call × 4 = ~4 KB
        Πlog correctness proof:            ~256 bytes          (Protection 9)

    Session metadata:                      ~100 bytes
    Combined R, r, σ:                      33 + 32 + 32 = 97 bytes

    Total per signing session:             ~10 KB (cleaned up after completion)

PARTISIA GAS ESTIMATES:
───────────────────────

    DKG (full 7-round ceremony):           ~50-80 transactions total
    Signing (one session):                 ~15-20 transactions
    Key refresh:                           ~30-40 transactions

    These are estimates. Actual costs depend on Partisia gas pricing and
    contract execution costs. The ZK proof verification (Feldman, Schnorr,
    Πenc) dominates the compute cost.
```

---

### Production Readiness Summary

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                   PRODUCTION READINESS SCORECARD — ALL 15 PROTECTIONS        │
├─────────────────────────────────┬──────────┬───────────────┬────────────────┤
│  Component                      │  Status  │  Severity     │  Protection #  │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│                        CORE PROTOCOL (already complete)                      │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│  DKG math (Pedersen/Feldman)    │  ✅ DONE  │  —            │  —             │
│  Threshold signing (GG20)       │  ✅ DONE  │  —            │  —             │
│  Feldman verification           │  ✅ DONE  │  —            │  —             │
│  Commit-reveal (DKG + sigs)     │  ✅ DONE  │  —            │  —             │
│  Lagrange interpolation         │  ✅ DONE  │  —            │  —             │
│  Low-s normalization (EIP-2)    │  ✅ DONE  │  —            │  —             │
│  Gamma cancellation (R comp)    │  ✅ DONE  │  —            │  —             │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│                   CRYPTOGRAPHIC PROTECTIONS (key extraction prevention)      │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│  MtA range proofs (Πenc/Πaff-g) │  ✅ DONE  │  CRITICAL     │  #1            │
│  Paillier key verification      │  ✅ DONE  │  CRITICAL     │  #2            │
│  Schnorr proof (anti-rogue)     │  ✅ DONE  │  CRITICAL     │  #3            │
│  Ring-Pedersen params (Πprm)    │  ✅ DONE  │  CRITICAL*    │  #10           │
│                                 │          │  (*if CGGMP21) │                │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│                    PROTOCOL ROBUSTNESS (DoS / liveness)                      │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│  Identifiable abort             │  ✅ DONE  │  HIGH         │  #4            │
│  Session isolation / nonce      │  ✅ DONE  │  HIGH         │  #5            │
│  Signing timeout/abort          │  ✅ DONE  │  HIGH         │  #6            │
│  EIP-155 chain ID signatures    │  ✅ DONE  │  HIGH         │  #11           │
│  Constant-time operations       │  ✅ DONE  │  HIGH         │  #12           │
│  Entropy / RNG quality          │  ✅ DONE  │  HIGH         │  #13           │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│                   OPERATIONAL (long-term maintenance)                        │
├─────────────────────────────────┼──────────┼───────────────┼────────────────┤
│  Key refresh (proactive sharing)│  ✅ DONE  │  MEDIUM       │  #7            │
│  Key recovery (re-sharing)      │  ✅ DONE  │  MEDIUM       │  #8            │
│  δᵢ correctness proof (Πlog)   │  ✅ DONE  │  MEDIUM       │  #9            │
│  Front-running / ordering       │  ✅ DONE  │  MEDIUM       │  #14           │
│  Storage & gas cost analysis    │  ✅ DONE  │  MEDIUM       │  #15           │
└─────────────────────────────────┴──────────┴───────────────┴────────────────┘

ALL 15 PROTECTIONS DOCUMENTED WITH:
    ✓  The exact attack each prevents (with worked examples)
    ✓  Step-by-step implementation protocol
    ✓  Contract changes required (new shortnames, state fields)
    ✓  Where it fits in the existing DKG/signing flow
    ✓  Worked numeric examples (where applicable)
    ✓  WHY it is necessary (not just WHAT)
    ✓  Real-world failure references (Sony PS3, Android BTC, Debian OpenSSL)

IMPLEMENTATION ORDER (recommended):

    PHASE A — Minimum Viable Security (before any real funds):
        1. Protection 3  (Schnorr proof)      — pure EC math, no Paillier
        2. Protection 5  (Session isolation)   — RFC 6979 + state machine
        3. Protection 6  (Timeout/abort)       — state machine extension
        4. Protection 11 (EIP-155 chain ID)    — signature format
        5. Protection 12 (Constant-time)       — audit existing code
        6. Protection 13 (Entropy quality)     — audit RNG usage

    PHASE B — Full Cryptographic Security:
        7. Protection 2  (Paillier key setup)  — one-time per party
        8. Protection 10 (Ring-Pedersen)        — extends Paillier setup
        9. Protection 1  (MtA range proofs)    — requires Paillier ZKPs
       10. Protection 4  (Identifiable abort)  — MtA transcripts on-chain
       11. Protection 9  (δᵢ correctness)      — extends identifiable abort

    PHASE C — Operational Maturity:
       12. Protection 7  (Key refresh)         — periodic re-sharing
       13. Protection 8  (Key recovery)        — party replacement
       14. Protection 14 (Front-running)       — Partisia-specific
       15. Protection 15 (Gas/storage)         — cost optimization

ALTERNATIVE: Use CGGMP21 protocol (Canetti et al., 2021) which bundles
    protections 1, 2, 3, 4, 9, and 10 into a single unified protocol with
    formal security proofs. Used by Fireblocks, Coinbase, and other
    production MPC wallets.

    Reference: "UC Non-Interactive, Proactive, Threshold ECDSA
    with Identifiable Aborts" — Canetti, Gennaro, Goldfeder,
    Makriyannis, Peled (2021)
```

---

## The Golden Rules

1. **The private key never exists anywhere.** Not during DKG, not during signing, not ever. It's a mathematical ghost.

2. **Each party is independent.** Every party generates their own polynomial, sends their own sub-shares, computes their own Lagrange coefficient. No coordinator.

3. **Feldman keeps everyone honest.** The on-chain commitments `Cᵢ₀ = sᵢ·G, Cᵢ₁ = aᵢ·G` let anyone verify a sub-share without learning the underlying scalar.

4. **Lagrange is just a pre-multiplication.** All the threshold magic is one scalar multiply before the normal GG20 signing math: `x̃ᵢ = λᵢ · Xᵢ`.

5. **Sub-shares are the core of DKG.** Party i sends fᵢ(j) to Party j so that Party j's final share lands on the combined polynomial.

6. **ZK nodes are the trust anchor.** They hold the final shares as secrets, run the Feldman verification, and compute the combination. The on-chain contract orchestrates rounds but never sees raw key material.

7. **Any 2 of 3 — always.** Different subsets use different Lagrange weights but always reconstruct the same secret. Same public key, same Ethereum address, no matter who signs.
