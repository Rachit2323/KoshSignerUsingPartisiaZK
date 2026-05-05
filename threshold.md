# Threshold Signing: A Complete Explanation

---

## 1. The Current System — Additive Sharing (Pizza Slices)

Imagine a pizza cut into exactly 3 slices.

- **Party 1** holds slice 1
- **Party 2** holds slice 2
- **Party 3** holds slice 3

The full pizza is the private key. To sign a transaction, you need the full pizza — all 3 slices together.

**What happens if Party 3 goes offline?**

You have slice 1 and slice 2. That's only 2/3 of a pizza. You cannot eat it, you cannot sign. Done. Failed.

This is exactly how the current system works. The private key `s` is split as:

```
s = s₁ + s₂ + s₃
```

To sign, each party computes a partial signature using their slice, and the results are summed. If anyone is missing, the sum is wrong and the signature is invalid.

This is called **3-of-3**: every single party must show up. Miss one → broken.

---

## 2. What We Want — Threshold (The Bank Vault)

Picture a bank vault that needs **2 out of 3 managers** to open it.

- Each manager holds one key (their "share")
- Manager 1 + Manager 2 can open the vault. ✓
- Manager 1 + Manager 3 can open the vault. ✓
- Manager 2 + Manager 3 can open the vault. ✓
- Manager 1 alone cannot open it. ✗
- Manager 3 alone on vacation? No problem — the other two handle it.

This is **2-of-3 threshold**: any 2 out of 3 is enough.

The key insight: no single manager has to be present. The system keeps working even when someone is offline, unavailable, or lost their key — as long as enough others are available.

In cryptographic terms: any 2-party subset can compute a valid signature. Any 1-party subset learns nothing about the key.

---

## 3. Why You Can't Just "Remove a Slice" — Additive ≠ Threshold

Let's use concrete numbers to see why the pizza system can never become the vault system.

**Secret = 15. Split it additively into 3 shares:**
```
s₁ = 4
s₂ = 6
s₃ = 5

4 + 6 + 5 = 15  ✓
```

**Now party 3 goes offline. Can parties 1 and 2 recover the secret?**
```
4 + 6 = 10  ✗
```

10 is not 15. We're missing 5. There is no math trick that recovers the missing 5 — it's just gone. The number 5 lives only in Party 3's head, nowhere else.

Could you "pad" the shares so that any 2 sum to the secret? Let's try:

- If {1,2} must sum to 15: s₁ + s₂ = 15 → maybe s₁=4, s₂=11
- If {1,3} must sum to 15: s₁ + s₃ = 15 → s₃=11
- If {2,3} must sum to 15: s₂ + s₃ = 15 → 11+11 = 22 ≠ 15

It's mathematically impossible to make all three pairs sum to 15 simultaneously. You'd need s₁+s₂ = s₁+s₃ = s₂+s₃ = 15, which forces s₂=s₃ and s₁=s₂ and then 2s₁=15 — contradictions everywhere.

Additive shares are fundamentally all-or-nothing. You need a completely different structure.

---

## 4. How Shamir Works — Graphing a Line

Shamir secret sharing uses a clever trick from geometry: **two points define a line, and only two points define that exact line**.

Here's a 2-of-3 example with small numbers.

**Step 1: The secret is 7.**

**Step 2: Pick a random line that passes through (0, 7).**

A line is `f(x) = 7 + 3x`. The secret lives at `x = 0`. The slope `3` is random — it's the randomness that hides the secret.

**Step 3: Give each party a point on the line.**
```
Party 1 gets f(1) = 7 + 3(1) = 10   →  point (1, 10)
Party 2 gets f(2) = 7 + 3(2) = 13   →  point (2, 13)
Party 3 gets f(3) = 7 + 3(3) = 16   →  point (3, 16)
```

**Step 4: Any 2 parties can find the line and recover the secret.**

Parties 1 and 2 have points (1, 10) and (2, 13):
```
Slope = (13 - 10) / (2 - 1) = 3

Line equation: y = 3x + b
Plug in point (1, 10): 10 = 3(1) + b → b = 7

Secret = f(0) = b = 7  ✓
```

Parties 1 and 3 have points (1, 10) and (3, 16):
```
Slope = (16 - 10) / (3 - 1) = 6/2 = 3

Line equation: y = 3x + b
Plug in point (1, 10): 10 = 3(1) + b → b = 

Secret = 7  ✓
```

Parties 2 and 3 have points (2, 13) and (3, 16):
```
Slope = (16 - 13) / (3 - 2) = 3/1 = 3

Line equation: y = 3x + b
Plug in point (2, 13): 13 = 3(2) + b → b = 7

Secret = 7  ✓
```

**What about Party 3 alone?**

Party 3 has only one point: (3, 16). One point doesn't define a line — infinitely many lines pass through a single point. Party 3 could be on the line `y = 3x + 7` (secret=7), or `y = 5x + 1` (secret=1), or `y = 100x - 284` (secret=-284). All are equally valid. Party 3 learns absolutely nothing about the secret.

This is threshold security: 2 parties → can reconstruct. 1 party → learns nothing.

---

## 5. Lagrange Coefficients — Magic Weights for Signing

### The Problem We're Solving

We want to sign without ever assembling the private key. We know:
- Party 1 has share `x₁ = 10`
- Party 2 has share `x₂ = 13`
- Private key (secret) = 7

We need some way for parties 1 and 2 to each contribute their partial work, and when combined, produce a result as if the private key 7 was used — but neither party should ever compute 7.

### The Solution: Weighted Combination

The Lagrange interpolation formula tells us: if we have points on a polynomial, we can evaluate the polynomial at any point as a weighted sum of the known values.

For our 2-of-3 case with secret at `x=0`:

**Subset {1, 2}:**
```
λ₁ = 2/(2-1) = 2   (reading: "at x=0, using points at x=1 and x=2, Party 1's weight")
λ₂ = 1/(1-2) = -1  (Party 2's weight)

Verification:
x₁·λ₁ + x₂·λ₂ = 10·2 + 13·(-1) = 20 - 13 = 7  ✓
```

**Subset {1, 3}:**
```
λ₁ = 3/(3-1) = 3/2
λ₃ = 1/(1-3) = -1/2

Verification:
x₁·λ₁ + x₃·λ₃ = 10·(3/2) + 16·(-1/2) = 15 - 8 = 7  ✓
```

**Subset {2, 3}:**
```
λ₂ = 3/(3-2) = 3
λ₃ = 2/(2-3) = -2

Verification:
x₂·λ₂ + x₃·λ₃ = 13·3 + 16·(-2) = 39 - 32 = 7  ✓
```

The Lagrange coefficient formula for evaluating at `x=0`, party `i` in subset `S`, is:

```
λᵢ = ∏(j ∈ S, j≠i)  j / (j - i)
```

### Why This Enables Threshold Signing

In ECDSA signing, the private key `x` enters the protocol as `x·k⁻¹ mod n` (roughly). With threshold signing:

- Each party computes `xᵢ·λᵢ` — their **adjusted share**
- They run the partial signing protocol using this adjusted share
- Because `x₁·λ₁ + x₂·λ₂ = x` (the real private key), the partial results add up to the same final signature as if the full key `x` was used

The private key is never assembled. The math just works out because of how Lagrange interpolation is constructed.

---

## 6. DKG Sub-Share Distribution — Why Party 1 Sends f₁(2) to Party 2

This is the step that confuses people most. Let's be very precise about what's happening and why.

### Goal

Each party should end up with a Shamir share of the **combined** secret `x = x₁ + x₂ + x₃`, where each `xᵢ` is Party i's secret contribution. Nobody should know the others' contributions.

### What Each Party Does

**Party 1:**
- Picks secret contribution `x₁` (say, 3)
- Picks random slope `a₁` (say, 2)
- Defines polynomial: `f₁(z) = 3 + 2z`
- Evaluates it at each party's index and sends secretly:
  - Keeps `f₁(1) = 3 + 2(1) = 5` (their own sub-share)
  - Sends `f₁(2) = 3 + 2(2) = 7` to Party 2 (encrypted/secret)
  - Sends `f₁(3) = 3 + 2(3) = 9` to Party 3 (encrypted/secret)

**Party 2:**
- Picks secret contribution `x₂ = 5`, random slope `a₂ = 1`
- Defines polynomial: `f₂(z) = 5 + 1z`
- Keeps `f₂(2) = 5 + 1(2) = 7`
- Sends `f₂(1) = 5 + 1(1) = 6` to Party 1
- Sends `f₂(3) = 5 + 1(3) = 8` to Party 3

**Party 3:**
- Picks `x₃ = 4`, slope `a₃ = 3`
- Defines polynomial: `f₃(z) = 4 + 3z`
- Keeps `f₃(3) = 4 + 3(3) = 13`
- Sends `f₃(1) = 4 + 3(1) = 7` to Party 1
- Sends `f₃(2) = 4 + 3(2) = 10` to Party 2

### Each Party's Final Share = Sum of What They Received

```
Party 1's final share: X₁ = f₁(1) + f₂(1) + f₃(1) = 5 + 6 + 7 = 18
Party 2's final share: X₂ = f₁(2) + f₂(2) + f₃(2) = 7 + 7 + 10 = 24
Party 3's final share: X₁ = f₁(3) + f₂(3) + f₃(3) = 9 + 8 + 13 = 30
```

### Why Does This Give a Valid Shamir Share?

The combined secret is `x = x₁ + x₂ + x₃ = 3 + 5 + 4 = 12`.

The combined polynomial is `F(z) = f₁(z) + f₂(z) + f₃(z)`.

```
F(z) = (3 + 2z) + (5 + z) + (4 + 3z)
     = 12 + 6z

F(0) = 12 = x  ✓ (the combined secret is at x=0)
F(1) = 12 + 6 = 18 = X₁  ✓
F(2) = 12 + 12 = 24 = X₂  ✓
F(3) = 12 + 18 = 30 = X₃  ✓
```

Each party's final share is a point on the combined polynomial! And the combined secret `12` is at `z=0`.

**Why Party 1 sends f₁(2) to Party 2, specifically:**

Party 2's index is `2`. The combined polynomial `F` evaluated at `2` must equal `X₂`. By linearity: `F(2) = f₁(2) + f₂(2) + f₃(2)`. So Party 2 needs a contribution from *every* party's polynomial, evaluated *at index 2*. Party 1's polynomial evaluated at 2 is `f₁(2)` — that's exactly what Party 1 sends to Party 2.

The index in the evaluation matches the recipient's party number. Party `j` receives `fᵢ(j)` from every Party `i`, and sums them up to get their share.

---

## 7. Feldman VSS — How Parties Verify the Sub-Shares Are Honest

### The Problem

When Party 1 sends `f₁(2) = 7` to Party 2, Party 2 has no way to verify that:
1. Party 1 actually used a polynomial (and not just a random number)
2. The value 7 is actually on that polynomial

A cheating Party 1 could send garbage sub-shares, resulting in a corrupted combined key that nobody can use — or worse, a key that Party 1 secretly controls.

### The Solution: Feldman Commitments

Before distributing sub-shares, each party publishes **Feldman commitments**: the EC points corresponding to their polynomial coefficients.

**Party 1's polynomial:** `f₁(z) = 3 + 2z`
- Coefficient 0: `3` → publishes `C₁₀ = 3·G`
- Coefficient 1: `2` → publishes `C₁₁ = 2·G`

These commitments are public, on-chain. Anyone can see them.

**Verification by Party 2:**

Party 2 received `f₁(2) = 7` from Party 1. To verify this is on the committed polynomial:

Party 2 computes two things and checks they match:

```
Left side:  f₁(2) · G = 7·G   (scale the received value by G)

Right side: C₁₀ + 2·C₁₁ = 3·G + 2·(2·G) = 3·G + 4·G = 7·G  ✓
```

The formula is: for party `j` receiving `fᵢ(j)`, the check is:

```
fᵢ(j)·G  =?=  Σₖ  j^k · Cᵢₖ
```

(The right side is the polynomial evaluated using the *public commitments*.)

This works because EC scalar multiplication is linear: `(a + bz)·G = a·G + z·(b·G)`. If the value received is on the correct polynomial, both sides equal the same EC point. If Party 1 cheated, the point won't match.

**What Party 2 cannot do:** learn Party 1's secret `x₁ = 3` from seeing `3·G`. The discrete log problem makes this computationally infeasible. So the commitment is binding (can't cheat) but hiding (doesn't reveal the secret).

### In Our Implementation

In `dkg.rs`, the Feldman commitments are the `commitments` field published for each party. The ZK nodes verify incoming sub-shares against these commitments. If any verification fails, the party is marked as a cheater and the DKG aborts.

---

## 8. What Changes in the Code

### DKG (Key Generation)

**Current system** — each party contributes one number:
1. Party `i` picks a random scalar `sᵢ`
2. Publishes `sᵢ·G` on-chain (the public commitment)
3. Their share IS `sᵢ` — done

**New system** — each party contributes a line (degree-1 polynomial):
1. Party `i` picks two random numbers `sᵢ` (constant) and `aᵢ` (slope), defining `fᵢ(z) = sᵢ + aᵢ·z`
2. Publishes two EC points on-chain: `Cᵢ₀ = sᵢ·G` and `Cᵢ₁ = aᵢ·G` (Feldman commitments)
3. Secretly sends Party `j` the value `fᵢ(j)` as a ZK secret input
4. Each party verifies all received sub-shares against the Feldman commitments
5. Final share for Party `j`: `Xⱼ = Σᵢ fᵢ(j)` (sum of all sub-shares received)

The combined public key is `X·G = Σᵢ Cᵢ₀` — the sum of all parties' constant-term commitments.

**Why this is more complex to implement in Partisia:**
- Sub-shares must be sent as ZK secret inputs from one party to another
- The Feldman commitments go on-chain as public data
- Verification happens inside the ZK program (which can access both the public commitments and the private sub-share values)
- The ZK compiler's `#[zk_on_variable_inputted]` callback fires when a sub-share arrives, triggering verification

### Signing

**Current system:** each party uses their share `xᵢ` directly.

**New system:** before signing, multiply by the Lagrange weight for the active signing subset.

```typescript
// Determine which parties are signing (e.g., parties 1 and 2 out of {1,2,3})
const signingSet = [1, 2];

// Compute Lagrange coefficient for this party in this subset
const lambda = lagrangeCoefficient(myIndex, signingSet, CURVE_ORDER);
// For myIndex=1, signingSet=[1,2]: lambda = 2n  (as BigInt mod curve order)
// For myIndex=2, signingSet=[1,2]: lambda = CURVE_ORDER - 1n  (i.e., -1 mod n)

// Apply the adjustment — one multiplication
const adjustedShare = (lambda * myShare) % CURVE_ORDER;

// Then run the exact same GG20 signing protocol with adjustedShare
```

That's it. Everything else in the signing protocol stays the same. One multiplication before you start.

**The Lagrange coefficient function:**
```typescript
function lagrangeCoefficient(i: bigint, S: bigint[], order: bigint): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of S) {
    if (j === i) continue;
    num = (num * j) % order;
    den = (den * ((j - i + order) % order)) % order;
  }
  // num/den mod order = num * modInverse(den, order)
  return (num * modInverse(den, order)) % order;
}
```

---

## 9. Partisia-Specific Implementation Challenges

### Challenge 1: ZK Nodes Don't Trigger `#[off_chain_on_state_change]`

On testnet, the `#[off_chain_on_state_change]` attribute does NOT fire on ZK nodes. This means any logic that was supposed to run automatically when state changes (e.g., "when all sub-shares are received, compute the combined share") must be triggered by an explicit on-chain transaction instead.

**Workaround:** Use an explicit `trigger_computation` transaction with a shortname. The client sends this after all parties have submitted their sub-shares.

### Challenge 2: `SecretVarId` Is Non-Exhaustive

You cannot construct a `SecretVarId` using struct literal syntax. Use the constructor:

```rust
// Wrong — won't compile:
let id = SecretVarId { id: 42 };

// Correct:
let id = SecretVarId::new(42);
```

### Challenge 3: Nested `Vec<CustomStruct>` Crashes the ABI Parser

The Partisia ABI parser crashes when the contract state contains `Vec<YourCustomStruct>`. Flatten to parallel vectors of primitives:

```rust
// Crashes ABI parser:
pub struct State {
    pub parties: Vec<PartyInfo>,  // PartyInfo is a custom struct
}

// Works:
pub struct State {
    pub party_addresses: Vec<SomePartiaType>,
    pub party_commitments_x: Vec<Vec<u8>>,  // parallel fields
    pub party_commitments_y: Vec<Vec<u8>>,
}
```

### Challenge 4: Deploy Must Be Done via TypeScript

The Partisia CLI cannot parse `Vec<EngineConfig>` init arguments. Deploy using `DeploymentBuilder` + `BlockchainClientForDeploymentImpl` from the TypeScript SDK. The init RPC must include the ZK init shortname prefix (`0xffffffff0f`) before the encoded arguments.

### Challenge 5: ZK Node Addresses vs Engine Addresses

ZK node addresses are assigned at **deploy time** by the network, not the engine addresses visible in contract state. When sending secret inputs (sub-shares), target the ZK node addresses, not the engine addresses. These are returned by the deployment response and should be stored for later use.

### Challenge 6: Modular Arithmetic Must Use `mod_floor` Not `%`

In Rust with big integers, the `%` operator gives signed remainder, not true modular reduction. For values that can go negative (like `j - i` in the Lagrange formula), use `mod_floor` or always add the modulus first:

```rust
// Risky — can produce negative result:
let diff = (j - i) % ORDER;

// Safe — always positive:
let diff = ((j as i64 - i as i64).rem_euclid(ORDER as i64)) as u64;
```

---

## 10. The Real Production Flow — End to End

This section walks through exactly what happens in a production system, in order, with no hand-waving.

---

### Phase 0: Deploy the Contract (Once)

Someone (the "coordinator") deploys the ZK signer contract on Partisia. The contract is initialized knowing:
- How many parties there are (3)
- The threshold (2)
- The ZK node addresses (assigned by the network at deploy time — these are NOT the engine addresses in state)

The contract is deployed using TypeScript (`DeploymentBuilder`), not the CLI.

```
Coordinator → deploys ZK contract → gets back:
  - contract address (e.g. 0x03a1...)
  - ZK node addresses [node1, node2, node3]
```

The contract sits idle, waiting.

---

### Phase 1: DKG — Generating the Shared Key (Once per wallet)

This is a 3-round ceremony that runs completely distributed. No single party ever holds the full private key.

**Round 1: Commit (each party, one transaction each)**

Each party `i` locally:
1. Generates their secret polynomial `fᵢ(z) = sᵢ + aᵢ·z` (two random scalars)
2. Computes Feldman commitments: `Cᵢ₀ = sᵢ·G`, `Cᵢ₁ = aᵢ·G`
3. Commits a hash of these to the contract (not the actual values yet — commit then reveal prevents frontrunning)

Contract collects 3 commits, then opens a reveal window.

**Round 2: Reveal + Sub-Share Distribution**

Each party `i`:
1. Reveals `Cᵢ₀` and `Cᵢ₁` on-chain (now visible to everyone)
2. Sends `fᵢ(j)` **secretly** to each other party `j` — as a ZK secret input to the contract's ZK nodes
   - `fᵢ(1)` → to Party 1 (or keeps it if i=1)
   - `fᵢ(2)` → to Party 2
   - `fᵢ(3)` → to Party 3

The sub-shares travel encrypted over the ZK channel. The on-chain contract state never sees these raw values.

**Round 3: Verify + Combine (inside the ZK program)**

Inside the ZK computation (running on ZK nodes, not visible):
1. Each party's received sub-shares are summed: `Xⱼ = f₁(j) + f₂(j) + f₃(j)`
2. Each sub-share is verified against the Feldman commitments: `fᵢ(j)·G == Cᵢ₀ + j·Cᵢ₁`
3. If all pass → each party's final share `Xⱼ` is stored as a ZK secret variable

On-chain (public), the contract publishes the combined public key:
```
PubKey = C₁₀ + C₂₀ + C₃₀  =  s₁·G + s₂·G + s₃·G  =  (s₁+s₂+s₃)·G
```

This EC point IS the wallet's public key → the Ethereum address derivable from it.

**Result of DKG:**
- Each party `j` holds their final share `Xⱼ` (stored as a ZK secret, never leaves the ZK nodes in plaintext)
- The world knows the public key (can receive funds)
- Nobody knows the private key

---

### Phase 2: Signing a Transaction

Someone wants to send funds from the wallet. Two of the three parties need to sign.

**Step 1: Initiate**

The coordinator (or any party) posts a signing request on-chain:
```
"Sign this transaction hash: 0xdeadbeef..."
```

Parties 1 and 2 are online and agree to sign. Party 3 is offline.

**Step 2: Commit nonce (GG20 Round 1)**

Each signing party locally picks a random nonce `kᵢ` (the "signing nonce", like a one-time pad).

Each party:
1. Computes `kᵢ·G` and publishes it on-chain (commitment to nonce)
2. The combined nonce point is: `R = k₁·G + k₂·G = (k₁+k₂)·G`
3. The r-value of the signature = x-coordinate of `R`

**Step 3: Apply Lagrange and sign**

Each party `i` in signing set `S = {1, 2}`:
1. Computes `λᵢ` — the Lagrange coefficient for their index in subset `S`
   - Party 1: `λ₁ = 2`
   - Party 2: `λ₂ = -1 mod n`
2. Computes **adjusted share**: `x̃ᵢ = λᵢ · Xᵢ mod n`
   - This is one scalar multiplication. Done locally.
3. Computes their partial signature inside ZK:
   ```
   sᵢ = kᵢ⁻¹ · (hash + r · x̃ᵢ) mod n
   ```
   (This is ECDSA's `s` computation, but using the adjusted share and their own nonce inverse)

**Step 4: Combine**

The partial signatures are summed inside the ZK computation:
```
s = s₁ + s₂ mod n
```

This sum is mathematically identical to what you'd get if the full private key `x = x₁·λ₁ + x₂·λ₂` was used with a single combined nonce. So it's a valid ECDSA signature.

**Step 5: Output**

The ZK program opens/reveals `(r, s)` — the final ECDSA signature. This goes on-chain and can be verified by anyone against the public key.

The private key was never assembled anywhere. Party 3 was never involved.

---

### What Each Party Stores Permanently

```
Party 1 stores:  X₁  (their Shamir share — a 32-byte scalar)
Party 2 stores:  X₂
Party 3 stores:  X₃

Public (on-chain):  PubKey  (the wallet's EC point)
```

That's all. No other state needs to persist between signings.

---

### What Happens If Party 3 Comes Back Later

Nothing special. Party 3 still has their share `X₃`. If later parties 2 and 3 want to sign without Party 1:
- They compute Lagrange weights for subset `{2, 3}`:
  - `λ₂ = 3`, `λ₃ = -2`
- Each adjusts their share: `x̃₂ = 3·X₂`, `x̃₃ = -2·X₃`
- Run the same protocol → valid signature

The public key is the same. The wallet address is the same. Any 2-of-3 combination always produces a valid signature for the same key.

---

### Timeline Summary

```
Deploy contract  →  DKG ceremony (3 rounds)  →  Wallet is live
                                                      ↓
                              User wants to sign a transaction
                                                      ↓
                         2 parties online → initiate signing
                                                      ↓
                     Round 1: commit nonces (r-value commitment)
                                                      ↓
                     Round 2: partial sigs with adjusted shares
                                                      ↓
                     Combine → reveal (r, s) → valid signature
                                                      ↓
                              Transaction is broadcast
```

---

### The Golden Rules

1. **The private key is never at any one place.** Not during DKG, not during signing.
2. **Lagrange is just a pre-multiplication.** All the threshold magic is one line before the normal signing math.
3. **Sub-shares are the core of DKG.** Party `i` sends `fᵢ(j)` to Party `j` so that Party `j`'s final share lands on the combined polynomial.
4. **Feldman keeps everyone honest.** The on-chain commitments `Cᵢₖ = aₖ·G` let anyone verify a sub-share without learning the underlying scalar.
5. **ZK nodes are the trust anchor.** They hold the final shares as secrets. They run the combining and signing math. The on-chain contract orchestrates the rounds but never sees raw key material.

---

## Quick Reference

| | Current (Additive, 3-of-3) | Target (Shamir, 2-of-3) |
|---|---|---|
| How key is split | `s = s₁ + s₂ + s₃` | Each party holds a point on a combined polynomial |
| Who must sign | All 3 parties | Any 2 out of 3 |
| If one party offline | Broken | Fine, continue without them |
| DKG change | Each party picks one number `sᵢ`, publishes `sᵢ·G` | Each party picks a line `fᵢ(z)`, publishes 2 EC points, sends sub-shares |
| Sub-share from i to j | N/A | `fᵢ(j)` — Party i's polynomial evaluated at j's index |
| Feldman verification | N/A | `fᵢ(j)·G == Σₖ jᵏ·Cᵢₖ` |
| Signing change | Use `xᵢ` directly | Multiply `xᵢ` by Lagrange weight `λᵢ` first |
| Lagrange weights depend on | N/A | Which subset of parties is signing |
| Private key ever assembled | No | Still no |
| Partisia deploy | CLI | TypeScript `DeploymentBuilder` only |
