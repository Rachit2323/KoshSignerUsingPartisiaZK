import "./styles.css";
import {
  buildEthTransfer,
  getTransactionSigningHash,
  parseSignatureBytes,
  signTransaction,
  submitSignedTransaction,
  type BrowserThresholdKeyStatus,
} from "./evm-browser";
import { hexToBytes, type Hex } from "viem";

type FrontendMode = "existing" | "create";

type JobRecord = {
  id: string;
  status: string;
  phase: string;
  logs: string[];
  error: string | null;
  updatedAt?: string;
  result?: Record<string, unknown> | null;
  activeContractAddress?: string;
  activeKeyId?: number;
  evmTxHash?: string | null;
  createdEvmAddress?: string | null;
  createdPublicKeyHex?: string | null;
};

type RuntimeSummary = {
  mode: string;
  contractAddress: string;
  keyId: number;
  senderAddress: string;
  evmAddress: string | null;
  updatedAt: string;
};

type RuntimeJobSummary = {
  id: string;
  type: string;
  status: string;
};

type RuntimeActivePayload = {
  parties_up: number;
  running_jobs: RuntimeJobSummary[];
  sender_address?: string;
  sender_mode?: string;
};

type PasskeyLinkedKey = {
  contract_address: string;
  key_id: number;
  label: string;
};

type PasskeyAccount = {
  account_id: string;
  label: string;
  linked_keys: PasskeyLinkedKey[];
  selected_key: PasskeyLinkedKey | null;
};

type RuntimePreflight = {
  ok: boolean;
  backend_reachable: boolean;
  relay_configured: boolean;
  sender_address: string | null;
  sender_gas_balance: number | null;
  sender_gas_ok: boolean;
  local_runtime_present: boolean;
  key_exists_onchain: boolean;
  can_create: boolean;
  can_sign: boolean;
  recommended_mint_command: string | null;
  message: string;
};

type SignSession = {
  jobId: string;
  contractAddress: string;
  keyId: number;
  signingHash: Hex;
  unsignedTx: Record<string, unknown>;
  evmAddress: Hex;
};

type AppState = {
  mode: FrontendMode;
  signerAddress: string;
  keyId: number;
  numParties: number;
  recipient: Hex;
  amountWei: string;
  apiBaseUrl: string;
  passkeySessionToken: string | null;
  passkeyAccount: PasskeyAccount | null;
  status: BrowserThresholdKeyStatus | null;
  signingHash: Hex | null;
  txPreview: string | null;
  unsignedTx: Record<string, unknown> | null;
  latestVerifiedTaskId: number | null;
  latestSignatureHex: Hex | null;
  latestSepoliaTxHash: string | null;
  currentJob: JobRecord | null;
  activeSignSession: SignSession | null;
  runtimeActive: RuntimeActivePayload | null;
  error: string | null;
};

const storageKey = "kosh-frontend-threshold-state-v5";
const defaultContractAddress = "0353980c937b95faac89ee9af366471b64d9206f2e";
const defaultKeyId = 63001;
const defaultRecipient = "0xb0538910f0Abffc41F0CF701E626975E51e92bC7" as Hex;
const defaultApiBaseUrl = "http://127.0.0.1:8080";
const legacyContractAddresses = new Set([
  "03d69b9a696147c8545aa580b2e528e69928d171e5",
  "031fb3ede8b7274ffb94ef250ba3747e49b2706d12",
  "03a1e8aba3ba45c1e42d01f688768436cb2b572de0",
]);

function normalizeSignerAddress(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return defaultContractAddress;
  if (legacyContractAddresses.has(trimmed)) return defaultContractAddress;
  return trimmed;
}

const state: AppState = {
  mode: load("mode", "existing") as FrontendMode,
  signerAddress: normalizeSignerAddress(load("signerAddress", defaultContractAddress)),
  keyId: Number(load("keyId", String(defaultKeyId))),
  numParties: Number(load("numParties", "3")),
  recipient: load("recipient", defaultRecipient) as Hex,
  amountWei: load("amountWei", "1000000000000000"),
  apiBaseUrl: load("apiBaseUrl", defaultApiBaseUrl),
  passkeySessionToken: load("passkeySessionToken", "") || null,
  passkeyAccount: null,
  status: null,
  signingHash: null,
  txPreview: null,
  unsignedTx: null,
  latestVerifiedTaskId: null,
  latestSignatureHex: null,
  latestSepoliaTxHash: null,
  currentJob: null,
  activeSignSession: null,
  runtimeActive: null,
  error: null,
};

const app = document.querySelector<HTMLDivElement>("#app")!;
if (!app) throw new Error("Missing #app");

let pollTimer: number | null = null;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function load(key: string, fallback: string): string {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw) as Record<string, string>;
    return parsed[key] ?? fallback;
  } catch {
    return fallback;
  }
}

function persist(): void {
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      mode: state.mode,
      signerAddress: state.signerAddress,
      keyId: String(state.keyId),
      numParties: String(state.numParties),
      recipient: state.recipient,
      amountWei: state.amountWei,
      apiBaseUrl: state.apiBaseUrl,
      passkeySessionToken: state.passkeySessionToken ?? "",
    }),
  );
}

function setError(message: string | null): void {
  state.error = message;
  render();
}

function displayLinkedKeyLabel(key: PasskeyLinkedKey, index: number): string {
  return /(^|\s)(key)\s+\d+/i.test(key.label) || /kosh key/i.test(key.label) ? `Linked Key ${index + 1}` : key.label;
}

function baseUrl(): string {
  return state.apiBaseUrl.replace(/\/$/, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toCreationOptions(options: any): PublicKeyCredentialCreationOptions {
  return {
    ...options.publicKey,
    challenge: base64UrlToBytes(options.publicKey.challenge),
    user: {
      ...options.publicKey.user,
      id: base64UrlToBytes(options.publicKey.user.id),
    },
    excludeCredentials: (options.publicKey.excludeCredentials ?? []).map((cred: any) => ({
      ...cred,
      id: base64UrlToBytes(cred.id),
    })),
  };
}

function toRequestOptions(options: any): PublicKeyCredentialRequestOptions {
  return {
    ...options.publicKey,
    challenge: base64UrlToBytes(options.publicKey.challenge),
    allowCredentials: (options.publicKey.allowCredentials ?? []).map((cred: any) => ({
      ...cred,
      id: base64UrlToBytes(cred.id),
    })),
  };
}

function registrationToJson(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function authenticationToJson(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function passkeyFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  if (state.passkeySessionToken) headers.set("x-kosh-session", state.passkeySessionToken);
  const resp = await fetch(`${baseUrl()}${path}`, { ...init, headers });
  // Session expired (server restarted) — clear stale token so UI shows sign-in buttons
  if (resp.status === 401 || resp.status === 403) {
    const clone = resp.clone();
    const body = await clone.json().catch(() => ({})) as Record<string, unknown>;
    if (typeof body.error === "string" && body.error.includes("session")) {
      state.passkeySessionToken = null;
      state.passkeyAccount = null;
      persist();
      throw new Error("Session expired — please sign in with your passkey again.");
    }
  }
  return resp;
}

function nextSessionId(): number {
  return Math.floor(Date.now() / 1000) >>> 0;
}

async function parseApiBody(resp: Response): Promise<unknown> {
  const raw = await resp.text();
  if (!raw) return null;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return { error: raw };
  }
}

function stringifyTx(tx: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(tx, (_k, value) => (typeof value === "bigint" ? value.toString() : value)));
}

function reviveUnsignedTx(tx: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(tx));
}

function txReady(): boolean {
  return Boolean(state.signingHash && state.unsignedTx);
}

function alternateBaseUrls(url: string): string[] {
  const trimmed = url.replace(/\/+$/, "");
  const options = [trimmed];
  if (trimmed.includes("127.0.0.1")) {
    options.push(trimmed.replace("127.0.0.1", "localhost"));
  } else if (trimmed.includes("localhost")) {
    options.push(trimmed.replace("localhost", "127.0.0.1"));
  }
  return [...new Set(options)];
}

function hasSelectedPasskeyKey(): boolean {
  return Boolean(state.passkeyAccount?.selected_key);
}

function effectiveEvmAddress(): string | null {
  return state.status?.evmAddress ?? state.currentJob?.createdEvmAddress ?? null;
}

function canBuildTx(): boolean {
  return Boolean(
    effectiveEvmAddress() &&
    state.recipient &&
    /^[0-9]+$/.test(state.amountWei) &&
    BigInt(state.amountWei || "0") > 0n,
  );
}

function canStartSigning(): boolean {
  return Boolean(
    state.passkeySessionToken &&
    hasSelectedPasskeyKey() &&
    state.status?.exists &&
    !state.activeSignSession,
  );
}

async function ensureBackendAvailable(): Promise<void> {
  let lastError: unknown = null;
  for (const candidate of alternateBaseUrls(baseUrl())) {
    try {
      const resp = await fetch(`${candidate}/api/v1/health`);
      if (!resp.ok) {
        lastError = new Error(`Rust backend health check failed: ${resp.status}`);
        continue;
      }
      if (state.apiBaseUrl !== candidate) {
        state.apiBaseUrl = candidate;
        persist();
      }
      if (state.error?.includes("Cannot reach Rust backend")) {
        state.error = null;
        render();
      }
      return;
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(`Cannot reach Rust backend at ${baseUrl()}. Start the backend and confirm CORS is enabled. (${lastError instanceof Error ? lastError.message : String(lastError)})`);
}

async function fetchPreflight(mode: "create" | "sign"): Promise<RuntimePreflight> {
  await ensureBackendAvailable();
  const resp = await fetch(
    `${baseUrl()}/api/v1/runtime/preflight?contract_address=${encodeURIComponent(state.signerAddress)}&key_id=${state.keyId}&mode=${mode}`,
  );
  if (!resp.ok) throw new Error(`Failed to run backend preflight: ${resp.status}`);
  const body = (await resp.json()) as { preflight?: RuntimePreflight };
  if (!body.preflight) throw new Error("Backend preflight returned no data.");
  return body.preflight;
}

function normalizeJob(job: Record<string, unknown>): JobRecord {
  const result = (job.result as Record<string, unknown> | null | undefined) ?? null;
  return {
    id: String(job.id ?? ""),
    status: String(job.status ?? "idle").toLowerCase(),
    phase: String(job.phase ?? "queued").toLowerCase(),
    logs: Array.isArray(job.logs) ? job.logs.map((value) => String(value)) : [],
    error: typeof job.error === "string" ? job.error : null,
    updatedAt: typeof job.updated_at === "string" ? String(job.updated_at) : undefined,
    result,
    activeContractAddress:
      typeof result?.contract_address === "string" ? String(result.contract_address) : undefined,
    activeKeyId: typeof result?.key_id === "number" ? Number(result.key_id) : undefined,
    evmTxHash:
      typeof (result?.sepolia_broadcast as Record<string, unknown> | undefined)?.tx_hash === "string"
        ? String((result?.sepolia_broadcast as Record<string, unknown>).tx_hash)
        : null,
    createdEvmAddress: typeof result?.evm_address === "string" ? String(result.evm_address) : null,
    createdPublicKeyHex: typeof result?.public_key_hex === "string" ? String(result.public_key_hex) : null,
  };
}

function normalizeThresholdStatus(raw: BrowserThresholdKeyStatus): BrowserThresholdKeyStatus {
  const status = { ...raw } as BrowserThresholdKeyStatus & {
    public_key_hex?: string;
    combined_pk_hex?: string;
    verified_task_ids?: (string | number)[];
    keygen_phase_discriminant?: number;
  };
  status.evmAddress = status.evmAddress ?? status.evm_address;
  status.publicKeyHex = status.publicKeyHex ?? status.public_key_hex ?? status.combined_pk_hex;
  status.keygenPhaseDiscriminant =
    status.keygenPhaseDiscriminant ?? status.keygen_phase_discriminant;
  status.verifiedTaskIds = status.verifiedTaskIds ?? status.verified_task_ids ?? [];
  return status;
}

function applyCreatedKeyResult(job: JobRecord): void {
  state.status = normalizeThresholdStatus({
    key_id: state.keyId,
    exists: true,
    evm_address: job.createdEvmAddress ?? undefined,
    public_key_hex: job.createdPublicKeyHex ?? undefined,
    verifiedTaskIds: [],
    phase: 0,
  } as BrowserThresholdKeyStatus);
}

async function refreshPasskeyMe(): Promise<void> {
  if (!state.passkeySessionToken) return;
  let resp: Response;
  try {
    resp = await passkeyFetch('/api/v1/passkeys/me');
  } catch {
    // passkeyFetch throws when session is stale — already cleared token
    render();
    return;
  }
  if (!resp.ok) {
    state.passkeySessionToken = null;
    state.passkeyAccount = null;
    persist();
    render();
    return;
  }
  const body = (await resp.json()) as { me?: { authenticated: boolean; account?: PasskeyAccount | null } };
  if (!body.me?.authenticated) {
    state.passkeySessionToken = null;
    state.passkeyAccount = null;
    persist();
    render();
    return;
  }
  state.passkeyAccount = body.me?.account ?? null;
  const selected = state.passkeyAccount?.selected_key ?? null;
  if (selected) {
    state.signerAddress = selected.contract_address;
    state.keyId = selected.key_id;
  }
  persist();
  if (selected) {
    await handleLoadKey().catch(() => undefined);
  } else {
    state.status = null;
    state.signingHash = null;
    state.txPreview = null;
    state.unsignedTx = null;
    state.currentJob = null;
    render();
  }
}

async function handlePasskeyRegister(): Promise<void> {
  try {
    setError(null);
    const resp = await fetch(`${baseUrl()}/api/v1/passkeys/register/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: state.passkeyAccount?.label ?? 'Kosh Passkey',
        contract_address: state.status?.exists ? state.signerAddress : null,
        key_id: state.status?.exists ? state.keyId : null,
      }),
    });
    const start = await parseApiBody(resp) as { registration_id?: string; options?: any; error?: string } | null;
    if (!resp.ok || !start?.registration_id || !start?.options) throw new Error(start && typeof start === "object" && "error" in start && typeof start.error === "string" ? start.error : 'Failed to start passkey registration.');
    const credential = await navigator.credentials.create({ publicKey: toCreationOptions(start.options) }) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey registration was cancelled.');
    const finishResp = await fetch(`${baseUrl()}/api/v1/passkeys/register/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ registration_id: start.registration_id, credential: registrationToJson(credential) }),
    });
    const finish = await parseApiBody(finishResp) as { session_token?: string; account?: PasskeyAccount; error?: string } | null;
    if (!finishResp.ok || !finish?.session_token || !finish?.account) {
      throw new Error(finish && typeof finish === "object" && "error" in finish && typeof finish.error === "string" ? finish.error : 'Failed to finish passkey registration.');
    }
    state.passkeySessionToken = finish.session_token;
    state.passkeyAccount = finish.account;
    persist();
    render();
    if (!state.passkeyAccount?.linked_keys?.length) {
      state.error = null;
      render();
    }
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function handlePasskeySignIn(): Promise<void> {
  try {
    setError(null);
    const startResp = await fetch(`${baseUrl()}/api/v1/passkeys/auth/start`, { method: 'POST' });
    const start = await parseApiBody(startResp) as { authentication_id?: string; options?: any; error?: string } | null;
    if (!startResp.ok || !start?.authentication_id || !start?.options) throw new Error(start && typeof start === "object" && "error" in start && typeof start.error === "string" ? start.error : 'Failed to start passkey authentication.');
    const credential = await navigator.credentials.get({ publicKey: toRequestOptions(start.options) }) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey sign-in was cancelled.');
    const finishResp = await fetch(`${baseUrl()}/api/v1/passkeys/auth/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authentication_id: start.authentication_id, credential: authenticationToJson(credential) }),
    });
    const finish = await parseApiBody(finishResp) as { session_token?: string; account?: PasskeyAccount; error?: string } | null;
    if (!finishResp.ok || !finish?.session_token || !finish?.account) {
      throw new Error(finish && typeof finish === "object" && "error" in finish && typeof finish.error === "string" ? finish.error : 'Failed to finish passkey authentication.');
    }
    state.passkeySessionToken = finish.session_token;
    state.passkeyAccount = finish.account;
    const selected = finish.account.selected_key ?? finish.account.linked_keys[0] ?? null;
    if (selected) {
      state.signerAddress = selected.contract_address;
      state.keyId = selected.key_id;
      await handleLoadKey();
    }
    persist();
    render();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function handleSelectPasskeyKey(contractAddress: string, keyId: number): Promise<void> {
  try {
    const resp = await passkeyFetch('/api/v1/passkeys/select-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contract_address: contractAddress, key_id: keyId }),
    });
    const body = await resp.json() as { account?: PasskeyAccount };
    if (!resp.ok || !body.account) throw new Error('Failed to select linked key.');
    state.passkeyAccount = body.account;
    state.signerAddress = contractAddress;
    state.keyId = keyId;
    persist();
    await handleLoadKey();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function maybeLinkCreatedKeyToPasskey(): Promise<void> {
  if (!state.passkeySessionToken) return;
  const resp = await passkeyFetch('/api/v1/passkeys/link-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contract_address: state.signerAddress,
      key_id: state.keyId,
      label: `Kosh Key ${state.keyId}`,
      combined_pk_hex: state.status?.combined_pk_hex ?? state.status?.evmAddress ?? "",
      evm_address: state.status?.evmAddress ?? "",
    }),
  });
  if (!resp.ok) return;
  const body = await resp.json() as { account?: PasskeyAccount };
  if (body.account) {
    state.passkeyAccount = body.account;
    // Auto-select the newly linked key so Build Transaction works immediately
    if (!state.passkeyAccount.selected_key && state.passkeyAccount.linked_keys.length > 0) {
      const newest = state.passkeyAccount.linked_keys[state.passkeyAccount.linked_keys.length - 1];
      state.passkeyAccount.selected_key = newest;
      // Also persist the selection on the server
      passkeyFetch('/api/v1/passkeys/select-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contract_address: newest.contract_address, key_id: newest.key_id }),
      }).catch(() => undefined);
    }
    persist();
  }
}

async function syncSelectedPasskeyKey(): Promise<void> {
  const selected = state.passkeyAccount?.selected_key ?? null;
  if (!selected) return;
  state.signerAddress = selected.contract_address;
  state.keyId = selected.key_id;
  persist();
}

async function handleLoadKey(): Promise<void> {
  try {
    await ensureBackendAvailable();
    if (!state.signerAddress || !state.keyId) throw new Error("Enter a contract address and key ID first.");
    setError(null);
    const statusResp = await fetch(
      `${baseUrl()}/api/v1/threshold/key-status?contract_address=${encodeURIComponent(state.signerAddress)}&key_id=${state.keyId}`,
    );
    if (statusResp.status === 400 || statusResp.status === 404) {
      state.status = null;
      state.error = null;
      render();
      return;
    }
    if (!statusResp.ok) throw new Error(`Backend error: ${statusResp.status}`);
    const raw = (await statusResp.json()) as BrowserThresholdKeyStatus;
    state.status = normalizeThresholdStatus(raw);
    state.latestVerifiedTaskId = state.status.verifiedTaskIds.length
      ? Number(state.status.verifiedTaskIds[state.status.verifiedTaskIds.length - 1])
      : null;
    state.latestSignatureHex = null;
    state.latestSepoliaTxHash = null;
    if (!state.activeSignSession) {
      state.currentJob = null;
    }
    if (state.latestVerifiedTaskId !== null) {
      const taskResp = await fetch(
        `${baseUrl()}/api/v1/threshold/task-signature?contract_address=${encodeURIComponent(state.signerAddress)}&key_id=${state.keyId}&task_id=${state.latestVerifiedTaskId}`,
      );
      if (!taskResp.ok) throw new Error(`Failed to load threshold task signature: ${taskResp.status}`);
      const task = (await taskResp.json()) as { signatureHex: Hex | null };
      state.latestSignatureHex = task.signatureHex;
    }
    if (!state.activeSignSession) {
      state.signingHash = null;
      state.txPreview = null;
      state.unsignedTx = null;
    }
    persist();
    render();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function waitForCreatedKey(maxAttempts = 10, delayMs = 1500): Promise<boolean> {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      await handleLoadKey();
      if (state.status?.exists) return true;
    } catch {
      // Let retries handle eventual contract-state visibility.
    }
    await sleep(delayMs);
  }
  return Boolean(state.status?.exists);
}

async function handleCreateKey(): Promise<void> {
  try {
    setError(null);
    const preflight = await fetchPreflight("create");
    if (!preflight.ok || !preflight.can_create) throw new Error(preflight.message);
    if (!state.passkeySessionToken) throw new Error("Register or sign in with a passkey first.");
    const resp = await passkeyFetch('/api/v1/passkeys/create-key', {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contract_address: state.signerAddress,
        num_parties: state.numParties,
      }),
    });
    const body = (await parseApiBody(resp)) as {
      job?: Record<string, unknown>;
      error?: string;
      key_id?: number;
      contract_address?: string;
    } | null;
    if (!resp.ok || !body?.job) throw new Error(body && typeof body === "object" && "error" in body && typeof body.error === "string" ? body.error : `Create-key failed: ${resp.status}`);
    if (typeof body.key_id === "number") state.keyId = body.key_id;
    if (typeof body.contract_address === "string") state.signerAddress = body.contract_address;
    state.currentJob = normalizeJob(body.job);
    state.latestSepoliaTxHash = null;
    state.signingHash = null;
    state.txPreview = null;
    state.unsignedTx = null;
    persist();
    render();
    pollJob();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function handleBuildTx(): Promise<void> {
  try {
    setError(null);
    const fromAddress = effectiveEvmAddress();
    if (!fromAddress) throw new Error("Load a threshold key first.");
    if (!hasSelectedPasskeyKey() && !state.passkeySessionToken) throw new Error("Sign in with a passkey first.");
    state.currentJob = null;
    state.latestSepoliaTxHash = null;
    const tx = await buildEthTransfer({
      apiBaseUrl: baseUrl(),
      from: fromAddress as `0x${string}`,
      to: state.recipient,
      value: BigInt(state.amountWei),
    });
    state.signingHash = getTransactionSigningHash(tx);
    state.txPreview = JSON.stringify(tx, (_k, value) => (typeof value === "bigint" ? value.toString() : value), 2);
    state.unsignedTx = stringifyTx(tx as Record<string, unknown>);
    persist();
    render();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function handleStartSigning(): Promise<void> {
  try {
    setError(null);
    if (!txReady()) {
      await handleBuildTx();
    }
    const preflight = await fetchPreflight("sign");
    if (!preflight.ok || !preflight.can_sign) throw new Error(preflight.message);
    if (!state.signingHash) throw new Error("Build Tx + Signing Hash first.");
    if (!state.unsignedTx) throw new Error("Build Tx + Signing Hash first.");
    if (!state.passkeySessionToken) throw new Error("Sign in with your passkey first.");
    const resp = await passkeyFetch('/api/v1/passkeys/reuse-sign', {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tx_tag: "eth_transfer",
        signing_parties: [1, 2],
        threshold: 2,
        msg_hash_hex: state.signingHash,
        session_id: nextSessionId(),
        signed_tx_hex: null,
      }),
    });
    const body = (await parseApiBody(resp)) as { job?: Record<string, unknown>; error?: string } | null;
    if (!resp.ok || !body?.job) {
      throw new Error(body && typeof body === "object" && "error" in body && typeof body.error === "string"
        ? body.error
        : `Backend error: ${resp.status}`);
    }
    state.currentJob = normalizeJob(body.job);
    state.latestSepoliaTxHash = null;
    state.activeSignSession = {
      jobId: state.currentJob.id,
      contractAddress: state.signerAddress,
      keyId: state.keyId,
      signingHash: state.signingHash!,
      unsignedTx: state.unsignedTx!,
      evmAddress: (effectiveEvmAddress() ?? "") as `0x${string}`,
    };
    render();
    pollJob();
  } catch (err) {
    setError(err instanceof Error ? err.message : String(err));
  }
}

async function refreshJob(): Promise<void> {
  if (!state.currentJob?.id) throw new Error("No active job.");
  const resp = await fetch(`${baseUrl()}/api/v1/jobs/${state.currentJob.id}`);
  if (!resp.ok) throw new Error(`Failed to read backend job: ${resp.status}`);
  const body = (await resp.json()) as Record<string, unknown>;
  const completedJob = normalizeJob(body);
  state.currentJob = completedJob;
  if (state.currentJob.activeContractAddress) state.signerAddress = state.currentJob.activeContractAddress;
  if (typeof state.currentJob.activeKeyId === "number") state.keyId = state.currentJob.activeKeyId;
  persist();

  if (state.currentJob.status === "completed") {
    if (state.mode === "create") {
      if (typeof completedJob.activeKeyId === "number") state.keyId = completedJob.activeKeyId;
      if (completedJob.activeContractAddress) state.signerAddress = completedJob.activeContractAddress;
      applyCreatedKeyResult(completedJob);
      state.mode = "existing"; // set BEFORE any async that might throw
      persist();
      render();
      await waitForCreatedKey().catch(() => undefined);
      await maybeLinkCreatedKeyToPasskey().catch(() => undefined);
      await syncSelectedPasskeyKey().catch(() => undefined);
      render();
    } else {
      await finalizeSigningResult(completedJob);
    }
    return;
  }

  render();
}

async function finalizeSigningResult(completedJob: JobRecord): Promise<void> {
  const result = completedJob.result ?? null;
  const session = state.activeSignSession;
  const signatureHex =
    typeof result?.onchain_signature_hex === "string"
      ? (result.onchain_signature_hex as Hex)
      : typeof result?.signature_hex === "string"
        ? (result.signature_hex as Hex)
        : null;
  if (!signatureHex || !session) {
    render();
    return;
  }
  try {
    state.latestSignatureHex = signatureHex;
    const { r, s, recoveryId } = parseSignatureBytes(hexToBytes(signatureHex), session.signingHash, session.evmAddress);
    const signedTx = signTransaction(reviveUnsignedTx(session.unsignedTx) as never, r, s, recoveryId);
    const evmTxHash = await submitSignedTransaction(signedTx, baseUrl());
    state.latestSepoliaTxHash = evmTxHash;
    state.currentJob = { ...completedJob, evmTxHash };
    state.activeSignSession = null;
    await handleLoadKey();
    state.latestSepoliaTxHash = evmTxHash;
    state.currentJob = { ...completedJob, evmTxHash };
    render();
  } catch (err) {
    state.currentJob = completedJob;
    setError(err instanceof Error ? `Signature verified, but Sepolia broadcast failed: ${err.message}` : String(err));
  }
}

async function syncActiveRuntime(): Promise<void> {
  try {
    await ensureBackendAvailable();
    const resp = await fetch(`${baseUrl()}/api/v1/runtime/active`);
    if (!resp.ok) return;
    const body = (await resp.json()) as { ok?: boolean; runtime?: RuntimeSummary | RuntimeActivePayload | null };
    if (!body.ok || !body.runtime) return;
    const runtime = body.runtime as unknown as Record<string, unknown>;
    if (typeof runtime.contract_address === "string") state.signerAddress = String(runtime.contract_address);
    if (typeof runtime.key_id === "number") state.keyId = Number(runtime.key_id);
    if (typeof runtime.evm_address === "string" && state.status) {
      state.status = { ...state.status, evmAddress: runtime.evm_address as Hex };
    }
    state.runtimeActive = {
      parties_up: typeof runtime.parties_up === "number" ? runtime.parties_up : 0,
      running_jobs: Array.isArray(runtime.running_jobs)
        ? runtime.running_jobs
            .filter((job): job is Record<string, unknown> => typeof job === "object" && job !== null)
            .map((job) => ({
              id: typeof job.id === "string" ? job.id : "",
              type: typeof job.type === "string" ? job.type : "unknown",
              status: typeof job.status === "string" ? job.status : "unknown",
            }))
        : [],
      sender_address: typeof runtime.sender_address === "string" ? runtime.sender_address : undefined,
      sender_mode: typeof runtime.sender_mode === "string" ? runtime.sender_mode : undefined,
    };
    persist();
    render();
  } catch {
    return;
  }
}

function pollJob(): void {
  if (pollTimer) window.clearTimeout(pollTimer);
  const run = async () => {
    try {
      await refreshJob();
      if (state.currentJob && ["queued", "running"].includes(state.currentJob.status)) {
        pollTimer = window.setTimeout(run, 1500);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  void run();
}

function render(): void {
  // Key exists on-chain if we loaded it successfully
  const keyExists = Boolean(state.status?.exists);
  // If key exists, always stay in existing mode — don't offer Create
  if (keyExists && state.mode === "create") {
    state.mode = "existing";
    persist();
  }

  const sepoliaTxHash = state.latestSepoliaTxHash ?? state.currentJob?.evmTxHash ?? null;
  const sepoliaStatus = sepoliaTxHash
    ? "submitted"
    : state.currentJob?.status === "running"
      ? "signing_on_partisia"
      : state.currentJob?.status === "failed" && state.latestSignatureHex
        ? "failed"
        : state.currentJob?.status === "completed" && txReady()
          ? "ready_to_broadcast"
          : txReady()
            ? "ready_to_sign"
            : "idle";

  // ── Step 1: Auth ────────────────────────────────────────────────────────
  const authSection = `
    <section class="panel section">
      <div class="eyebrow">Step 1 — Authentication</div>
      <div class="callout">
        <div class="stat-value">${state.passkeyAccount ? `✓ ${escapeHtml(state.passkeyAccount.label)}` : "Not signed in"}</div>
        <div class="action-grid section">
          <button id="passkeySignIn" class="${state.passkeyAccount ? "secondary" : ""}">Sign in with Passkey</button>
          <button id="passkeyRegister" class="secondary">Register Passkey</button>
        </div>
        ${state.passkeyAccount?.linked_keys?.length ? `
          <div class="section">
            <div class="stat-label">Linked Keys</div>
            <div class="action-grid">
              ${state.passkeyAccount.linked_keys.map((key, index) =>
                `<button class="secondary linked-key" data-contract="${escapeAttr(key.contract_address)}" data-key-id="${key.key_id}">
                  ${escapeHtml(displayLinkedKeyLabel(key, index))}
                </button>`
              ).join("")}
            </div>
          </div>` : ""}
      </div>
    </section>`;

  // ── Step 2: Key ──────────────────────────────────────────────────────────
  // Prefer live status, fall back to job result (shown right after key creation)
  const evmAddress = state.status?.evmAddress ?? state.currentJob?.createdEvmAddress ?? null;
  const publicKeyHex = state.status?.publicKeyHex ?? state.currentJob?.createdPublicKeyHex ?? null;

  const keyInfoCard = keyExists ? `
    <div class="callout section">
      <div class="eyebrow">DKG Key Loaded ✓</div>

      <div class="section">
        <div class="stat-label">Derived EVM Wallet Address</div>
        <div class="stat-value mono success" style="font-size:1.05em;word-break:break-all;">${evmAddress ?? "—"}</div>
        ${evmAddress ? `
        <div class="action-grid section">
          <button class="secondary" onclick="navigator.clipboard.writeText('${escapeAttr(evmAddress ?? "")}').then(()=>this.textContent='Copied!').catch(()=>{})">Copy Address</button>
          <a class="secondary linked-key" href="https://sepolia.etherscan.io/address/${escapeAttr(evmAddress)}" target="_blank" rel="noreferrer">View on Sepolia Etherscan ↗</a>
        </div>` : ""}
      </div>

      <div class="section">
        <div class="stat-label">Combined Public Key</div>
        <div class="stat-value mono" style="word-break:break-all;font-size:0.82em;">${publicKeyHex ?? "—"}</div>
      </div>

      <div class="stat-grid section">
        <div class="stat"><span class="stat-label">Keygen Phase</span><span class="stat-value">${state.status?.keygenPhaseDiscriminant ?? "—"}</span></div>
        <div class="stat"><span class="stat-label">Verified Signatures</span><span class="stat-value">${state.status?.verifiedTaskIds.length ? state.status.verifiedTaskIds.join(", ") : "None yet"}</span></div>
        <div class="stat"><span class="stat-label">Key ID</span><span class="stat-value mono">${state.keyId}</span></div>
        <div class="stat"><span class="stat-label">Contract</span><span class="stat-value mono" style="word-break:break-all;font-size:0.8em;">${escapeHtml(state.signerAddress)}</span></div>
      </div>
    </div>` : "";

  const keySection = `
    <section class="panel section">
      <div class="eyebrow">Step 2 — Key</div>
      <div class="grid section">
        <label>Contract Address
          <input id="signerAddress" value="${escapeAttr(state.signerAddress)}" />
        </label>
        <label>Backend URL
          <input id="apiBaseUrl" value="${escapeAttr(state.apiBaseUrl)}" />
        </label>
        ${!keyExists ? `<label>Number of Parties
          <input id="numParties" type="number" min="2" max="10" value="${state.numParties}" />
        </label>` : ""}
      </div>
      <div class="action-grid">
        <button id="loadKey">Load Key</button>
        ${!keyExists ? `<button id="createKey" class="secondary">Create New Key</button>` : ""}
      </div>
      ${!keyExists && !state.currentJob ? `<p class="section" style="opacity:0.5;font-size:0.85em;">No key loaded. Load an existing key or create a new one.</p>` : ""}
      ${keyInfoCard}
      ${state.currentJob && state.mode === "create" ? `
        <div class="section callout">
          <div class="stat-label">${state.currentJob.status === "failed" ? "Create Key Failed" : "Creating Key…"}</div>
          <div class="stat-value ${state.currentJob.status === "completed" ? "success" : state.currentJob.status === "failed" ? "danger" : ""}">
            ${escapeHtml(state.currentJob.phase)}
          </div>
          <pre class="mono section">${escapeHtml(state.currentJob.logs[state.currentJob.logs.length - 1] ?? "")}</pre>
          ${state.currentJob?.error ? `<p class="danger section">${escapeHtml(state.currentJob.error)}</p>` : ""}
          <div class="action-grid section">
            <button id="refreshJob" class="secondary">Refresh</button>
          </div>
        </div>` : ""}
    </section>`;

  // ── Step 3: Sign ─────────────────────────────────────────────────────────
  const signSection = keyExists ? `
    <section class="panel section">
      <div class="eyebrow">Step 3 — Send</div>
      <div class="grid section">
        <label>Recipient (EVM)
          <input id="recipient" value="${escapeAttr(state.recipient)}" />
        </label>
        <label>Amount (wei)
          <input id="amountWei" value="${escapeAttr(state.amountWei)}" />
        </label>
      </div>
      <div class="action-grid">
        <button id="buildTx" class="secondary" ${canBuildTx() ? "" : "disabled"}>Build Transaction</button>
        <button id="startSigning" ${canStartSigning() ? "" : "disabled"}>Sign &amp; Send</button>
      </div>
      ${state.txPreview ? `
        <div class="section callout">
          <div class="stat-label">Signing Hash</div>
          <div class="stat-value mono" style="word-break:break-all;font-size:0.8em;">${escapeHtml(state.signingHash ?? "—")}</div>
          <div class="stat-label section">Unsigned Transaction</div>
          <pre class="mono section" style="white-space:pre-wrap;word-break:break-word;">${escapeHtml(state.txPreview)}</pre>
        </div>` : ""}
      ${state.currentJob && state.mode === "existing" ? `
        <div class="section callout">
          <div class="stat-value ${state.currentJob.status === "completed" ? "success" : state.currentJob.status === "failed" ? "danger" : ""}">
            ${state.currentJob.status === "completed" ? "✓ Done" : state.currentJob.status === "failed" ? "✗ Failed" : `⏳ ${escapeHtml(state.currentJob.phase)}`}
          </div>
          ${state.currentJob?.error ? `<p class="danger section">${escapeHtml(state.currentJob.error)}</p>` : ""}
        </div>` : ""}
      ${sepoliaTxHash ? `
        <div class="section callout">
          <div class="stat-label">✓ Transaction Sent</div>
          <div class="stat-value mono section">${escapeHtml(sepoliaTxHash)}</div>
          <a class="secondary linked-key section" href="https://sepolia.etherscan.io/tx/${escapeAttr(sepoliaTxHash)}" target="_blank" rel="noreferrer">View on Sepolia Etherscan ↗</a>
        </div>` : ""}
    </section>` : "";

  // Big wallet card — shown only when DKG key is loaded
  const walletCard = evmAddress ? `
    <section class="panel section" style="text-align:center;padding:32px 24px;">
      <div class="eyebrow">Your Wallet</div>
      <h2 style="margin:8px 0 20px;">Derived EVM Address</h2>
      <div style="
        background:#0d0d0d;
        border:1px solid #2a2a2a;
        border-radius:12px;
        padding:20px 24px;
        font-family:monospace;
        font-size:1.05em;
        word-break:break-all;
        letter-spacing:0.03em;
        color:#4ade80;
        margin:0 auto 20px;
        max-width:600px;
      ">${escapeHtml(evmAddress)}</div>
      <div class="action-grid" style="justify-content:center;max-width:400px;margin:0 auto;">
        <button class="secondary" id="copyEvmAddress">Copy Address</button>
        <a class="secondary linked-key" href="https://sepolia.etherscan.io/address/${escapeAttr(evmAddress)}" target="_blank" rel="noreferrer">View on Etherscan ↗</a>
      </div>
      ${publicKeyHex ? `
      <div style="margin-top:24px;text-align:left;max-width:600px;margin-left:auto;margin-right:auto;">
        <div class="stat-label">Combined Public Key (P = P₁ + P₂ + P₃)</div>
        <div class="stat-value mono" style="word-break:break-all;font-size:0.78em;opacity:0.7;margin-top:4px;">${escapeHtml(publicKeyHex)}</div>
      </div>` : ""}
    </section>` : "";

  const runtimePanel = state.runtimeActive ? `
    <section class="panel section">
      <div class="eyebrow">Runtime</div>
      <div class="stat-grid section">
        <div class="stat">
          <span class="stat-label">Parties Up</span>
          <span class="stat-value">${state.runtimeActive.parties_up}/3</span>
        </div>
        <div class="stat">
          <span class="stat-label">Running Jobs</span>
          <span class="stat-value">${state.runtimeActive.running_jobs.length}</span>
        </div>
        ${state.runtimeActive.sender_address ? `
        <div class="stat">
          <span class="stat-label">Sender</span>
          <span class="stat-value mono" style="font-size:0.78em;word-break:break-all;">${escapeHtml(state.runtimeActive.sender_address)}</span>
        </div>` : ""}
        ${state.runtimeActive.sender_mode ? `
        <div class="stat">
          <span class="stat-label">Sender Mode</span>
          <span class="stat-value">${escapeHtml(state.runtimeActive.sender_mode)}</span>
        </div>` : ""}
      </div>
      ${state.runtimeActive.running_jobs.length ? `
        <div class="section callout">
          ${state.runtimeActive.running_jobs.map((job) => `
            <div class="section">
              <div class="stat-label">${escapeHtml(job.type)}</div>
              <div class="stat-value mono" style="font-size:0.8em;">${escapeHtml(job.id)}</div>
              <div class="stat-value">${escapeHtml(job.status)}</div>
            </div>
          `).join("")}
        </div>` : `
        <p class="section" style="opacity:0.7;font-size:0.9em;">No running jobs right now.</p>`}
    </section>` : "";

  app.innerHTML = `
    <section class="hero">
      <div class="panel">
        <div class="eyebrow">Kosh Threshold Signer</div>
        <h1>Threshold ECDSA Wallet</h1>
        <div class="badge-row">
          <div class="badge"><strong>Contract</strong><br><span class="mono">${escapeHtml(state.signerAddress.slice(0, 14))}…</span></div>
          <div class="badge"><strong>Key</strong><br><span class="mono ${keyExists ? "success" : ""}">${keyExists ? "✓ Loaded" : "Not loaded"}</span></div>
          ${state.passkeyAccount ? `<div class="badge"><strong>Auth</strong><br><span class="mono success">✓ ${escapeHtml(state.passkeyAccount.label)}</span></div>` : ""}
        </div>
      </div>
    </section>
    ${walletCard}
    ${runtimePanel}
    ${authSection}
    ${keySection}
    ${signSection}
    ${state.error ? `<section class="panel section"><p class="danger">${escapeHtml(state.error)}</p></section>` : ""}
  `;

  bindEvents();
}

function bindEvents(): void {
  const signerInput = document.querySelector<HTMLInputElement>("#signerAddress");
  const apiBaseUrlInput = document.querySelector<HTMLInputElement>("#apiBaseUrl");
  const numPartiesInput = document.querySelector<HTMLInputElement>("#numParties");
  const recipientInput = document.querySelector<HTMLInputElement>("#recipient");
  const amountInput = document.querySelector<HTMLInputElement>("#amountWei");

  signerInput?.addEventListener("input", (e) => {
    state.signerAddress = (e.target as HTMLInputElement).value;
    state.status = null;
    state.signingHash = null;
    state.txPreview = null;
    state.unsignedTx = null;
    state.currentJob = null;
    persist();
    render();
  });
  apiBaseUrlInput?.addEventListener("input", (e) => {
    state.apiBaseUrl = (e.target as HTMLInputElement).value;
    persist();
  });
  numPartiesInput?.addEventListener("input", (e) => {
    state.numParties = Number((e.target as HTMLInputElement).value || "3");
    persist();
  });
  recipientInput?.addEventListener("input", (e) => {
    state.recipient = (e.target as HTMLInputElement).value as Hex;
    persist();
  });
  amountInput?.addEventListener("input", (e) => {
    state.amountWei = (e.target as HTMLInputElement).value;
    persist();
  });

  document.querySelector<HTMLButtonElement>("#passkeySignIn")?.addEventListener("click", () => void handlePasskeySignIn());
  document.querySelector<HTMLButtonElement>("#passkeyRegister")?.addEventListener("click", () => void handlePasskeyRegister());
  document.querySelectorAll<HTMLButtonElement>(".linked-key[data-contract]").forEach((button) => {
    button.addEventListener("click", () => {
      const contractAddress = button.dataset.contract ?? state.signerAddress;
      const keyId = Number(button.dataset.keyId ?? '0');
      void handleSelectPasskeyKey(contractAddress, keyId);
    });
  });
  document.querySelector<HTMLButtonElement>("#copyEvmAddress")?.addEventListener("click", (e) => {
    const addr = state.status?.evmAddress ?? "";
    if (!addr) return;
    navigator.clipboard.writeText(addr).then(() => {
      const btn = e.target as HTMLButtonElement;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = "Copy Address"; }, 2000);
    }).catch(() => {});
  });
  document.querySelector<HTMLButtonElement>("#loadKey")?.addEventListener("click", () => void handleLoadKey());
  document.querySelector<HTMLButtonElement>("#createKey")?.addEventListener("click", () => {
    state.mode = "create";
    state.currentJob = null;
    state.error = null;
    persist();
    void handleCreateKey();
  });
  document.querySelector<HTMLButtonElement>("#buildTx")?.addEventListener("click", () => void handleBuildTx());
  document.querySelector<HTMLButtonElement>("#startSigning")?.addEventListener("click", () => void handleStartSigning());
  document.querySelector<HTMLButtonElement>("#refreshJob")?.addEventListener("click", () => {
    void refreshJob().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  });
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function escapeAttr(value: string): string {
  return escapeHtml(value).replaceAll('"', "&quot;");
}

render();
void syncActiveRuntime().catch(() => undefined);
void refreshPasskeyMe().catch(() => undefined);
if (state.signerAddress && state.keyId) {
  void handleLoadKey().catch(() => undefined);
}
window.setInterval(() => {
  void syncActiveRuntime().catch(() => undefined);
}, 2000);
window.setInterval(() => {
  void ensureBackendAvailable().catch(() => undefined);
}, 3000);
