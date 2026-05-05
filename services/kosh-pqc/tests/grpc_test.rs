/// Integration test: starts the real kosh-pqc binary and makes real gRPC calls.
/// Tests: GetIdentity, Encapsulate→Decapsulate round-trip, Sign→Verify round-trip,
/// EncryptPayload→DecryptPayload AES-GCM round-trip.

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub mod pb {
    tonic::include_proto!("kosh.pqc");
}

use pb::{
    pqc_service_client::PqcServiceClient, DecapsulateRequest, DecryptPayloadRequest,
    EncapsulateRequest, EncryptPayloadRequest, GetIdentityRequest, SignRequest, VerifyRequest,
};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_ready(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "kosh-pqc not ready at {addr}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_pqc(port: u16) -> Guard {
    let bin = env!("CARGO_BIN_EXE_kosh-pqc");
    let pqc_file = format!("/tmp/kosh-pqc-test-{port}.json");
    let proc = Command::new(bin)
        .env("PORT", port.to_string())
        .env("PQC_KEY_FILE", &pqc_file)
        .env("RUST_LOG", "error")
        .spawn()
        .expect("failed to start kosh-pqc");
    let addr = format!("127.0.0.1:{port}");
    wait_ready(&addr, Duration::from_secs(10));
    Guard(proc)
}

async fn client(port: u16) -> PqcServiceClient<tonic::transport::Channel> {
    PqcServiceClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .unwrap()
}

#[tokio::test]
async fn test_get_identity_returns_nonempty_keys() {
    let port = free_port();
    let _guard = start_pqc(port);
    let mut c = client(port).await;

    let resp = c.get_identity(GetIdentityRequest {}).await.unwrap().into_inner();
    assert!(!resp.kyber_pk_b64.is_empty(), "kyber_pk_b64 must not be empty");
    assert!(!resp.dilithium_pk_b64.is_empty(), "dilithium_pk_b64 must not be empty");
    println!("kyber_pk (first 20): {}", &resp.kyber_pk_b64[..20]);
    println!("dilithium_pk (first 20): {}", &resp.dilithium_pk_b64[..20]);
}

#[tokio::test]
async fn test_encapsulate_decapsulate_round_trip() {
    let port = free_port();
    let _guard = start_pqc(port);
    let mut c = client(port).await;

    // Get the party's own encapsulation key
    let id = c.get_identity(GetIdentityRequest {}).await.unwrap().into_inner();

    // Encapsulate to that key (in practice a different party would do this)
    let enc = c
        .encapsulate(EncapsulateRequest {
            recipient_kyber_pk_b64: id.kyber_pk_b64.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!enc.ciphertext_b64.is_empty());
    assert!(!enc.shared_secret_b64.is_empty());

    // Decapsulate using the party's private key
    let dec = c
        .decapsulate(DecapsulateRequest {
            ciphertext_b64: enc.ciphertext_b64.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    // The shared secrets must match
    assert_eq!(
        enc.shared_secret_b64, dec.shared_secret_b64,
        "encapsulated and decapsulated shared secrets must match"
    );
    println!("KEM round-trip OK — shared_secret: {}...", &enc.shared_secret_b64[..20]);
}

#[tokio::test]
async fn test_encrypt_decrypt_round_trip() {
    let port = free_port();
    let _guard = start_pqc(port);
    let mut c = client(port).await;

    let id = c.get_identity(GetIdentityRequest {}).await.unwrap().into_inner();
    let enc = c
        .encapsulate(EncapsulateRequest {
            recipient_kyber_pk_b64: id.kyber_pk_b64,
        })
        .await
        .unwrap()
        .into_inner();

    let plaintext = b"hello from kosh-pqc integration test".to_vec();

    // Encrypt
    let encrypted = c
        .encrypt_payload(EncryptPayloadRequest {
            shared_secret_b64: enc.shared_secret_b64.clone(),
            plaintext: plaintext.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!encrypted.ciphertext.is_empty());
    assert_eq!(encrypted.nonce.len(), 12);
    assert_eq!(encrypted.tag.len(), 16);

    // Decrypt
    let decrypted = c
        .decrypt_payload(DecryptPayloadRequest {
            shared_secret_b64: enc.shared_secret_b64,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(decrypted.plaintext, plaintext, "decrypted plaintext must match original");
    println!("AES-GCM round-trip OK");
}

#[tokio::test]
async fn test_sign_verify_round_trip() {
    let port = free_port();
    let _guard = start_pqc(port);
    let mut c = client(port).await;

    let id = c.get_identity(GetIdentityRequest {}).await.unwrap().into_inner();

    let message = b"sign this message for KoshSigner".to_vec();

    // Sign
    let sign_resp = c
        .sign(SignRequest { message: message.clone() })
        .await
        .unwrap()
        .into_inner();

    assert!(!sign_resp.signature.is_empty(), "signature must not be empty");

    // Verify with the party's public key
    let verify_resp = c
        .verify(VerifyRequest {
            dilithium_pk_b64: id.dilithium_pk_b64.clone(),
            message: message.clone(),
            signature: sign_resp.signature.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(verify_resp.valid, "signature must verify correctly");
    println!("ML-DSA sign+verify round-trip OK, sig len={}", sign_resp.signature.len());
}

#[tokio::test]
async fn test_verify_wrong_message_fails() {
    let port = free_port();
    let _guard = start_pqc(port);
    let mut c = client(port).await;

    let id = c.get_identity(GetIdentityRequest {}).await.unwrap().into_inner();

    let sign_resp = c
        .sign(SignRequest { message: b"real message".to_vec() })
        .await
        .unwrap()
        .into_inner();

    // Verify with a DIFFERENT message — must fail
    let verify_resp = c
        .verify(VerifyRequest {
            dilithium_pk_b64: id.dilithium_pk_b64,
            message: b"tampered message".to_vec(),
            signature: sign_resp.signature,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!verify_resp.valid, "tampered message must NOT verify");
    println!("ML-DSA tamper detection OK");
}
