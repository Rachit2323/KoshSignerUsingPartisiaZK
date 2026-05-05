use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::{signature::Verifier, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::identity::Identity;
use crate::pb::pqc_service_server::PqcService;
use crate::pb::*;

pub struct PqcServiceImpl {
    pub identity: Arc<Identity>,
}

fn aes_key(shared_secret: &[u8]) -> [u8; 32] {
    Sha256::digest(shared_secret).into()
}

fn random_nonce() -> [u8; 12] {
    use std::io::Read;
    let mut n = [0u8; 12];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut n)
        .unwrap();
    n
}

#[tonic::async_trait]
impl PqcService for PqcServiceImpl {
    async fn get_identity(
        &self,
        _req: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        let (kem_pk, dsa_pk) = self.identity.public_keys();
        Ok(Response::new(GetIdentityResponse {
            kyber_pk_b64: kem_pk,
            dilithium_pk_b64: dsa_pk,
        }))
    }

    async fn encapsulate(
        &self,
        req: Request<EncapsulateRequest>,
    ) -> Result<Response<EncapsulateResponse>, Status> {
        let (ct, ss) = self
            .identity
            .encapsulate_to(&req.into_inner().recipient_kyber_pk_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(EncapsulateResponse {
            ciphertext_b64: B64.encode(&ct),
            shared_secret_b64: B64.encode(&ss),
        }))
    }

    async fn decapsulate(
        &self,
        req: Request<DecapsulateRequest>,
    ) -> Result<Response<DecapsulateResponse>, Status> {
        let ct_bytes = B64
            .decode(&req.into_inner().ciphertext_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let ss = self
            .identity
            .decapsulate_ct(&ct_bytes)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(DecapsulateResponse {
            shared_secret_b64: B64.encode(&ss),
        }))
    }

    async fn encrypt_payload(
        &self,
        req: Request<EncryptPayloadRequest>,
    ) -> Result<Response<EncryptPayloadResponse>, Status> {
        let r = req.into_inner();
        let ss = B64
            .decode(&r.shared_secret_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let key_bytes = aes_key(&ss);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce_bytes = random_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, r.plaintext.as_ref())
            .map_err(|e| Status::internal(e.to_string()))?;

        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        Ok(Response::new(EncryptPayloadResponse {
            ciphertext: ct.to_vec(),
            nonce: nonce_bytes.to_vec(),
            tag: tag.to_vec(),
        }))
    }

    async fn decrypt_payload(
        &self,
        req: Request<DecryptPayloadRequest>,
    ) -> Result<Response<DecryptPayloadResponse>, Status> {
        let r = req.into_inner();
        let ss = B64
            .decode(&r.shared_secret_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let key_bytes = aes_key(&ss);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&r.nonce);

        let mut ct_with_tag = r.ciphertext.clone();
        ct_with_tag.extend_from_slice(&r.tag);

        let plaintext = cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|_| Status::unauthenticated("AES-GCM decryption failed"))?;

        Ok(Response::new(DecryptPayloadResponse { plaintext }))
    }

    async fn sign(&self, req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        use ml_dsa::signature::Signer;
        let sig: Signature<MlDsa65> = self.identity.dsa_sk.sign(&req.into_inner().message);
        let encoded = sig.encode();
        let sig_bytes: &[u8] = encoded.as_ref();
        Ok(Response::new(SignResponse {
            signature: sig_bytes.to_vec(),
        }))
    }

    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let r = req.into_inner();

        let pk_bytes = B64
            .decode(&r.dilithium_pk_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vk_enc: &EncodedVerifyingKey<MlDsa65> = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid dilithium pk length"))?;
        let vk = VerifyingKey::<MlDsa65>::decode(vk_enc);

        let sig: Signature<MlDsa65> = r
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid signature length"))?;

        let valid = vk.verify(&r.message, &sig).is_ok();
        Ok(Response::new(VerifyResponse { valid }))
    }
}
