// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use ring::rand::SecureRandom;
use ring::{digest, rand};
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

pub const ALG_HMAC256_256: i64 = -4;
pub const ALG_ES256: i64 = -7;
pub const ALG_PS256: i64 = -37;

type HmacSha256 = Hmac<Sha256>;

pub trait CryptographicAlgorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError>;
    fn algorithm_id(&self) -> i64;
}

pub struct HmacSha256Algorithm {
    key: Vec<u8>,
}

impl HmacSha256Algorithm {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn generate_key() -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        let mut key = vec![0u8; 32];
        rng.fill(&mut key).unwrap();
        key
    }
}

impl CryptographicAlgorithm for HmacSha256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        mac.update(data);

        mac.verify_slice(signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_HMAC256_256
    }
}

pub struct Es256Algorithm {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl Es256Algorithm {
    pub fn new_with_key_pair() -> Result<Self, CatError> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key,
        })
    }

    pub fn new_verifier(verifying_key: VerifyingKey) -> Self {
        Self {
            signing_key: None,
            verifying_key,
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl CryptographicAlgorithm for Es256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| CatError::CryptoError("No signing key available".to_string()))?;

        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let signature =
            Signature::try_from(signature).map_err(|e| CatError::CryptoError(e.to_string()))?;

        self.verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_ES256
    }
}

pub struct Ps256Algorithm {
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
}

impl Ps256Algorithm {
    pub fn new_with_key_pair() -> Result<Self, CatError> {
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key: Some(private_key),
            public_key,
        })
    }

    pub fn new_verifier(public_key: RsaPublicKey) -> Self {
        Self {
            private_key: None,
            public_key,
        }
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

impl CryptographicAlgorithm for Ps256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| CatError::CryptoError("No private key available".to_string()))?;

        let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.sign_with_rng(&mut OsRng, data);

        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let verifying_key = RsaVerifyingKey::<Sha256>::new(self.public_key.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;

        verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_PS256
    }
}

pub fn create_signing_input(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_b64 = URL_SAFE_NO_PAD.encode(header);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    format!("{}.{}", header_b64, payload_b64).into_bytes()
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}
