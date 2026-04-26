//! Core Schnorr Proof of Knowledge (PoK) implementation over Ristretto255.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ZKPError;
use crate::transcript::TranscriptProtocol;

/// A securely wiped proving key (the user's secret).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProvingKey {
    pub(crate) secret: Scalar,
}

impl ProvingKey {
    /// Construct a new securely erased proving key.
    pub fn new(secret: Scalar) -> Self {
        Self { secret }
    }
}

/// The verifier's public key point on the Ristretto255 curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub(crate) point: RistrettoPoint,
}

impl VerifyingKey {
    /// Compute the public key from a given proving key.
    pub fn from_proving_key(pk: &ProvingKey) -> Self {
        Self {
            point: &pk.secret * RISTRETTO_BASEPOINT_TABLE,
        }
    }

    /// Construct a VerifyingKey directly from a valid RistrettoPoint (used during deserialization).
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    /// Retrieve the compressed representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
}

/// The mathematical Non-Interactive Zero-Knowledge Proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub commitment_r: CompressedRistretto,
    pub response_z: Scalar,
}

impl Proof {
    /// Generate a non-interactive Schnorr PoK proving knowledge of `ProvingKey`.
    ///
    /// # Protocol
    /// 1. Prover selects random nonce `r`, computes `R = r * G`.
    /// 2. Prover hashes `R` and `Public_Key` into the `merlin::Transcript` to derive challenge `c`.
    /// 3. Prover calculates `z = r + c * secret`.
    pub fn generate<R: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        proving_key: &ProvingKey,
        rng: &mut R,
    ) -> Self {
        transcript.zkprust_domain_sep(b"schnorr-pok");

        let verifying_key = VerifyingKey::from_proving_key(proving_key);
        transcript.append_point(b"public-key", &verifying_key.to_bytes());

        // 1. Commitment Phase
        // Ensure nonce `r` is zeroized immediately after computing R and z.
        let mut r = Scalar::random(rng);
        let r_point = (&r * RISTRETTO_BASEPOINT_TABLE).compress();
        transcript.append_point(b"commitment-R", &r_point.to_bytes());

        // 2. Challenge Phase (Fiat-Shamir)
        let c = transcript.challenge_scalar(b"challenge-c");

        // 3. Response Phase (z = r + c * x)
        let z = r + (c * proving_key.secret);

        // Security: Zeroize the random scalar nonce.
        r.zeroize();

        Self {
            commitment_r: r_point,
            response_z: z,
        }
    }

    /// Verifies the non-interactive Schnorr PoK against a `VerifyingKey`.
    /// 
    /// Math: `z * G == R + c * Public_Key`
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ZKPError> {
        transcript.zkprust_domain_sep(b"schnorr-pok");
        transcript.append_point(b"public-key", &verifying_key.to_bytes());
        transcript.append_point(b"commitment-R", &self.commitment_r.to_bytes());

        let c = transcript.challenge_scalar(b"challenge-c");

        let r_point = self
            .commitment_r
            .decompress()
            .ok_or(ZKPError::InvalidProof)?;

        // z * G
        let z_g = &self.response_z * RISTRETTO_BASEPOINT_TABLE;
        
        // R + c * X
        let r_plus_cx = r_point + (c * verifying_key.point);

        // Constant-time mathematical equivalence check.
        if z_g == r_plus_cx {
            Ok(())
        } else {
            Err(ZKPError::VerificationFailed)
        }
    }

    /// Serialize the Proof down to a pure 64-byte binary payload.
    /// Bytes [0..32] are the `commitment_r` CompressedRistretto point.
    /// Bytes [32..64] are the `response_z` Scalar.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(self.commitment_r.as_bytes());
        buf[32..64].copy_from_slice(self.response_z.as_bytes());
        buf
    }

    /// Decompress a 64-byte binary payload securely back into a `Proof` mathematically.
    /// Returns an error if the scalar or curve point is maliciously formatted.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, ZKPError> {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let commitment_r = CompressedRistretto::from_slice(&r_bytes)
            .map_err(|_| ZKPError::InvalidProof)?;

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&bytes[32..64]);
        
        let response_z = Option::from(Scalar::from_canonical_bytes(z_bytes))
            .ok_or(ZKPError::InvalidProof)?;

        Ok(Self {
            commitment_r,
            response_z,
        })
    }
}
