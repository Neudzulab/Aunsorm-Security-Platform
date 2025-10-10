use std::fmt;

use aunsorm_core::SensitiveVec;
use hpke::{
    aead::{Aead, AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::{Kem as KemTrait, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, OpModeR, OpModeS, Serializable,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::PacketError;

const EXPORT_LABEL: &[u8] = b"Aunsorm/1.01/hpke/export";
const INFO_PREFIX: &[u8] = b"Aunsorm/1.01/hpke/info/";

/// HPKE çıktısından türetilen paylaşımlı sırrın uzunluğu.
pub const EXPORT_SECRET_LEN: usize = 32;

/// Desteklenen HPKE paketleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeSuite {
    /// X25519 + HKDF-SHA256 + `ChaCha20Poly1305`
    X25519HkdfSha256ChaCha20Poly1305,
    /// X25519 + HKDF-SHA256 + `AES-256-GCM`
    X25519HkdfSha256AesGcm256,
}

impl HpkeSuite {
    /// Suite için okunabilir kimlik.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::X25519HkdfSha256ChaCha20Poly1305 => "hpke-x25519-chacha20poly1305",
            Self::X25519HkdfSha256AesGcm256 => "hpke-x25519-aesgcm256",
        }
    }

    fn seal_impl<A, R>(
        self,
        recipient_public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<HpkeSealOutput, PacketError>
    where
        A: Aead,
        R: CryptoRng + RngCore,
    {
        let info_context = build_info(self, info);
        let pk = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(recipient_public_key)
            .map_err(|_| PacketError::Invalid("invalid hpke public key"))?;
        let (enc, mut context) = setup_sender::<A, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk,
            &info_context,
            rng,
        )?;
        let ciphertext = context.seal(plaintext, aad)?;
        let mut export = vec![0_u8; EXPORT_SECRET_LEN];
        context.export(EXPORT_LABEL, &mut export)?;
        Ok(HpkeSealOutput {
            encapsulated_key: enc.to_bytes().to_vec(),
            ciphertext,
            export_secret: SensitiveVec::new(export),
        })
    }

    fn open_impl<A>(
        self,
        recipient_private_key: &[u8],
        encapsulated_key: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<HpkeOpenOutput, PacketError>
    where
        A: Aead,
    {
        let info_context = build_info(self, info);
        let sk = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(recipient_private_key)
            .map_err(|_| PacketError::Invalid("invalid hpke private key"))?;
        let enc = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(encapsulated_key)
            .map_err(|_| PacketError::Invalid("invalid hpke encapsulated key"))?;
        let mut context = setup_receiver::<A, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &enc,
            &info_context,
        )?;
        let plaintext = context.open(ciphertext, aad)?;
        let mut export = vec![0_u8; EXPORT_SECRET_LEN];
        context.export(EXPORT_LABEL, &mut export)?;
        Ok(HpkeOpenOutput {
            plaintext,
            export_secret: SensitiveVec::new(export),
        })
    }
}

impl fmt::Display for HpkeSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.identifier())
    }
}

/// HPKE anahtar çifti.
#[derive(Debug, Clone)]
pub struct HpkeKeyPair {
    public_key: Vec<u8>,
    private_key: SensitiveVec,
}

impl HpkeKeyPair {
    /// Ortak anahtar baytlarını döndürür.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Gizli anahtar baytlarını döndürür.
    #[must_use]
    pub const fn private_key(&self) -> &SensitiveVec {
        &self.private_key
    }
}

/// HPKE şifreleme çıktısı.
#[derive(Debug)]
pub struct HpkeSealOutput {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub export_secret: SensitiveVec,
}

/// HPKE çözme çıktısı.
#[derive(Debug)]
pub struct HpkeOpenOutput {
    pub plaintext: Vec<u8>,
    pub export_secret: SensitiveVec,
}

/// Deterministik bilgi bağlamı oluşturur.
fn build_info(suite: HpkeSuite, info: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(INFO_PREFIX.len() + suite.identifier().len() + 1 + info.len());
    ctx.extend_from_slice(INFO_PREFIX);
    ctx.extend_from_slice(suite.identifier().as_bytes());
    ctx.push(0);
    ctx.extend_from_slice(info);
    ctx
}

/// X25519 tabanlı HPKE anahtar çifti üretir.
#[must_use]
pub fn generate_keypair<R>(rng: &mut R) -> HpkeKeyPair
where
    R: CryptoRng + RngCore,
{
    let (sk, pk) = <X25519HkdfSha256 as KemTrait>::gen_keypair(rng);
    HpkeKeyPair {
        public_key: pk.to_bytes().to_vec(),
        private_key: SensitiveVec::new(sk.to_bytes().to_vec()),
    }
}

/// HPKE ile şifreleme gerçekleştirir.
///
/// # Errors
/// HPKE anahtarları geçersiz olduğunda veya kapsülleme/şifreleme sırasında hata
/// yaşandığında `PacketError` döner.
pub fn seal<R>(
    suite: HpkeSuite,
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<HpkeSealOutput, PacketError>
where
    R: CryptoRng + RngCore,
{
    match suite {
        HpkeSuite::X25519HkdfSha256ChaCha20Poly1305 => {
            suite.seal_impl::<ChaCha20Poly1305, _>(recipient_public_key, info, aad, plaintext, rng)
        }
        HpkeSuite::X25519HkdfSha256AesGcm256 => {
            suite.seal_impl::<AesGcm256, _>(recipient_public_key, info, aad, plaintext, rng)
        }
    }
}

/// HPKE ile şifrelenmiş veriyi çözer.
///
/// # Errors
/// HPKE gizli anahtarı veya kapsüllenmiş anahtar geçersizse ya da doğrulama
/// başarısız olursa `PacketError` döner.
pub fn open(
    suite: HpkeSuite,
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<HpkeOpenOutput, PacketError> {
    match suite {
        HpkeSuite::X25519HkdfSha256ChaCha20Poly1305 => suite.open_impl::<ChaCha20Poly1305>(
            recipient_private_key,
            encapsulated_key,
            info,
            aad,
            ciphertext,
        ),
        HpkeSuite::X25519HkdfSha256AesGcm256 => suite.open_impl::<AesGcm256>(
            recipient_private_key,
            encapsulated_key,
            info,
            aad,
            ciphertext,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const INFO: &[u8] = b"hpke-test";
    const AAD: &[u8] = b"hpke aad";
    const PLAINTEXT: &[u8] = b"HPKE makes future migrations easier";

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42_u8; 32])
    }

    fn roundtrip(suite: HpkeSuite) {
        let mut key_rng = rng();
        let keypair = generate_keypair(&mut key_rng);
        let mut seal_rng = rng();
        let sealed = seal(
            suite,
            keypair.public_key(),
            INFO,
            AAD,
            PLAINTEXT,
            &mut seal_rng,
        )
        .expect("seal");
        let opened = open(
            suite,
            keypair.private_key().as_slice(),
            &sealed.encapsulated_key,
            INFO,
            AAD,
            &sealed.ciphertext,
        )
        .expect("open");
        assert_eq!(opened.plaintext, PLAINTEXT);
        assert_eq!(opened.export_secret, sealed.export_secret);
    }

    #[test]
    fn roundtrip_chacha20poly1305() {
        roundtrip(HpkeSuite::X25519HkdfSha256ChaCha20Poly1305);
    }

    #[test]
    fn roundtrip_aesgcm256() {
        roundtrip(HpkeSuite::X25519HkdfSha256AesGcm256);
    }

    #[test]
    fn different_info_changes_export() {
        let mut key_rng = rng();
        let keypair = generate_keypair(&mut key_rng);
        let mut rng_a = rng();
        let mut rng_b = rng();
        let sealed_a = seal(
            HpkeSuite::X25519HkdfSha256ChaCha20Poly1305,
            keypair.public_key(),
            INFO,
            AAD,
            PLAINTEXT,
            &mut rng_a,
        )
        .expect("seal");
        let sealed_b = seal(
            HpkeSuite::X25519HkdfSha256ChaCha20Poly1305,
            keypair.public_key(),
            b"hpke-test-alt",
            AAD,
            PLAINTEXT,
            &mut rng_b,
        )
        .expect("seal");
        assert_ne!(sealed_a.export_secret, sealed_b.export_secret);
    }

    #[test]
    fn rejects_invalid_keys() {
        let mut key_rng = rng();
        let keypair = generate_keypair(&mut key_rng);
        let mut seal_rng = rng();
        let sealed = seal(
            HpkeSuite::X25519HkdfSha256ChaCha20Poly1305,
            keypair.public_key(),
            INFO,
            AAD,
            PLAINTEXT,
            &mut seal_rng,
        )
        .expect("seal");
        let err = open(
            HpkeSuite::X25519HkdfSha256ChaCha20Poly1305,
            &[0_u8; 31],
            &sealed.encapsulated_key,
            INFO,
            AAD,
            &sealed.ciphertext,
        )
        .expect_err("invalid sk");
        assert!(matches!(err, PacketError::Invalid(_)));
    }
}
