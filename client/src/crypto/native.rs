use std::{
    ops::{Mul, Rem, Shr},
    sync::OnceLock,
};

use cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, IvSizeUser, KeyIvInit,
};
use digest::{Mac, OutputSizeUser};
use hkdf::Hkdf;
use num::{FromPrimitive, Integer, One, Zero};
use num_bigint_dig::BigUint;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{portal, Key};

type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;
type MacAlg = hmac::Hmac<sha2::Sha256>;

pub(crate) fn encrypt(data: impl AsRef<[u8]>, key: &Key, iv: impl AsRef<[u8]>) -> Vec<u8> {
    let mut blob = vec![0; data.as_ref().len() + EncAlg::block_size()];

    // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for
    // PKCS7
    let encrypted_len = EncAlg::new_from_slices(key.as_ref(), iv.as_ref())
        .expect("Invalid key length")
        .encrypt_padded_b2b_mut::<Pkcs7>(data.as_ref(), &mut blob)
        .unwrap()
        .len();

    blob.truncate(encrypted_len);

    blob
}

pub(crate) fn decrypt(
    blob: impl AsRef<[u8]>,
    key: &Key,
    iv: impl AsRef<[u8]>,
) -> Zeroizing<Vec<u8>> {
    let mut data = blob.as_ref().to_vec();

    DecAlg::new_from_slices(key.as_ref(), iv.as_ref())
        .expect("Invalid key length")
        .decrypt_padded_mut::<Pkcs7>(&mut data)
        .unwrap()
        .to_vec()
        .into()
}

pub(crate) fn iv_len() -> usize {
    DecAlg::iv_size()
}

pub(crate) fn generate_private_key() -> Zeroizing<Vec<u8>> {
    let generic_array = EncAlg::generate_key(cipher::rand_core::OsRng);
    Zeroizing::new(generic_array.to_vec())
}

pub(crate) fn generate_public_key(private_key: impl AsRef<[u8]>) -> Vec<u8> {
    let private_key_uint = BigUint::from_bytes_be(private_key.as_ref());
    let dh_generator = {
        static DH_GENERATOR: OnceLock<BigUint> = OnceLock::new();
        DH_GENERATOR.get_or_init(|| BigUint::from_u64(0x2).unwrap())
    };
    let public_key_uint = powm(dh_generator, private_key_uint);

    public_key_uint.to_bytes_be()
}

pub(crate) fn generate_aes_key(
    private_key: impl AsRef<[u8]>,
    server_public_key: impl AsRef<[u8]>,
) -> Zeroizing<Vec<u8>> {
    let server_public_key_uint = BigUint::from_bytes_be(server_public_key.as_ref());
    let private_key_uint = BigUint::from_bytes_be(private_key.as_ref());
    let common_secret = powm(&server_public_key_uint, private_key_uint);

    let mut common_secret_bytes = common_secret.to_bytes_be();
    let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
    // inefficient, but ok for now
    common_secret_padded.append(&mut common_secret_bytes);

    // hkdf
    // input_keying_material
    let ikm = common_secret_padded;
    let salt = None;
    let info = [];

    // output keying material
    let mut okm = Zeroizing::new(vec![0; 16]);

    let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
    hk.expand(&info, okm.as_mut())
        .expect("hkdf expand should never fail");

    okm
}

pub(crate) fn generate_iv() -> Vec<u8> {
    EncAlg::generate_iv(cipher::rand_core::OsRng).to_vec()
}

pub(crate) fn mac_len() -> usize {
    MacAlg::output_size()
}

pub(crate) fn compute_mac(data: impl AsRef<[u8]>, key: &Key) -> Vec<u8> {
    let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
    mac.update(data.as_ref());
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn verify_mac(data: impl AsRef<[u8]>, key: &Key, expected: impl AsRef<[u8]>) -> bool {
    let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
    mac.update(data.as_ref());
    mac.verify_slice(expected.as_ref()).is_ok()
}

pub(crate) fn derive_key(
    secret: impl AsRef<[u8]>,
    key_strength: Result<(), portal::WeakKeyError>,
    salt: impl AsRef<[u8]>,
    iteration_count: usize,
) -> Key {
    let mut key = Key::new_with_strength(vec![0; EncAlg::block_size()], key_strength);

    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        secret.as_ref(),
        salt.as_ref(),
        iteration_count.try_into().unwrap(),
        key.as_mut(),
    )
    .expect("HMAC can be initialized with any key length");

    key
}

/// from https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs#L53
fn powm(base: &BigUint, mut exp: BigUint) -> BigUint {
    let modulus = {
        // for key exchange
        static DH_PRIME: OnceLock<BigUint> = OnceLock::new();
        DH_PRIME.get_or_init(|| {
            BigUint::from_bytes_be(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68,
                0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08,
                0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A,
                0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
                0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51,
                0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
                0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38,
                0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ])
        })
    };

    let mut base = base.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }
    exp.zeroize();

    result
}
