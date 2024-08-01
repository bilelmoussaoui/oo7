use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{hash, Hasher, MessageDigest},
    md::Md,
    memcmp,
    nid::Nid,
    pkcs5::pbkdf2_hmac,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use zeroize::Zeroizing;

use crate::{portal, Key};

const ENC_ALG: Nid = Nid::AES_128_CBC;
const MAC_ALG: Nid = Nid::SHA256;

pub fn encrypt(data: impl AsRef<[u8]>, key: &Key, iv: impl AsRef<[u8]>) -> Vec<u8> {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    let mut encryptor = Crypter::new(cipher, Mode::Encrypt, key.as_ref(), Some(iv.as_ref()))
        .expect("Invalid key or IV length");
    encryptor.pad(true);

    let mut blob = vec![0; data.as_ref().len() + cipher.block_size()];
    // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for
    // PKCS7
    let mut encrypted_len = encryptor.update(data.as_ref(), &mut blob).unwrap();
    encrypted_len += encryptor.finalize(&mut blob[encrypted_len..]).unwrap();

    blob.truncate(encrypted_len);

    blob
}

fn decrypt_with_padding(
    blob: impl AsRef<[u8]>,
    key: &Key,
    iv: impl AsRef<[u8]>,
    pad: bool,
) -> Zeroizing<Vec<u8>> {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key.as_ref(), Some(iv.as_ref()))
        .expect("Invalid key or IV length");
    decrypter.pad(pad);

    let mut data = Zeroizing::new(vec![0; blob.as_ref().len() + cipher.block_size()]);
    let mut decrypted_len = decrypter.update(blob.as_ref(), &mut data).unwrap();
    decrypted_len += decrypter.finalize(&mut data[decrypted_len..]).unwrap();

    data.truncate(decrypted_len);

    data
}

pub(crate) fn decrypt(
    blob: impl AsRef<[u8]>,
    key: &Key,
    iv: impl AsRef<[u8]>,
) -> Zeroizing<Vec<u8>> {
    decrypt_with_padding(blob, key, iv, true)
}

pub(crate) fn decrypt_no_padding(
    blob: impl AsRef<[u8]>,
    key: &Key,
    iv: impl AsRef<[u8]>,
) -> Zeroizing<Vec<u8>> {
    decrypt_with_padding(blob, key, iv, false)
}

pub(crate) fn iv_len() -> usize {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    cipher.iv_len().unwrap()
}

pub(crate) fn generate_private_key() -> Zeroizing<Vec<u8>> {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    let mut buf = Zeroizing::new(vec![0; cipher.key_len()]);
    // FIXME: should return an error?
    rand_bytes(&mut buf).unwrap();
    buf
}

pub(crate) fn generate_public_key(private_key: impl AsRef<[u8]>) -> Vec<u8> {
    let private_key_bn = BigNum::from_slice(private_key.as_ref()).unwrap();
    Dh::from_pqg(
        BigNum::get_rfc2409_prime_1024().unwrap(),
        None,
        BigNum::from_u32(2).unwrap(),
    )
    .and_then(|key| key.set_private_key(private_key_bn))
    .unwrap()
    .public_key()
    .to_vec()
}

pub(crate) fn generate_aes_key(
    private_key: impl AsRef<[u8]>,
    server_public_key: impl AsRef<[u8]>,
) -> Zeroizing<Vec<u8>> {
    let private_key_bn = BigNum::from_slice(private_key.as_ref()).unwrap();
    let server_public_key_bn = BigNum::from_slice(server_public_key.as_ref()).unwrap();
    let mut common_secret_bytes = Dh::from_pqg(
        BigNum::get_rfc2409_prime_1024().unwrap(),
        None,
        BigNum::from_u32(2).unwrap(),
    )
    .and_then(|key| key.set_private_key(private_key_bn))
    .and_then(|key| key.compute_key(&server_public_key_bn))
    .unwrap();

    let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
    // inefficient, but ok for now
    common_secret_padded.append(&mut common_secret_bytes);

    // hkdf
    // input_keying_material
    let ikm = common_secret_padded;

    let mut okm = Zeroizing::new(vec![0; 16]);
    let mut ctx = PkeyCtx::new_id(Id::HKDF).unwrap();
    ctx.derive_init().unwrap();
    ctx.set_hkdf_md(Md::sha256()).unwrap();
    ctx.set_hkdf_key(&ikm).unwrap();
    ctx.derive(Some(okm.as_mut()))
        .expect("hkdf expand should never fail");
    okm
}

pub fn generate_iv() -> Vec<u8> {
    let mut buf = vec![0; iv_len()];
    // FIXME: should return an error?
    rand_bytes(&mut buf).unwrap();
    buf
}

pub(crate) fn mac_len() -> usize {
    let md = MessageDigest::from_nid(MAC_ALG).unwrap();
    md.size()
}

pub(crate) fn compute_mac(data: impl AsRef<[u8]>, key: &Key) -> Vec<u8> {
    let md = MessageDigest::from_nid(MAC_ALG).unwrap();
    let mac_key = PKey::hmac(key.as_ref()).unwrap();
    let mut signer = Signer::new(md, &mac_key).unwrap();
    signer.update(data.as_ref()).unwrap();
    signer.sign_to_vec().unwrap()
}

pub(crate) fn verify_mac(data: impl AsRef<[u8]>, key: &Key, expected: impl AsRef<[u8]>) -> bool {
    memcmp::eq(compute_mac(&data, key).as_slice(), expected.as_ref())
}

pub(crate) fn verify_checksum_md5(digest: impl AsRef<[u8]>, content: impl AsRef<[u8]>) -> bool {
    memcmp::eq(
        &hash(MessageDigest::md5(), content.as_ref()).unwrap(),
        digest.as_ref(),
    )
}

pub(crate) fn derive_key(
    secret: impl AsRef<[u8]>,
    key_strength: Result<(), portal::WeakKeyError>,
    salt: impl AsRef<[u8]>,
    iteration_count: usize,
) -> Key {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    let mut key = Key::new_with_strength(vec![0; cipher.block_size()], key_strength);

    let md = MessageDigest::from_nid(MAC_ALG).unwrap();
    pbkdf2_hmac(
        secret.as_ref(),
        salt.as_ref(),
        iteration_count,
        md,
        key.as_mut(),
    )
    .unwrap();

    key
}

pub(crate) fn legacy_derive_key_and_iv(
    secret: impl AsRef<[u8]>,
    key_strength: Result<(), portal::WeakKeyError>,
    salt: impl AsRef<[u8]>,
    iteration_count: usize,
) -> (Key, Vec<u8>) {
    let cipher = Cipher::from_nid(ENC_ALG).unwrap();
    let mut buffer = vec![0; cipher.key_len() + cipher.iv_len().unwrap()];
    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    let mut pos = 0usize;

    loop {
        hasher.update(secret.as_ref()).unwrap();
        hasher.update(salt.as_ref()).unwrap();
        let mut digest = hasher.finish().unwrap();

        for _ in 1..iteration_count {
            // We can't pass an instance, the borrow checker
            // would complain about digest being dropped at the end of
            // foor block
            #[allow(clippy::needless_borrows_for_generic_args)]
            hasher.update(&digest).unwrap();
            digest = hasher.finish().unwrap();
        }

        let to_read = usize::min(digest.len(), buffer.len() - pos);
        buffer[pos..].copy_from_slice(&(&*digest)[..to_read]);
        pos += to_read;

        if pos == buffer.len() {
            break;
        }

        // We can't pass an instance, the borrow checker
        // would complain about digest being dropped at the end of
        // foor block
        #[allow(clippy::needless_borrows_for_generic_args)]
        hasher.update(&digest).unwrap();
    }

    let iv = buffer.split_off(cipher.key_len());
    (Key::new_with_strength(buffer, key_strength), iv)
}
