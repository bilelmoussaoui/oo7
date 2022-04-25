use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
use hmac::{digest::OutputSizeUser, Mac};

use crate::{error::Result, Key};

type MacAlg = hmac::Hmac<sha2::Sha256>;
type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

pub(crate) fn encrypt(data: &[u8], key: &Key) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut blob = vec![0; data.len() + EncAlg::block_size()];

    let iv = EncAlg::generate_iv(cipher::rand_core::OsRng);

    // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for PKCS7
    let encrypted_len = EncAlg::new(key.as_ref().into(), &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut blob)
        .unwrap()
        .len();

    blob.truncate(encrypted_len);

    // Unwrapping since arbitrary keylength allowed
    let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
    mac.update(&blob);
    blob.append(&mut mac.finalize().into_bytes().as_slice().into());

    Ok((blob, iv.to_vec()))
}

pub(crate) fn decrypt(data: &[u8], key: &Key, iv: &[u8]) -> Result<Vec<u8>> {
    let data_len = data.len();
    let mut data = data.to_vec();

    let mac_tag = data.split_off(data_len - hmac::HmacCore::<sha2::Sha256>::output_size());

    // verify item
    let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
    mac.update(data.as_ref());
    mac.verify_slice(&mac_tag).unwrap();

    // decrypt item
    let decrypted = DecAlg::new(key.as_ref().into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(data.as_mut())
        .unwrap()
        .to_vec();

    Ok(decrypted)
}
