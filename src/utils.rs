use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, IvSizeUser, KeyIvInit,
};
use hmac::{digest::OutputSizeUser, Mac};
use zeroize::Zeroizing;

use crate::error::Result;

type MacAlg = hmac::Hmac<sha2::Sha256>;
type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut blob = vec![0; data.len() + EncAlg::block_size()];
    let iv = EncAlg::generate_iv(cipher::rand_core::OsRng);

    // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for PKCS7
    let encrypted_len = EncAlg::new(key.into(), &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut blob)
        .unwrap()
        .len();

    blob.truncate(encrypted_len);
    blob.append(&mut iv.as_slice().into());

    // Unwrapping since arbitrary keylength allowed
    let mut mac = MacAlg::new_from_slice(key).unwrap();
    mac.update(&blob);
    blob.append(&mut mac.finalize().into_bytes().as_slice().into());

    Ok(blob)
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let data_len = data.len();
    let mut data = data.to_vec();

    let mac_tag = data.split_off(data_len - hmac::HmacCore::<sha2::Sha256>::output_size());

    // verify item
    let mut mac = MacAlg::new_from_slice(key).unwrap();
    mac.update(&data);
    mac.verify_slice(&mac_tag).unwrap();

    let iv = data.split_off(data_len - DecAlg::iv_size());

    let mut data_ = Zeroizing::new(data);

    // decrypt item
    let decrypted = DecAlg::new(key.into(), iv.as_slice().into())
        .decrypt_padded_mut::<Pkcs7>(&mut data_)
        .unwrap()
        .to_vec();

    Ok(decrypted)
}
