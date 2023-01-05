#[cfg(feature = "native_crypto")]
mod native;
#[cfg(feature = "native_crypto")]
pub(crate) use native::*;

#[cfg(feature = "openssl_crypto")]
mod openssl;
#[cfg(feature = "openssl_crypto")]
pub(crate) use self::openssl::*;

#[cfg(test)]
mod test {
    use super::*;
    use crate::Key;

    #[test]
    fn test_encrypt() {
        let data = b"some data";
        let expected_encrypted = &[
            241, 233, 175, 173, 142, 44, 63, 240, 77, 154, 211, 233, 217, 170, 49, 142,
        ];
        let aes_key = Key::new(vec![
            132, 3, 113, 222, 81, 209, 49, 43, 81, 232, 243, 46, 1, 103, 184, 42,
        ]);
        let aes_iv = &[
            78, 82, 67, 158, 214, 102, 48, 109, 84, 107, 94, 54, 225, 29, 186, 246,
        ];

        let encrypted = encrypt(data, &aes_key, aes_iv);
        assert_eq!(encrypted, expected_encrypted);

        let decrypted = decrypt(&encrypted, &aes_key, aes_iv);
        assert_eq!(decrypted.to_vec(), data);
    }
}
