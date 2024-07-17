#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
#[cfg(all(all(feature = "tokio", feature = "async-std"), not(doc)))]
compile_error!("You can't enable both async-std & tokio features at once");

use std::collections::{BTreeMap, HashMap};

mod error;
mod key;
mod migration;

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub use key::Key;
#[cfg(not(feature = "unstable"))]
pub(crate) use key::Key;

#[cfg(not(feature = "unstable"))]
mod crypto;
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod crypto;
pub mod dbus;
pub mod portal;

mod helpers;
mod keyring;

pub use error::{Error, Result};
pub use keyring::{Item, Keyring};
pub use migration::migrate;
pub use zbus;

/// Checks whether the application is sandboxed or not.
pub async fn is_sandboxed() -> bool {
    helpers::is_flatpak().await || helpers::is_snap().await
}

/// An item/collection attributes.
pub trait AsAttributes {
    fn as_attributes(&self) -> HashMap<&str, &str>;

    fn hash<'a>(&'a self, key: &Key) -> Vec<(&'a str, zeroize::Zeroizing<Vec<u8>>)> {
        self.as_attributes()
            .into_iter()
            .map(|(k, v)| (k, crate::portal::AttributeValue::from(v).mac(key)))
            .collect()
    }
}

impl<K, V> AsAttributes for &[(K, V)]
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for &HashMap<K, V>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for HashMap<K, V>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for BTreeMap<K, V>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for &BTreeMap<K, V>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for Vec<(K, V)>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}

impl<K, V> AsAttributes for &Vec<(K, V)>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn as_attributes(&self) -> HashMap<&str, &str> {
        self.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect()
    }
}
