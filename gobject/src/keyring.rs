use std::sync::{Arc, OnceLock};

use glib::{subclass::prelude::*, translate::*};
use gobject_ffi::{c_return_type, ffi_impl};

use crate::error::to_glib_error;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Keyring {
        pub(super) inner: OnceLock<Arc<oo7_rs::Keyring>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Keyring {
        const NAME: &'static str = "Oo7Keyring";
        type Type = super::Keyring;
    }

    impl ObjectImpl for Keyring {}
}

glib::wrapper! {
    pub struct Keyring(ObjectSubclass<imp::Keyring>);
}

unsafe impl Send for Keyring {}
unsafe impl Sync for Keyring {}

impl Keyring {
    fn inner(&self) -> Arc<oo7_rs::Keyring> {
        self.imp().inner.get().unwrap().clone()
    }

    fn set_inner(&self, keyring: Arc<oo7_rs::Keyring>) {
        self.imp().inner.set(keyring).ok();
    }
}

#[ffi_impl(prefix = "oo7")]
impl Keyring {
    async fn new() -> Result<Keyring, glib::Error> {
        oo7_rs::Keyring::new()
            .await
            .map(|keyring| {
                let obj = glib::Object::new::<Keyring>();
                obj.set_inner(Arc::new(keyring));
                obj
            })
            .map_err(to_glib_error)
    }

    async fn unlock(&self) -> Result<bool, glib::Error> {
        self.inner()
            .unlock()
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn lock(&self) -> Result<bool, glib::Error> {
        self.inner()
            .lock()
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn is_locked(&self) -> Result<bool, glib::Error> {
        self.inner().is_locked().await.map_err(to_glib_error)
    }

    async fn create_item(
        &self,
        label: String,
        #[c_type(*mut glib::ffi::GHashTable, transfer=none)]
        attributes: crate::ffi_wrappers::Attributes,
        secret: Vec<u8>,
        replace: bool,
    ) -> Result<bool, glib::Error> {
        let oo7_secret = oo7_rs::Secret::from(secret);
        let map = attributes.into_inner();
        self.inner()
            .create_item(&label, &map, oo7_secret, replace)
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn delete(
        &self,
        #[c_type(*mut glib::ffi::GHashTable, transfer=none)]
        attributes: crate::ffi_wrappers::Attributes,
    ) -> Result<bool, glib::Error> {
        let map = attributes.into_inner();
        self.inner()
            .delete(&map)
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    #[c_return_type(*mut glib::ffi::GList, transfer=full)]
    async fn search_items(
        &self,
        #[c_type(*mut glib::ffi::GHashTable, transfer=none)]
        attributes: crate::ffi_wrappers::Attributes,
    ) -> Result<crate::ffi_wrappers::ItemVec, glib::Error> {
        let map = attributes.into_inner();
        self.inner()
            .search_items(&map)
            .await
            .map(|items| {
                // Convert Vec<Item> to Vec<Arc<Item>>
                let arc_items: Vec<std::sync::Arc<oo7_rs::Item>> =
                    items.into_iter().map(std::sync::Arc::new).collect();
                crate::ffi_wrappers::ItemVec(std::sync::Arc::new(arc_items))
            })
            .map_err(to_glib_error)
    }
}
