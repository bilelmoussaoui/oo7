use std::sync::{Arc, OnceLock};

use glib::{subclass::prelude::*, translate::*};
use gobject_ffi::{c_return_type, ffi_impl};

use crate::{error::to_glib_error, ffi_wrappers::Attributes};
mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Item {
        pub(super) inner: OnceLock<Arc<oo7_rs::Item>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Item {
        const NAME: &'static str = "Oo7Item";
        type Type = super::Item;
    }

    impl ObjectImpl for Item {}
}

glib::wrapper! {
    pub struct Item(ObjectSubclass<imp::Item>);
}

unsafe impl Send for Item {}
unsafe impl Sync for Item {}

impl Item {
    pub fn new(item: oo7_rs::Item) -> Self {
        Self::from_arc(Arc::new(item))
    }

    pub fn from_arc(item: Arc<oo7_rs::Item>) -> Self {
        let obj = glib::Object::new::<Item>();
        obj.imp().inner.set(item).ok();
        obj
    }

    fn inner(&self) -> Arc<oo7_rs::Item> {
        self.imp().inner.get().unwrap().clone()
    }
}

#[ffi_impl(prefix = "oo7")]
impl Item {
    #[c_return_type(*mut glib::ffi::GHashTable, transfer=full)]
    async fn get_attributes(&self) -> Result<Attributes, glib::Error> {
        self.inner()
            .attributes()
            .await
            .map(Attributes)
            .map_err(to_glib_error)
    }

    async fn get_label(&self) -> Result<String, glib::Error> {
        self.inner().label().await.map_err(to_glib_error)
    }

    async fn get_created(&self) -> Result<u64, glib::Error> {
        self.inner()
            .created()
            .await
            .map(|d| d.as_secs())
            .map_err(to_glib_error)
    }

    async fn get_modified(&self) -> Result<u64, glib::Error> {
        self.inner()
            .modified()
            .await
            .map(|d| d.as_secs())
            .map_err(to_glib_error)
    }

    async fn is_locked(&self) -> Result<bool, glib::Error> {
        self.inner().is_locked().await.map_err(to_glib_error)
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

    async fn set_label(&self, label: String) -> Result<bool, glib::Error> {
        self.inner()
            .set_label(&label)
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn get_secret(&self) -> Result<glib::Bytes, glib::Error> {
        self.inner()
            .secret()
            .await
            .map(|s| glib::Bytes::from_owned(s.as_bytes().to_vec()))
            .map_err(to_glib_error)
    }

    async fn set_secret(&self, secret: Vec<u8>) -> Result<bool, glib::Error> {
        let oo7_secret = oo7_rs::Secret::from(secret);
        self.inner()
            .set_secret(oo7_secret)
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn delete(&self) -> Result<bool, glib::Error> {
        self.inner()
            .delete()
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }

    async fn set_attributes(
        &self,
        #[c_type(*mut glib::ffi::GHashTable, transfer=none)] attributes: Attributes,
    ) -> Result<bool, glib::Error> {
        let map = attributes.into_inner();
        self.inner()
            .set_attributes(&map)
            .await
            .map(|_| true)
            .map_err(to_glib_error)
    }
}
