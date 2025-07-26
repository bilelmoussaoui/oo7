use crate::{
    Key,
    file::{self, UnlockedItem, api},
};

#[derive(Clone, Debug)]
pub struct LockedItem {
    pub(crate) inner: api::EncryptedItem,
}

impl LockedItem {
    // TODO should return the original item if we fail to decrypt it.
    pub fn unlock(self, key: &Key) -> Result<UnlockedItem, file::Error> {
        self.inner.decrypt(key)
    }
}
