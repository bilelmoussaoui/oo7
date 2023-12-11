use serde::{Serialize, Serializer};
use zbus::zvariant::{self, OwnedObjectPath};

#[derive(Debug, Default, zvariant::Type)]
#[zvariant(signature = "o")]
pub struct Prompt {
    path: OwnedObjectPath,
}

impl Prompt {}

impl Serialize for Prompt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OwnedObjectPath::serialize(&self.path, serializer)
    }
}
