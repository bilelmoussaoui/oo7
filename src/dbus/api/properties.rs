use std::collections::HashMap;

use serde::ser::{Serialize, SerializeMap};
use zbus::zvariant::Type;

static PROPERTY_LABEL: &str = "org.freedesktop.Secret.Item.Label";
static PROPERTY_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

#[derive(Debug, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Properties<'a> {
    label: &'a str,
    attributes: HashMap<&'a str, &'a str>,
}

impl<'a> Properties<'a> {
    pub fn new(label: &'a str, attributes: HashMap<&'a str, &'a str>) -> Self {
        Self { label, attributes }
    }

    pub fn with_label(label: &'a str) -> Self {
        Self {
            label,
            attributes: Default::default(),
        }
    }
}

impl<'a> Serialize for Properties<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.attributes.is_empty() {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(PROPERTY_LABEL, self.label)?;
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry(PROPERTY_LABEL, self.label)?;
            map.serialize_entry(PROPERTY_ATTRIBUTES, &self.attributes)?;
            map.end()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_label() {
        let properties = Properties::with_label("some_label");

        let encoded = serde_json::to_string(&properties).unwrap();
        let decoded: HashMap<&str, &str> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded[PROPERTY_LABEL], "some_label");
        assert!(!decoded.contains_key(PROPERTY_ATTRIBUTES));
    }

    #[test]
    fn serialize_label_with_attributes() {
        let mut attributes = HashMap::new();
        attributes.insert("some", "attribute");
        let properties = Properties::new("some_label", attributes);

        let encoded = serde_json::to_string(&properties).unwrap();
        let decoded: HashMap<&str, serde_json::Value> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded[PROPERTY_LABEL], "some_label");
        assert!(decoded.contains_key(PROPERTY_ATTRIBUTES));
        assert_eq!(decoded[PROPERTY_ATTRIBUTES]["some"], "attribute");
    }

    #[test]
    fn signature() {
        assert_eq!(Properties::signature(), "a{sv}");
    }
}
