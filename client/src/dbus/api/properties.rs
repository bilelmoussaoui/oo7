use std::collections::HashMap;

use serde::{
    ser::{Serialize, SerializeMap},
    Deserialize,
};
use zbus::zvariant::{Type, Value};

use crate::AsAttributes;

const ITEM_PROPERTY_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_PROPERTY_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

const COLLECTION_PROPERTY_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

#[derive(Debug, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Properties {
    label: String,
    attributes: Option<HashMap<String, String>>,
}

impl Properties {
    pub fn for_item(label: &str, attributes: &impl AsAttributes) -> Self {
        Self {
            label: label.to_owned(),
            attributes: Some(
                attributes
                    .as_attributes()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        }
    }

    pub fn for_collection(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            attributes: None,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn attributes(&self) -> Option<&HashMap<String, String>> {
        self.attributes.as_ref()
    }
}

impl Serialize for Properties {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.attributes.is_none() {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(COLLECTION_PROPERTY_LABEL, &Value::from(&self.label))?;
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry(ITEM_PROPERTY_LABEL, &Value::from(&self.label))?;
            let mut dict = zbus::zvariant::Dict::new(String::SIGNATURE, String::SIGNATURE);

            if let Some(attributes) = &self.attributes {
                for (key, value) in attributes {
                    dict.add(key, value).expect("Key/Value of correct types");
                }
            }

            map.serialize_entry(ITEM_PROPERTY_ATTRIBUTES, &Value::from(dict))?;
            map.end()
        }
    }
}

impl<'de> Deserialize<'de> for Properties {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map: HashMap<&str, Value<'_>> = HashMap::deserialize(deserializer)?;
        if map.contains_key(COLLECTION_PROPERTY_LABEL) {
            let label =
                zvariant::Str::try_from(map.get(COLLECTION_PROPERTY_LABEL).unwrap()).unwrap();
            Ok(Self::for_collection(&label))
        } else {
            let label = zvariant::Str::try_from(map.get(ITEM_PROPERTY_LABEL).unwrap()).unwrap();
            let attributes = HashMap::<String, String>::try_from(
                map.get(ITEM_PROPERTY_ATTRIBUTES)
                    .unwrap()
                    .try_clone()
                    .unwrap(),
            )
            .unwrap();
            Ok(Self::for_item(&label, &attributes))
        }
    }
}

#[cfg(test)]
mod tests {
    use zbus::zvariant::{serialized::Context, to_bytes, Endian, Type};

    use super::*;

    #[test]
    fn serialize_label() {
        let properties = Properties::for_collection("some_label");

        let ctxt = Context::new_dbus(Endian::Little, 0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = encoded.deserialize().unwrap().0;

        assert_eq!(
            decoded[COLLECTION_PROPERTY_LABEL],
            Value::from("some_label")
        );
        assert!(!decoded.contains_key(ITEM_PROPERTY_ATTRIBUTES));
        assert!(!decoded.contains_key(ITEM_PROPERTY_LABEL));
    }

    #[test]
    fn serialize_label_with_attributes() {
        let mut attributes = HashMap::new();
        attributes.insert("some", "attribute");
        let properties = Properties::for_item("some_label", &attributes);

        let ctxt = Context::new_dbus(Endian::Little, 0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = encoded.deserialize().unwrap().0;

        assert_eq!(decoded[ITEM_PROPERTY_LABEL], Value::from("some_label"));
        assert!(!decoded.contains_key(COLLECTION_PROPERTY_LABEL));
        assert!(decoded.contains_key(ITEM_PROPERTY_ATTRIBUTES));
        assert_eq!(
            decoded[ITEM_PROPERTY_ATTRIBUTES],
            zvariant::Dict::from(attributes).into()
        );
    }

    #[test]
    fn signature() {
        assert_eq!(Properties::SIGNATURE, "a{sv}");
    }
}
