use std::collections::HashMap;

use serde::ser::{Serialize, SerializeMap};
use zbus::zvariant::{Type, Value};

const ITEM_PROPERTY_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_PROPERTY_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

const COLLECTION_PROPERTY_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

#[derive(Debug, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Properties<'a> {
    label: &'a str,
    attributes: Option<&'a HashMap<&'a str, &'a str>>,
    is_collection: bool,
}

impl<'a> Properties<'a> {
    pub fn for_item(label: &'a str, attributes: &'a HashMap<&'a str, &'a str>) -> Self {
        Self {
            label,
            attributes: Some(attributes),
            is_collection: false,
        }
    }

    pub fn for_collection(label: &'a str) -> Self {
        Self {
            label,
            attributes: None,
            is_collection: true,
        }
    }
}

impl<'a> Serialize for Properties<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.is_collection {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(COLLECTION_PROPERTY_LABEL, &Value::from(self.label))?;
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry(ITEM_PROPERTY_LABEL, &Value::from(self.label))?;
            let mut dict = zbus::zvariant::Dict::new(String::signature(), String::signature());

            if let Some(attributes) = self.attributes {
                for (key, value) in attributes {
                    dict.add(key, value).expect("Key/Value of correct types");
                }
            }

            map.serialize_entry(ITEM_PROPERTY_ATTRIBUTES, &Value::from(dict))?;
            map.end()
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::LE;
    use zbus::zvariant::{self, from_slice, to_bytes, EncodingContext as Context, Type};

    use super::*;

    #[test]
    fn serialize_label() {
        let properties = Properties::for_collection("some_label");

        let ctxt = Context::<LE>::new_dbus(0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = from_slice(&encoded, ctxt).unwrap();

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

        let ctxt = Context::<LE>::new_dbus(0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = from_slice(&encoded, ctxt).unwrap();

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
        assert_eq!(Properties::signature(), "a{sv}");
    }
}
