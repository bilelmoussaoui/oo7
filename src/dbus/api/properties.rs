use std::collections::HashMap;

use serde::ser::{Serialize, SerializeMap};
use zbus::zvariant::{Type, Value};

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
            map.serialize_entry(PROPERTY_LABEL, &Value::from(self.label))?;
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry(PROPERTY_LABEL, &Value::from(self.label))?;
            let mut dict = zbus::zvariant::Dict::new(String::signature(), String::signature());
            for (key, value) in &self.attributes {
                dict.add(key, value).expect("Key/Value of correct types");
            }

            map.serialize_entry(PROPERTY_ATTRIBUTES, &Value::from(dict))?;
            map.end()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::LE;
    use zbus::zvariant::{self, from_slice, to_bytes, EncodingContext as Context, Type};

    #[test]
    fn serialize_label() {
        let properties = Properties::with_label("some_label");

        let ctxt = Context::<LE>::new_dbus(0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = from_slice(&encoded, ctxt).unwrap();

        assert_eq!(decoded[PROPERTY_LABEL], Value::from("some_label"));
        assert!(!decoded.contains_key(PROPERTY_ATTRIBUTES));
    }

    #[test]
    fn serialize_label_with_attributes() {
        let mut attributes = HashMap::new();
        attributes.insert("some", "attribute");
        let properties = Properties::new("some_label", attributes.clone());

        let ctxt = Context::<LE>::new_dbus(0);
        let encoded = to_bytes(ctxt, &properties).unwrap();
        let decoded: HashMap<&str, Value<'_>> = from_slice(&encoded, ctxt).unwrap();

        assert_eq!(decoded[PROPERTY_LABEL], Value::from("some_label"));
        assert!(decoded.contains_key(PROPERTY_ATTRIBUTES));
        assert_eq!(
            decoded[PROPERTY_ATTRIBUTES],
            zvariant::Dict::from(attributes).into()
        );
    }

    #[test]
    fn signature() {
        assert_eq!(Properties::signature(), "a{sv}");
    }
}
