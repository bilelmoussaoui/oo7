use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{Algorithm, Result};

use super::api;

pub struct Item<'a> {
    item: Arc<api::Item<'a>>,
    session: Arc<api::Session<'a>>,
    #[allow(unused)]
    algorithm: Arc<Algorithm>,
}

impl<'a> Item<'a> {
    pub(crate) fn new(
        session: Arc<api::Session<'a>>,
        algorithm: Arc<Algorithm>,
        item: api::Item<'a>,
    ) -> Item<'a> {
        Self {
            item: Arc::new(item),
            session,
            algorithm,
        }
    }

    pub async fn is_locked(&self) -> Result<bool> {
        self.item.is_locked().await
    }

    pub async fn label(&self) -> Result<String> {
        self.item.label().await
    }

    pub async fn set_label(&self, label: &str) -> Result<()> {
        self.item.set_label(label).await
    }

    pub async fn created(&self) -> Result<Duration> {
        self.item.created().await
    }

    pub async fn modified(&self) -> Result<Duration> {
        self.item.modified().await
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        self.item.attributes().await
    }

    pub async fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        self.item.set_attributes(attributes).await
    }

    pub async fn delete(&self) -> Result<()> {
        self.item.delete().await
    }

    pub async fn secret(&self) -> Result<Vec<u8>> {
        let secret = self.item.secret(&self.session).await?;
        Ok(secret.value)
    }
}
