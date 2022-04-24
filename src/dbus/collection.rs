use std::{collections::HashMap, sync::Arc};

use crate::{Algorithm, Result};

use super::{api, Item};

pub struct Collection<'a> {
    collection: Arc<api::Collection<'a>>,
    session: Arc<api::Session<'a>>,
    algorithm: Arc<Algorithm>,
}

impl<'a> Collection<'a> {
    pub(crate) fn new(
        session: Arc<api::Session<'a>>,
        algorithm: Arc<Algorithm>,
        collection: api::Collection<'a>,
    ) -> Collection<'a> {
        Self {
            collection: Arc::new(collection),
            session,
            algorithm,
        }
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        let items = self.collection.search_items(attributes).await?;
        Ok(items
            .into_iter()
            .map(|item| Item::new(Arc::clone(&self.session), Arc::clone(&self.algorithm), item))
            .collect::<Vec<_>>())
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Item<'_>> {
        let secret = api::Secret::new(
            Arc::clone(&self.algorithm),
            Arc::clone(&self.session),
            secret,
            content_type,
        );

        let item = self
            .collection
            .create_item(label, attributes, &secret, replace)
            .await?;

        Ok(Item::new(
            Arc::clone(&self.session),
            Arc::clone(&self.algorithm),
            item,
        ))
    }
}
