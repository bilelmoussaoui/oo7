use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::lock::Mutex;

use crate::{utils, Algorithm, Error, Result};

use super::api;

pub struct Item<'a> {
    inner: Arc<api::Item<'a>>,
    session: Arc<api::Session<'a>>,
    service: Arc<api::Service<'a>>,
    algorithm: Arc<Algorithm>,
    /// Defines whether the Item has been deleted or not
    available: Mutex<bool>,
}

impl<'a> Item<'a> {
    pub(crate) fn new(
        service: Arc<api::Service<'a>>,
        session: Arc<api::Session<'a>>,
        algorithm: Arc<Algorithm>,
        item: api::Item<'a>,
    ) -> Item<'a> {
        Self {
            inner: Arc::new(item),
            service,
            session,
            algorithm,
            available: Mutex::new(true),
        }
    }

    pub(crate) async fn is_available(&self) -> bool {
        *self.available.lock().await
    }

    pub async fn is_locked(&self) -> Result<bool> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.is_locked().await
        }
    }

    pub async fn label(&self) -> Result<String> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.label().await
        }
    }

    pub async fn set_label(&self, label: &str) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_label(label).await
        }
    }

    pub async fn created(&self) -> Result<Duration> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.created().await
        }
    }

    pub async fn modified(&self) -> Result<Duration> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.modified().await
        }
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.attributes().await
        }
    }

    pub async fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_attributes(attributes).await
        }
    }

    pub async fn delete(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.delete().await?;
            *self.available.lock().await = false;
            Ok(())
        }
    }

    pub async fn secret(&self) -> Result<Vec<u8>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = self.inner.secret(&self.session).await?;

            let value = match self.algorithm.as_ref() {
                Algorithm::Plain => secret.value,
                Algorithm::Encrypted(aes_key) => {
                    let iv = secret.parameters;
                    utils::decrypt(&secret.value, aes_key, &iv).unwrap()
                }
            };
            Ok(value)
        }
    }

    #[doc(alias = "SetSecret")]
    pub async fn set_secret(&self, secret: &[u8], content_type: &str) -> Result<()> {
        let secret = api::Secret::new(
            Arc::clone(&self.algorithm),
            Arc::clone(&self.session),
            secret,
            content_type,
        );
        self.inner.set_secret(&secret).await?;
        Ok(())
    }

    pub async fn unlock(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.lock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }

    pub async fn lock(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.lock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }
}
