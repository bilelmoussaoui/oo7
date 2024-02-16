//  org.freedesktop.Secret.Service

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use oo7::{
    dbus::{
        api::{Properties, SecretInner},
        Algorithm,
    },
    portal::{Item, Keyring},
    Key,
};
use tokio::sync::RwLock;
use zbus::{
    proxy::ProxyDefault,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
    ObjectServer, SignalContext,
};

use super::{
    collection::Collection, error::ServiceError, prompt::Prompt, session::Session, Result,
};

#[derive(Debug)]
pub struct Service {
    collections: RwLock<Vec<Collection>>,
    keyring: Arc<Keyring>,
    cnx: Mutex<Option<zbus::Connection>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let client_public_key = match algorithm {
            Algorithm::Plain => None,
            Algorithm::Encrypted => Some(Key::from(input)),
        };
        let (session, key) = Session::new(client_public_key);
        // TODO: clean up the default generated key
        let key = key
            .map(|k| OwnedValue::from(&k))
            .unwrap_or_else(|| Value::new::<Vec<u8>>(vec![]).try_to_owned().unwrap());
        Ok((key, session.path().into()))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        properties: Properties,
        alias: &str,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, Prompt)> {
        let collection = Collection::new(
            properties.label(),
            alias,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            Arc::clone(&self.keyring),
        );
        self.collections.write().await.push(Collection::new(
            collection.label(),
            alias,
            *collection.created(),
            Arc::clone(&self.keyring),
        ));

        let path = OwnedObjectPath::from(collection.path());
        object_server.at(&path, collection).await?;
        let prompt = Prompt::default(); // temp Prompt
        Self::collection_created(&ctxt, path.as_ref())
            .await
            .map_err::<ServiceError, _>(From::from)?;
        Ok((path, prompt))
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<(Vec<Item>, Vec<Item>)> {
        let items = self
            .keyring
            .search_items(&attributes)
            .await
            .map_err::<ServiceError, _>(From::from)?;

        let mut unlocked: Vec<Item> = Vec::new();
        let mut locked: Vec<Item> = Vec::new();

        for item in items {
            let attributes = item.attributes();
            if attributes.get("locked").is_some() {
                // this if condition is probably wrong
                // how to access &AttributeValue value
                locked.push(item)
            } else {
                unlocked.push(item)
            }
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, Prompt)> {
        // manage unlock state in memory
        // when do we need to prompt?
        let mut unlocked: Vec<OwnedObjectPath> = Vec::new();

        'main: for object in objects {
            for collection in self.collections.read().await.iter() {
                if collection.path() == *object {
                    if collection.locked() {
                        collection.set_locked(false).await;
                        unlocked.push(object.clone());
                    } else {
                        break 'main;
                    }
                }
            }
        }

        if unlocked.is_empty() {
            unlocked.push(OwnedObjectPath::default());
        }

        let prompt = Prompt::default(); // temporarily

        Ok((unlocked, prompt))
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, Prompt)> {
        // manage lock state in memory
        // when do we need to prompt?
        let mut locked: Vec<OwnedObjectPath> = Vec::new();

        for object in objects {
            for collection in self.collections.read().await.iter() {
                if collection.path() == *object && !collection.locked() {
                    collection.set_locked(true).await;
                    locked.push(object.clone());
                }
            }
        }

        if locked.is_empty() {
            locked.push(OwnedObjectPath::default());
        }

        let prompt = Prompt::default(); // temporarily

        Ok((locked, prompt))
    }

    pub async fn get_secrets(
        &self,
        paths: Vec<OwnedObjectPath>,
        session: ObjectPath<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretInner>> {
        let mut secrets = HashMap::with_capacity(paths.len());
        for collection in self.collections.read().await.iter() {
            let items = collection.items.read().await;
            for item in items.iter() {
                for path in paths.iter() {
                    if item.path() == path.as_ref() {
                        let secret = item.secret(session.clone()).await?;
                        secrets.insert(path.to_owned(), secret);
                    }
                }
            }
        }
        Ok(secrets)
    }

    pub fn read_alias(&self, name: &str) -> ObjectPath {
        self.collections
            .iter()
            .find_map(|c| {
                if c.label() == name {
                    Some(c.path())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    pub fn set_alias(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        alias: &str,
        path: ObjectPath<'_>,
    ) -> Result<()> {
        match self.collections.iter().find(|c| c.path() == path) {
            Some(collection) => {
                collection.set_alias(&ctxt, alias).await?;
                Ok(())
            }
            None => {
                tracing::error!("Collection {path} not found");
                Err(ServiceError::NoSuchObject)
            }
        }
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<ObjectPath> {
        self.collections
            .read()
            .await
            .iter()
            .map(|collection| collection.path())
            .collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(
        ctxt: &SignalContext<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_deleted(
        ctxt: &SignalContext<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_changed(
        ctxt: &SignalContext<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Service {
    pub async fn new() -> Self {
        Self {
            collections: RwLock::new(Vec::new()),
            keyring: Arc::new(Keyring::load_default().await.unwrap()),
            cnx: Default::default(),
        }
    }

    pub async fn run(self) -> Result<()> {
        let cnx = zbus::connection::Builder::session()?
            //.name(oo7::dbus::api::Service::DESTINATION.unwrap())?
            .name("org.freedesktop.secrets.Devel")?
            .build()
            .await?;
        *self.cnx.lock().unwrap() = Some(cnx.clone());
        cnx.object_server()
            .at(oo7::dbus::api::Service::PATH.unwrap(), self)
            .await?;
        Ok(())
    }
}
