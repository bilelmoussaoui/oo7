//  org.freedesktop.Secret.Service

use std::{
    collections::HashMap,
    env, fs,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use oo7::{
    dbus::{
        api::{Properties, SecretInner},
        Algorithm,
    },
    portal::{Item, Keyring, Secret},
    Key,
};
use tokio::sync::RwLock;
use zbus::{
    proxy::ProxyDefault,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
    ObjectServer, SignalContext,
};

use super::{
    collection::Collection, error::ServiceError, prompt::Prompt, service_manager::ServiceManager,
    session::Session, Result,
};
#[cfg(debug_assertions)]
use crate::SERVICE_NAME;
use crate::{LOGIN_KEYRING, LOGIN_KEYRING_PATH};

#[derive(Clone, Debug)]
pub struct Service {
    collections: Arc<RwLock<Vec<Collection>>>,
    keyring: Arc<Keyring>,
    cnx: Arc<Mutex<Option<zbus::Connection>>>,
    manager: Arc<Mutex<ServiceManager>>,
    sessions_counter: Arc<RwLock<i32>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let (service_public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted => {
                let private_key = Key::generate_private_key();
                let client_public_key = Key::from(input);
                (
                    Some(Key::generate_public_key(&private_key)),
                    Some(Key::generate_aes_key(&private_key, &client_public_key)),
                )
            }
        };

        *self.sessions_counter.write().await += 1;
        let session = Session::new(
            aes_key,
            Arc::clone(&self.manager),
            *self.sessions_counter.read().await,
        );
        self.manager
            .lock()
            .unwrap()
            .insert_session(session.path().to_owned(), session.to_owned());

        object_server
            .at(session.path().to_owned(), session.to_owned())
            .await?;
        tracing::info!("Session created: {}", session.path());

        let key = service_public_key
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
    ) -> Result<(OwnedObjectPath, ObjectPath)> {
        let collection = Collection::new(
            properties.label(),
            alias,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            Arc::clone(&self.keyring),
            Arc::clone(&self.manager),
        );

        self.collections.write().await.push(collection.clone());
        self.manager
            .lock()
            .unwrap()
            .insert_collection(collection.label(), collection.clone());

        let path = OwnedObjectPath::from(collection.path());
        object_server.at(&path, collection).await?;
        tracing::info!("Collection: created: {}", path);

        // perform prompt
        let prompt = Prompt::for_new_collection(Arc::clone(&self.manager));
        object_server
            .at(prompt.path().to_owned(), prompt.to_owned())
            .await?;

        // signal
        Self::collection_created(&ctxt, path.as_ref())
            .await
            .map_err::<ServiceError, _>(From::from)?;

        Ok((path, prompt.path().to_owned()))
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
                locked.push(item)
            } else {
                unlocked.push(item)
            }
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(Vec<ObjectPath>, ObjectPath)> {
        // to store objectpaths that were unlocked without a prompt.
        let mut unlocked: Vec<ObjectPath> = Vec::new();

        // to send objects to unlock information to the Prompter
        self.manager
            .lock()
            .unwrap()
            .set_collections_to_unlock(objects.clone());

        // todo: set ObjectPath dynamically
        let interface_ref = object_server
            .interface::<_, Collection>(
                OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login").unwrap(),
            )
            .await
            .unwrap();
        let interface = interface_ref.get_mut().await;

        // if the collection is alreday in unlocked state update unlocked
        if !interface.locked() {
            for object in objects {
                unlocked.push(object.into_inner());
            }
            return Ok((unlocked, ObjectPath::default()));
        }

        // perform prompt
        let prompt = Prompt::for_unlock(Arc::clone(&self.manager));
        object_server
            .at(prompt.path().to_owned(), prompt.to_owned())
            .await?;

        Ok((unlocked, prompt.path().to_owned()))
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath)> {
        // to store objectpaths that were locked without a prompt
        let mut locked: Vec<OwnedObjectPath> = Vec::new();

        // sets lock state in memory
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

        // gnome-keyring-daemon returns an empty objectpath: '/' here
        let prompt = ObjectPath::default();

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

    pub async fn read_alias(&self, name: &str) -> ObjectPath {
        self.collections
            .read()
            .await
            .iter()
            .find_map(|c| {
                if c.label() == name {
                    Some(c.path().to_owned())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    pub async fn set_alias(
        &self,
        alias: &str,
        path: ObjectPath<'_>,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<()> {
        match self
            .collections
            .read()
            .await
            .iter()
            .find(|c| c.path() == path)
        {
            Some(collection) => {
                if alias != "default" {
                    return Err(ServiceError::ZBus(zbus::Error::Failure(String::from(
                        "Only the 'default' alias is supported",
                    ))));
                }

                collection.set_alias(alias).await;

                let interface_ref = object_server
                    .interface::<_, Collection>(collection.path())
                    .await
                    .unwrap();
                let interface = interface_ref.get_mut().await;

                interface.set_alias(alias).await;
                interface
                    .alias_changed(interface_ref.signal_context())
                    .await
                    .unwrap();

                let _ = Service::collection_changed(&ctxt, collection.path()).await;

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
            .map(|collection| collection.path().to_owned())
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
    pub async fn new(password: Vec<u8>) -> Self {
        if password.is_empty() {
            panic!("Login password can't be empty");
        }

        Self {
            collections: Arc::new(RwLock::new(Vec::new())),
            keyring: Arc::new(
                match Keyring::open(LOGIN_KEYRING, Secret::from(password)).await {
                    Ok(keyring) => keyring,
                    Err(err) => panic!("Failed to unlock login keyring, wrong password: {}", err),
                },
            ),
            cnx: Default::default(),
            manager: Arc::new(Mutex::new(ServiceManager::default())),
            sessions_counter: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn run(self) -> Result<()> {
        #[cfg(debug_assertions)]
        let service_name = SERVICE_NAME;
        #[cfg(not(debug_assertions))]
        let service_name = oo7::dbus::api::Service::DESTINATION.unwrap();
        let cnx = zbus::connection::Builder::session()?
            .name(service_name)?
            .build()
            .await?;
        *self.cnx.lock().unwrap() = Some(cnx.clone());
        let object_server = cnx.object_server();
        object_server
            .at(oo7::dbus::api::Service::PATH.unwrap(), self.clone())
            .await?;

        // loading login.keyring into the objects tree
        Service::init_login(&object_server, self).await;

        Ok(())
    }

    pub async fn init_login(object_server: &ObjectServer, service: Service) {
        let path = format!("{}/{}", env::var("HOME").unwrap(), LOGIN_KEYRING_PATH);
        let created = fs::metadata(path)
            .unwrap()
            .created()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let login = Collection::new(
            LOGIN_KEYRING,
            "login",
            created,
            service.keyring.clone(),
            service.manager.clone(),
        );

        service.collections.write().await.push(login.clone());
        service
            .manager
            .lock()
            .unwrap()
            .insert_collection(login.label(), login.clone());

        let path = OwnedObjectPath::from(login.path());
        object_server.at(&path, login).await.unwrap();
    }
}
