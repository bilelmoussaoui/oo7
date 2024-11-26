// Secret Service Manager

use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::session::Session;

#[derive(Debug)]
pub struct ServiceManager {
    connection: zbus::Connection,
    // sessions mapped to their corresponding object path on the bus
    sessions: HashMap<OwnedObjectPath, Arc<Session>>,
    session_index: Arc<RwLock<u32>>,
}

impl ServiceManager {
    pub fn new(connection: zbus::Connection) -> Self {
        Self {
            sessions: Default::default(),
            session_index: Default::default(),
            connection,
        }
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection.object_server()
    }

    pub fn session(&self, path: &OwnedObjectPath) -> Option<Arc<Session>> {
        self.sessions.get(path).map(Arc::clone)
    }

    pub fn insert_session(&mut self, path: OwnedObjectPath, session: Arc<Session>) {
        self.sessions.insert(path, session);
    }

    pub fn remove_session(&mut self, path: &OwnedObjectPath) {
        self.sessions.remove(path);
    }

    pub fn signal_emitter<'a, P>(
        &self,
        path: P,
    ) -> Result<zbus::object_server::SignalEmitter<'a>, oo7::dbus::ServiceError>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let signal_emitter = zbus::object_server::SignalEmitter::new(&self.connection, path)?;

        Ok(signal_emitter)
    }

    pub async fn session_index(&self) -> u32 {
        let n_sessions = *self.session_index.read().await + 1;
        *self.session_index.write().await = n_sessions;

        n_sessions
    }
}
