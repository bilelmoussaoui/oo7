// Secret Service Manager

use std::{collections::HashMap, sync::Arc};

use zbus::zvariant::OwnedObjectPath;

use crate::session::Session;

#[derive(Debug)]
pub struct ServiceManager {
    connection: zbus::Connection,
    // sessions mapped to their corresponding object path on the bus
    sessions: HashMap<OwnedObjectPath, Arc<Session>>,
}

impl ServiceManager {
    pub fn new(connection: zbus::Connection) -> Self {
        Self {
            sessions: Default::default(),
            connection,
        }
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection.object_server()
    }

    pub fn n_sessions(&self) -> usize {
        self.sessions.len()
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
}
