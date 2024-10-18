// Secret Service Manager

use std::{collections::HashMap, sync::Arc};

use zbus::zvariant::OwnedObjectPath;

use crate::session::Session;

#[derive(Debug, Default)]
pub struct ServiceManager {
    // sessions mapped to their corresponding object path on the bus
    sessions: HashMap<OwnedObjectPath, Arc<Session>>,
}

impl ServiceManager {
    pub fn insert_session(&mut self, path: OwnedObjectPath, session: Arc<Session>) {
        self.sessions.insert(path, session);
    }

    pub fn remove_session(&mut self, path: &OwnedObjectPath) {
        self.sessions.remove(path);
    }
}
