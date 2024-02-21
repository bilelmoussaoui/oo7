use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::session::Session;

#[derive(Debug)]
pub struct ServiceManager {
    sessions: HashMap<OwnedObjectPath, Session>,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn session(&self, path: ObjectPath<'_>) -> Option<Session> {
        self.sessions.get(&path.into()).to_owned().cloned()
    }

    pub fn insert_session(&mut self, path: ObjectPath<'_>, session: Session) {
        self.sessions.insert(path.into(), session);
    }

    pub fn remove_session(&mut self, path: ObjectPath<'_>) {
        self.sessions.remove(&path.into());
    }
}
