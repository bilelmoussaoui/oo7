use std::collections::HashMap;

use tokio::sync::RwLock;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::session::Session;

#[derive(Debug)]
pub struct ServiceManager {
    sessions: RwLock<HashMap<OwnedObjectPath, Session>>,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn session(&self, path: ObjectPath<'_>) -> Option<&Session> {
        self.sessions.read().await.get(&path.into())
    }

    pub async fn insert_session(&mut self, path: OwnedObjectPath, session: Session) {
        self.sessions.write().await.insert(path, session);
    }
}
