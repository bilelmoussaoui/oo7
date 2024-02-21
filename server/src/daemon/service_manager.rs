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

    pub async fn session(&self, path: ObjectPath<'_>) -> Option<Session> {
        self.sessions
            .read()
            .await
            .get(&path.into())
            .to_owned()
            .cloned()
    }

    pub async fn insert_session(&mut self, path: ObjectPath<'_>, session: Session) {
        self.sessions.write().await.insert(path.into(), session);
    }

    pub async fn remove_session(&mut self, path: ObjectPath<'_>) {
        self.sessions.write().await.remove(&path.into());
    }
}
