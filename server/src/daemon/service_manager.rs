use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use oo7::Key;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::session::Session;

#[derive(Debug, Default)]
pub struct ServiceManager {
    sessions: HashMap<OwnedObjectPath, Session>,
    prompts_counter: RwLock<i32>,
    oo7_exchange_aes: RwLock<String>,
}

impl ServiceManager {
    pub fn session(&self, path: ObjectPath<'_>) -> Option<Session> {
        self.sessions.get(&path.into()).to_owned().cloned()
    }

    pub fn insert_session(&mut self, path: ObjectPath<'_>, session: Session) {
        self.sessions.insert(path.into(), session);
    }

    pub fn remove_session(&mut self, path: ObjectPath<'_>) {
        self.sessions.remove(&path.into());
    }

    pub fn prompts_counter(&self) -> i32 {
        *self.prompts_counter.read().unwrap()
    }

    pub fn update_prompts_counter(&mut self) -> i32 {
        *self.prompts_counter.write().unwrap() += 1;
        *self.prompts_counter.read().unwrap()
    }

    pub fn oo7_exchange_aes(&self) -> String {
        (*self.oo7_exchange_aes.read().unwrap()).to_owned()
    }

    pub fn set_oo7_exchange_aes(&mut self, oo7_exchange_aes: &str) {
        *self.oo7_exchange_aes.write().unwrap() = oo7_exchange_aes.to_string()
    }
}
