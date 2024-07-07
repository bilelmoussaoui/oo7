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
    collections: Vec<OwnedObjectPath>,
    prompts_counter: RwLock<i32>,
    secret_exchange_aes_key: RwLock<String>,
    prompt_dismissed: bool,
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

    pub fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections.clone()
    }

    pub fn insert_collection(&mut self, paths: Vec<OwnedObjectPath>) {
        for path in paths {
            self.collections.push(path);
        }
    }

    pub fn prompts_counter(&self) -> i32 {
        *self.prompts_counter.read().unwrap()
    }

    pub fn update_prompts_counter(&mut self) -> i32 {
        *self.prompts_counter.write().unwrap() += 1;
        *self.prompts_counter.read().unwrap()
    }

    pub fn secret_exchange_aes_key(&self) -> String {
        (*self.secret_exchange_aes_key.read().unwrap()).to_owned()
    }

    pub fn set_secret_exchange_aes_key(&mut self, aes_key: &str) {
        *self.secret_exchange_aes_key.write().unwrap() = aes_key.to_string()
    }

    pub fn prompt_dismissed(&self) -> bool {
        self.prompt_dismissed
    }

    pub fn set_prompt_dismissed(&mut self, dismissed: bool) {
        self.prompt_dismissed = dismissed;
    }
}
