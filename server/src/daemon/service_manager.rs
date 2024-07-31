use std::{collections::HashMap, sync::RwLock};

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::{collection::Collection, session::Session};

#[derive(Debug, Default)]
pub struct ServiceManager {
    sessions: HashMap<OwnedObjectPath, Session>,
    collections: HashMap<String, Collection>,
    collections_to_unlock: Vec<OwnedObjectPath>,
    unlock_request_sender: RwLock<String>,
    unlock_prompt_path: RwLock<OwnedObjectPath>,
    prompts_counter: RwLock<i32>,
    secret_exchange_public_key: RwLock<String>,
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

    pub fn collection(&self, label: &str) -> Collection {
        self.collections.get(label).unwrap().to_owned()
    }

    pub fn insert_collection(&mut self, label: &str, collection: Collection) {
        self.collections.insert(label.to_string(), collection);
    }

    pub fn remove_collection(&mut self, label: &str) {
        self.collections.remove(label);
    }

    pub fn collections_to_unlock(&self) -> Vec<OwnedObjectPath> {
        self.collections_to_unlock.clone()
    }

    pub fn unlock_request_sender(&self) -> String {
        (*self.unlock_request_sender.read().unwrap()).to_owned()
    }

    pub fn set_collections_to_unlock(&mut self, collections: Vec<OwnedObjectPath>, sender: &str) {
        for collection in collections {
            self.collections_to_unlock.push(collection);
        }

        *self.unlock_request_sender.write().unwrap() = sender.to_owned();
    }

    pub fn reset_collections_to_unlock(&mut self) {
        self.collections_to_unlock.clear();
    }

    pub fn unlock_prompt_path(&self) -> OwnedObjectPath {
        self.unlock_prompt_path.read().unwrap().clone()
    }

    pub fn set_unlock_prompt_path(&self, path: ObjectPath<'_>) {
        *self.unlock_prompt_path.write().unwrap() = path.into();
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

    pub fn secret_exchange_public_key(&self) -> String {
        (*self.secret_exchange_public_key.read().unwrap()).to_owned()
    }

    pub fn set_secret_exchange_public_key(&mut self, pub_key: &str) {
        *self.secret_exchange_public_key.write().unwrap() = pub_key.to_string()
    }

    pub fn prompt_dismissed(&self) -> bool {
        self.prompt_dismissed
    }

    pub fn set_prompt_dismissed(&mut self, dismissed: bool) {
        self.prompt_dismissed = dismissed;
    }
}
