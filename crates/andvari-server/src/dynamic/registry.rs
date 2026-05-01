//! Process-wide registry mapping engine names → impls.
//!
//! Engines self-register at boot from environment variables; the registry
//! is then handed to handlers via [`AppState::engines`].

use std::collections::HashMap;
use std::sync::Arc;

use andvari_core::dynamic::DynamicEngine;

#[derive(Default, Clone)]
pub struct EngineRegistry {
    inner: Arc<HashMap<String, Arc<dyn DynamicEngine>>>,
}

impl EngineRegistry {
    pub fn from_engines(engines: Vec<Arc<dyn DynamicEngine>>) -> Self {
        let mut map: HashMap<String, Arc<dyn DynamicEngine>> = HashMap::new();
        for e in engines {
            map.insert(e.name().to_string(), e);
        }
        Self {
            inner: Arc::new(map),
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn DynamicEngine>> {
        self.inner.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }
}
