//! Thin wrapper around the `keyring` crate so the rest of the CLI doesn't
//! deal with platform-specific quirks.

use anyhow::{Context, Result};
use keyring::Entry;

pub fn store(service: &str, account: &str, secret: &str) -> Result<()> {
    let entry = Entry::new(service, account).context("open keyring entry")?;
    entry.set_password(secret).context("write to OS keyring")?;
    Ok(())
}

pub fn load(service: &str, account: &str) -> Result<String> {
    let entry = Entry::new(service, account).context("open keyring entry")?;
    entry.get_password().context("read from OS keyring")
}

pub fn remove(service: &str, account: &str) -> Result<()> {
    let entry = Entry::new(service, account).context("open keyring entry")?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("remove keyring entry"),
    }
}
