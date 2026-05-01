//! Outbound webhooks.
//!
//! - Each workspace can register webhook URLs subscribing to a list of event
//!   types. Events come from handlers (e.g. `secret.write`).
//! - When an event fires, [`dispatcher::fire`] inserts a `pending` row into
//!   `webhook_deliveries` for every matching webhook.
//! - A background [`worker`] polls pending rows, POSTs the payload with an
//!   HMAC-SHA256 signature, and either marks them `success` or schedules a
//!   retry with exponential backoff.
//! - Deliveries that exceed 24 hours of retries become `dead-letter`.

pub mod api;
pub mod dispatcher;
pub mod worker;

pub use api::configure;
