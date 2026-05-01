//! Dynamic secrets engines + lease persistence + REST API.
//!
//! Postgres engine ships in this slice; MySQL / AWS-STS / SSH-OTP land in
//! the follow-up slice and slot into the same registry.

pub mod api;
pub mod aws_sts;
pub mod mysql;
pub mod postgres;
pub mod registry;
pub mod ssh_otp;

pub use registry::EngineRegistry;
