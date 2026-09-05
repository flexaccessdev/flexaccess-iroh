//! Shared iroh transport layer for FlexAccess applications.
//!
//! The programs built on iroh in this org (tunnel-rs, ezvpn, flextunnel) share
//! one transport foundation, documented once in
//! <https://github.com/flexaccessdev/iroh-common-architecture>. This crate is
//! that foundation as code, so a fix lands once instead of being ported by hand
//! across repos:
//!
//! - [`relay`]: the default-vs-custom [`relay::RelayConfig`] (which also decides
//!   where address lookup happens), the shared relay auth token, and the
//!   strict per-relay startup probe.
//! - [`lookup`]: the self-hosted address lookup service that custom relays
//!   require — the `lks1-` secret format and the `lookup_url` /
//!   `lookup_secret` pair.
//! - [`endpoint`]: the common endpoint builder, the bind-and-come-online policy
//!   for first creation versus a mid-run rebuild (including the foreground
//!   first publish to the lookup service), and a
//!   [`endpoint::RebuildableEndpoint`] handle.
//! - [`auth`]: the endpoint-bound public-key authentication transcript over the
//!   shared [`flexaccess_keys`] format; each application supplies its own
//!   domain-separation context.
//!
//! Everything product-specific — ALPNs, handshake wire formats, QUIC transport
//! tuning, connection-path status UIs — stays in the application.
//!
//! # iroh version
//!
//! `iroh` is required as a range (`>=1.1.0, <1.2.0`), never an exact pin, so
//! each consumer resolves the single `iroh` its own workspace locks and this
//! crate compiles against that. A consumer on a fork of iroh redirects this
//! crate's dependency to the fork as well with a `[patch.crates-io]` entry in
//! its root manifest; see the README.

pub mod auth;
pub mod endpoint;
pub mod lookup;
pub mod relay;

pub use flexaccess_keys;
