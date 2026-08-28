//! Minimal lib surface shared between the `authnz-rs` server binary and the
//! `seed-test-user` helper binary (used by the DynamoDB Local integration
//! test, `tests/agent_flow.rs`).
//!
//! Only modules with no dependency on the server's `AppState` are exported
//! here. `db`, `agent`, and the other handler modules stay bin-local (`mod`
//! declarations in `src/main.rs`) because they're deeply coupled to
//! `main.rs`-only items (`AppState`, `crate::patreon`, `crate::device_check`,
//! ...) and pulling them into this crate would drag that coupling along.

pub mod constants;
pub mod cwt;
pub mod keys;
