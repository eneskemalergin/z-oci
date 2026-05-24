//! Current `z-oci` executable entrypoint.
//!
//! The default build still installs a `z-oci` binary so the package keeps a
//! stable executable shape while the library surface matures, but the real
//! user-facing CLI commands are still deferred to the later CLI phase.
//!
//! Today the packaged examples provide the practical command-line entrypoints
//! for live resolver and offline fixture workflows.

// Intentionally empty scaffold until the real CLI phase lands.
pub fn main() void {}
