//! Rate limiter: registry rate-limit headers and backoff.
//!
//! ## Backoff Strategy
//!
//!   Reactive by default: handle 429 with exponential backoff + jitter.
//!   Pre-emptive (opt-in): pause before RateLimit-Remaining hits zero.
//!     Off by default - many registries send headers intermittently.
//!
//! ## Headers Parsed
//!
//!   RateLimit-*       (Docker Hub pull limits)
//!   X-RateLimit-*     (API limits)
//!   Retry-After       - seconds, HTTP-date, and Docker Hub Unix timestamp bug
//!
//! ## Configuration
//!
//!   max_retries       - configurable retry count (separate for rate-limit vs network)
//!   connect timeout   - per-request connect deadline
//!   read timeout      - per-request read deadline
