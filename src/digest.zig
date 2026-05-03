//! Digest validation: SHA256 hash verification against Docker-Content-Digest header.
//!
//!   On HEAD: trust the header (fast path).
//!   On GET:  stream body through `std.crypto.hash.sha2.Sha256`, compare against header.
//!            Constant memory (4 KB buffer), catches MITM / CDN poisoning / registry bugs.
//!
//!   Parse "algorithm:hex" strings with extensible algorithm enum (SHA256 in v1).
