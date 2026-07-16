# Library

If your program needs registry metadata, the library keeps process setup and ownership in your hands. You provide the allocator, `std.http.Client`, configuration, and parsed reference.

## Quick start

This example calls a live registry with anonymous access. `Config{}` does not read process credentials; inject credential sources when the registry requires them.

```zig
const std = @import("std");
const z_oci = @import("z_oci");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var client = std.http.Client{
        .allocator = allocator,
        .io = init.io,
    };
    defer client.deinit();

    var reference = try z_oci.Reference.parse(allocator, "ubuntu:22.04");
    const outcome = blk: {
        errdefer reference.deinit(allocator);
        break :blk try z_oci.resolve(
            allocator,
            &client,
            z_oci.Config{},
            reference,
            .{ .os = "linux", .architecture = "amd64" },
        );
    };

    switch (outcome) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            std.debug.print("resolved: {f}\n", .{owned.digest});
        },
        .failure => |failure| {
            std.debug.print("resolve failed: {f}\n", .{failure});
            z_oci.deinitResolveFailure(failure, allocator);
            reference.deinit(allocator);
            return error.ResolveFailed;
        },
    }
}
```

The `resolve` call returns a verified digest-pinned `ResolveResult`. On success it moves the reference fields into that result, so do not call `reference.deinit` on that path. On failure, release the failure and then release the input reference as shown.

## Choose an operation

- `Reference.parse` parses and normalizes a Docker or OCI image reference.
- `resolve` fetches and verifies a manifest, returning an owned digest-pinned result. A multi-arch reference requires a `Platform` to select a leaf manifest.
- `validate` checks an exact digest reference without returning a manifest. It returns `.valid`, `.not_found`, or a failure. A multi-arch digest requires a platform selection.
- `getManifest` returns the parsed manifest document. The successful `std.json.Parsed(Manifest)` value owns a JSON arena and must be released with `parsed.deinit()`.
- `inspect` returns the top-level manifest or index and, when a platform is supplied for an index, an optional selected leaf. Release a successful result with `InspectionResult.deinit()`.
- `resolveMany` resolves references sequentially with one HTTP client and auth session. Its platform option applies to the whole batch, and its result owns every success and failure item.
- `pingRegistry` probes `https://<registry>/v2/` without fetching a manifest. It reports anonymous reachability, an authentication-required response, or a classified failure; it is independent of `resolve`.

## Ownership and lifetime

The allocator passed to a public call owns the returned result or failure data:

- Call `ResolveResult.deinit(allocator)` for a successful `resolve` result.
- Call `z_oci.deinitResolveFailure(failure, allocator)` for a single-call failure from `resolve`, `validate`, `getManifest`, or `inspect`.
- Call `parsed.deinit()` for a successful `getManifest` result.
- Call `InspectionResult.deinit()` for a successful `inspect` result.
- Call `ResolveManyResult.deinit(allocator)` once for a `resolveMany` result. Do not use `deinitResolveFailure` on a batch item failure.

The HTTP client remains caller-owned. Keep it alive through the operation and release it after the returned value has been released. `Reference.parse` also returns caller-owned storage; release it on paths where `resolve` did not move it into a successful result.

Configuration slices and injected credential-source views are borrowed for the call. Keep their backing storage alive until the operation returns. See [Credentials](Credentials.md) for the supported sources and precedence.

## Deterministic tests

The `z_oci.testing` namespace exposes injected token and manifest exchangers for tests that should not contact a registry. [`examples/resolve-many.zig`](../examples/resolve-many.zig) demonstrates the batch seam with checked-in fixture data, while [`examples/resolve-reference.zig`](../examples/resolve-reference.zig) shows the live public path.

## Next steps

- [Installation](Installation.md) covers dependency and checkout builds.
- [CLI](CLI.md) documents the command-line path.
- [Examples](Examples.md) separates offline fixtures from live registry access.
- [Platform and limits](Platform.md) documents platform matching, HTTPS boundaries, and configuration limits.
