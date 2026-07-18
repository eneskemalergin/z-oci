const std = @import("std");
const z_oci = @import("z_oci");

test "consumer can import and use the public module" {
    var reference = try z_oci.Reference.parse(std.testing.allocator, "ubuntu:24.04");
    defer reference.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("registry-1.docker.io", reference.registry);
    try std.testing.expectEqualStrings("library/ubuntu", reference.repository);
    try std.testing.expectEqualStrings("24.04", reference.refString());
}
