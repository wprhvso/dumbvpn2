const std = @import("std");
const fake_ip = @import("fake_ip.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();

    std.log.info("mesh-client started", .{});

    const ip = try dns.allocate("example.com");
    std.log.info("Allocated fake IP 0x{x} for example.com", .{ip});

    if (dns.lookup(ip)) |domain| {
        std.log.info("Reverse lookup 0x{x} -> {s}", .{ ip, domain });
    }
}
