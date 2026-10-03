const std = @import("std");
const fake_ip = @import("fake_ip.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();

    _ = try dns.allocate("example.com");
}
