const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const fake_ip = @import("fake_ip.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();

    const ip = try dns.allocate("example.com");
    _ = ip;

    var buf: [8]u8 = undefined;
    const hdr = protocol.Header{
        .stream_id = 1,
        .frame_type = .connect,
        .flags = 0,
        .length = 0,
    };
    hdr.encode(&buf);
}
