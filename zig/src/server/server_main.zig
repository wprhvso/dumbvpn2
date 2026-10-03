const std = @import("std");
const ws = @import("ws_listener.zig");
const router = @import("stream_router.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var r = router.StreamRouter.init(allocator);
    defer r.deinit();

    const address = try std.net.Address.parseIp4("127.0.0.1", 4000);
    var server = try address.listen(.{ .reuse_port = true });
    defer server.deinit();

    while (true) {
        const conn = try server.accept();
        conn.stream.close();
        break;
    }
}
