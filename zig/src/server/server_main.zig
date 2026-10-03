const std = @import("std");
const ws = @import("ws_listener.zig");
const router = @import("stream_router.zig");
const embedded_ui = @import("embedded_ui.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var r = router.StreamRouter.init(allocator);
    defer r.deinit();

    const address = try std.net.Address.parseIp4("127.0.0.1", 4000);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    _ = embedded_ui.serveStatic("/");
}
