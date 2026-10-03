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

    std.log.info("mesh-server listening on 127.0.0.1:4000", .{});

    while (true) {
        var conn = server.accept() catch |err| {
            if (err == error.ProcessFdQuotaExceeded or err == error.SystemFdQuotaExceeded) {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            break;
        };
        defer conn.stream.close();

        var buf: [2048]u8 = undefined;
        const read_len = conn.stream.read(&buf) catch continue;
        if (read_len == 0) continue;
        const req = buf[0..read_len];

        var req_path: []const u8 = "/";
        var lines_iter = std.mem.splitScalar(u8, req, '\r');
        if (lines_iter.next()) |first_line| {
            var parts_iter = std.mem.splitScalar(u8, first_line, ' ');
            _ = parts_iter.next();
            if (parts_iter.next()) |p| {
                req_path = p;
            }
        }

        if (std.mem.eql(u8, req_path, "/api/v1/health")) {
            const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
            _ = conn.stream.writeAll(resp) catch {};
        } else if (embedded_ui.serveStatic(req_path)) |file| {
            var header_buf: [256]u8 = undefined;
            const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{ file.content_type, file.data.len }) catch continue;
            _ = conn.stream.writeAll(header) catch {};
            _ = conn.stream.writeAll(file.data) catch {};
        } else {
            const not_found = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            _ = conn.stream.writeAll(not_found) catch {};
        }
    }
}
