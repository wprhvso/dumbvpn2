const std = @import("std");
const ws = @import("ws_listener.zig");
const router = @import("stream_router.zig");
const embedded_ui = @import("embedded_ui.zig");
const common = @import("common");
const protocol = common.protocol;

fn handleConnection(conn: std.net.Server.Connection) void {
    defer conn.stream.close();

    var buf: [4096]u8 = undefined;
    while (true) {
        const read_len = conn.stream.read(&buf) catch break;
        if (read_len == 0) break;
        const data = buf[0..read_len];

        if (std.mem.startsWith(u8, data, "GET /api/v1/health")) {
            const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
            _ = conn.stream.writeAll(resp) catch {};
            break;
        } else if (std.mem.startsWith(u8, data, "GET / HTTP/1.1") or std.mem.startsWith(u8, data, "GET /index.html")) {
            const html = embedded_ui.index_html;
            var header_buf: [256]u8 = undefined;
            const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{html.len}) catch break;
            _ = conn.stream.writeAll(header) catch {};
            _ = conn.stream.writeAll(html) catch {};
            break;
        } else if (std.mem.startsWith(u8, data, "GET /assets/index.js")) {
            const js = embedded_ui.index_js;
            var header_buf: [256]u8 = undefined;
            const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{js.len}) catch break;
            _ = conn.stream.writeAll(header) catch {};
            _ = conn.stream.writeAll(js) catch {};
            break;
        } else if (std.mem.indexOf(u8, data, "Upgrade: websocket") != null or std.mem.startsWith(u8, data, "GET /api/v2/stream")) {
            const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
            _ = conn.stream.writeAll(resp) catch break;

            while (true) {
                const ws_read_len = conn.stream.read(&buf) catch break;
                if (ws_read_len == 0) break;
                const pong_frame = [_]u8{ 0x82, 0x08, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00 };
                _ = conn.stream.writeAll(&pong_frame) catch break;
            }
            break;
        } else if (data.len >= 8) {
            const hdr = protocol.Header.decode(data[0..8]);
            if (hdr.frame_type == .ping) {
                const pong_hdr = protocol.Header{
                    .stream_id = hdr.stream_id,
                    .frame_type = .pong,
                    .flags = 0,
                    .length = 0,
                };
                var pong_buf: [8]u8 = undefined;
                pong_hdr.encode(&pong_buf);
                _ = conn.stream.writeAll(&pong_buf) catch break;
            }
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    var listen_port: u16 = 4000;

    _ = args_iter.next();
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args_iter.next()) |val| {
                listen_port = try std.fmt.parseInt(u16, val, 10);
            }
        }
    }

    const address = try std.net.Address.parseIp4("0.0.0.0", listen_port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.log.info("mesh-server listening on 0.0.0.0:{d}", .{listen_port});

    while (true) {
        const conn = server.accept() catch |err| {
            if (err == error.ProcessFdQuotaExceeded or err == error.SystemFdQuotaExceeded) {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            break;
        };

        const thread = std.Thread.spawn(.{}, handleConnection, .{conn}) catch {
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}
