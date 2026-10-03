const std = @import("std");
const ws = @import("ws_listener.zig");
const router = @import("stream_router.zig");
const embedded_ui = @import("embedded_ui.zig");
const common = @import("common");
const protocol = common.protocol;

fn pump(src: std.net.Stream, dst: std.net.Stream) void {
    var buf: [16384]u8 = undefined;
    while (true) {
        const len = src.read(&buf) catch break;
        if (len == 0) break;
        dst.writeAll(buf[0..len]) catch break;
    }
}

fn handleConnection(allocator: std.mem.Allocator, conn: std.net.Server.Connection) void {
    defer conn.stream.close();

    var buf: [4096]u8 = undefined;
    const read_len = conn.stream.read(&buf) catch return;
    if (read_len == 0) return;
    const data = buf[0..read_len];

    if (std.mem.startsWith(u8, data, "GET /api/v1/health")) {
        const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        _ = conn.stream.writeAll(resp) catch {};
        return;
    } else if (std.mem.startsWith(u8, data, "GET / HTTP/1.1") or std.mem.startsWith(u8, data, "GET /index.html")) {
        const html = embedded_ui.index_html;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{html.len}) catch return;
        _ = conn.stream.writeAll(header) catch {};
        _ = conn.stream.writeAll(html) catch {};
        return;
    } else if (std.mem.startsWith(u8, data, "GET /assets/index.js")) {
        const js = embedded_ui.index_js;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{js.len}) catch return;
        _ = conn.stream.writeAll(header) catch {};
        _ = conn.stream.writeAll(js) catch {};
        return;
    } else if (std.mem.indexOf(u8, data, "Upgrade: websocket") != null or std.mem.startsWith(u8, data, "GET /api/v2/stream")) {
        const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        _ = conn.stream.writeAll(resp) catch return;

        var stream_buf: [4096]u8 = undefined;
        while (true) {
            const n = conn.stream.read(&stream_buf) catch break;
            if (n == 0) break;
            const payload = stream_buf[0..n];

            if (payload.len >= 8) {
                const hdr = protocol.Header.decode(payload[0..8]);
                if (hdr.frame_type == .ping) {
                    const pong_frame = [_]u8{ 0x82, 0x08, 0, 0, 0, 0, 0x06, 0, 0, 0 };
                    _ = conn.stream.writeAll(&pong_frame) catch break;
                } else if (hdr.frame_type == .connect and payload.len >= 12) {
                    const addr_type = payload[8];
                    var target_port: u16 = 80;
                    var target_host: []const u8 = "";

                    if (addr_type == 0x02) {
                        const domain_len = payload[9];
                        if (payload.len >= 10 + domain_len + 2) {
                            target_host = payload[10 .. 10 + domain_len];
                            target_port = std.mem.readInt(u16, payload[10 + domain_len ..][0..2], .big);
                        }
                    }

                    if (target_host.len > 0) {
                        std.log.info("Proxying CONNECT to {s}:{d}...", .{ target_host, target_port });
                        const target_stream = std.net.tcpConnectToHost(allocator, target_host, target_port) catch |err| {
                            std.log.warn("Failed to connect to target {s}:{d}: {any}", .{ target_host, target_port, err });
                            break;
                        };
                        defer target_stream.close();

                        _ = conn.stream.writeAll(&[_]u8{ 0x82, 0x08, 0, 0, 0, 1, 0x01, 0, 0, 0 }) catch break;

                        const t1 = std.Thread.spawn(.{}, pump, .{ conn.stream, target_stream }) catch break;
                        t1.detach();
                        pump(target_stream, conn.stream);
                        break;
                    }
                }
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

        const thread = std.Thread.spawn(.{}, handleConnection, .{ allocator, conn }) catch {
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}
