const std = @import("std");
const embedded_ui = @import("embedded_ui.zig");
const common = @import("common");
const protocol = common.protocol;

const UpstreamSession = struct {
    stream_id: u32,
    target_stream: std.net.Stream,
    target_host: [256]u8,
    target_host_len: usize,
    target_port: u16,
    active: std.atomic.Value(bool),
    ref_count: std.atomic.Value(usize),

    pub fn getHost(self: *const UpstreamSession) []const u8 {
        return self.target_host[0..self.target_host_len];
    }

    pub fn release(self: *UpstreamSession, allocator: std.mem.Allocator) void {
        if (self.ref_count.fetchSub(1, .seq_cst) == 1) {
            self.target_stream.close();
            allocator.destroy(self);
        }
    }
};

fn writeTunnelFrame(
    conn_stream: std.net.Stream,
    mutex: *std.Thread.Mutex,
    stream_id: u32,
    frame_type: protocol.FrameType,
    flags: u8,
    payload: []const u8,
) !void {
    var hdr_buf: [8]u8 = undefined;
    const hdr = protocol.Header{
        .stream_id = stream_id,
        .frame_type = frame_type,
        .flags = flags,
        .length = @intCast(payload.len),
    };
    hdr.encode(&hdr_buf);
    mutex.lock();
    defer mutex.unlock();
    try conn_stream.writeAll(&hdr_buf);
    if (payload.len > 0) {
        try conn_stream.writeAll(payload);
    }
}

fn pumpUpstreamToTunnel(
    allocator: std.mem.Allocator,
    session: *UpstreamSession,
    conn_stream: std.net.Stream,
    write_mutex: *std.Thread.Mutex,
) void {
    defer {
        session.active.store(false, .seq_cst);
        session.release(allocator);
    }

    var buf: [16384]u8 = undefined;
    while (session.active.load(.seq_cst)) {
        const n = session.target_stream.read(&buf) catch break;
        if (n == 0) break;
        std.log.info("[Hub] Upstream {s}:{d} read {d} bytes, encoding into tunnel frame (stream {d})", .{ session.getHost(), session.target_port, n, session.stream_id });
        writeTunnelFrame(conn_stream, write_mutex, session.stream_id, .data, 0, buf[0..n]) catch break;
    }
    writeTunnelFrame(conn_stream, write_mutex, session.stream_id, .close, protocol.Flags.FIN, &.{}) catch {};
    std.log.info("[Hub] Upstream session completed for {s}:{d} (stream {d})", .{ session.getHost(), session.target_port, session.stream_id });
}

fn handleConnection(allocator: std.mem.Allocator, conn: std.net.Server.Connection) void {
    defer conn.stream.close();

    std.log.info("Incoming connection accepted from {any}", .{conn.address});

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
        conn.stream.writeAll(resp) catch return;
        std.log.info("WebSocket tunnel established with {any}", .{conn.address});

        var write_mutex = std.Thread.Mutex{};
        var sessions_mutex = std.Thread.Mutex{};
        var parser = protocol.FrameParser.init();
        var sessions = std.AutoHashMap(u32, *UpstreamSession).init(allocator);
        defer {
            sessions_mutex.lock();
            var it = sessions.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.active.store(false, .seq_cst);
                entry.value_ptr.*.release(allocator);
            }
            sessions.deinit();
            sessions_mutex.unlock();
        }

        while (true) {
            const dest = parser.getWriteSlice();
            const n = conn.stream.read(dest) catch break;
            if (n == 0) break;
            parser.advance(n);

            while (parser.next()) |frame| {
                if (frame.header.frame_type == .ping) {
                    writeTunnelFrame(conn.stream, &write_mutex, 0, .pong, 0, &.{}) catch break;
                } else if (frame.header.frame_type == .connect) {
                    if (frame.payload.len >= 4 and frame.payload[0] == 0x02) {
                        const domain_len = frame.payload[1];
                        if (frame.payload.len >= 2 + domain_len + 2) {
                            const domain = frame.payload[2 .. 2 + domain_len];
                            const port = std.mem.readInt(u16, frame.payload[2 + domain_len ..][0..2], .big);

                            std.log.info("[Hub] Received CONNECT: proxying to {s}:{d} (stream {d})...", .{ domain, port, frame.header.stream_id });

                            const target_stream = std.net.tcpConnectToHost(allocator, domain, port) catch |err| {
                                std.log.err("[Hub] Connection to upstream {s}:{d} failed: {any}", .{ domain, port, err });
                                writeTunnelFrame(conn.stream, &write_mutex, frame.header.stream_id, .close, protocol.Flags.RST, &.{}) catch {};
                                continue;
                            };

                            const session = allocator.create(UpstreamSession) catch {
                                target_stream.close();
                                continue;
                            };
                            session.* = .{
                                .stream_id = frame.header.stream_id,
                                .target_stream = target_stream,
                                .target_host = undefined,
                                .target_host_len = domain.len,
                                .target_port = port,
                                .active = std.atomic.Value(bool).init(true),
                                .ref_count = std.atomic.Value(usize).init(2),
                            };
                            @memcpy(session.target_host[0..domain.len], domain);

                            sessions_mutex.lock();
                            sessions.put(frame.header.stream_id, session) catch {
                                sessions_mutex.unlock();
                                target_stream.close();
                                allocator.destroy(session);
                                continue;
                            };
                            sessions_mutex.unlock();

                            const reader_thread = std.Thread.spawn(.{}, pumpUpstreamToTunnel, .{
                                allocator,
                                session,
                                conn.stream,
                                &write_mutex,
                            }) catch {
                                sessions_mutex.lock();
                                _ = sessions.remove(frame.header.stream_id);
                                sessions_mutex.unlock();
                                session.release(allocator);
                                session.release(allocator);
                                continue;
                            };
                            reader_thread.detach();
                        }
                    }
                } else if (frame.header.frame_type == .data) {
                    sessions_mutex.lock();
                    const maybe_session = sessions.get(frame.header.stream_id);
                    sessions_mutex.unlock();

                    if (maybe_session) |session| {
                        session.target_stream.writeAll(frame.payload) catch {
                            session.active.store(false, .seq_cst);
                        };
                        std.log.info("[Hub] Wrote {d} bytes from tunnel to upstream {s}:{d} (stream {d})", .{ frame.payload.len, session.getHost(), session.target_port, frame.header.stream_id });
                    }
                } else if (frame.header.frame_type == .close) {
                    sessions_mutex.lock();
                    const maybe_session = sessions.fetchRemove(frame.header.stream_id);
                    sessions_mutex.unlock();

                    if (maybe_session) |kv| {
                        kv.value.active.store(false, .seq_cst);
                        kv.value.release(allocator);
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
