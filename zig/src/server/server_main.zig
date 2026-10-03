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

const ConnectionContext = struct {
    conn_stream: std.net.Stream,
    write_mutex: std.Thread.Mutex = .{},
    sessions_mutex: std.Thread.Mutex = .{},
    sessions: std.AutoHashMap(u32, *UpstreamSession),
    active: std.atomic.Value(bool),
    ref_count: std.atomic.Value(usize),
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, stream: std.net.Stream) !*ConnectionContext {
        const ctx = try allocator.create(ConnectionContext);
        ctx.* = .{
            .conn_stream = stream,
            .write_mutex = .{},
            .sessions_mutex = .{},
            .sessions = std.AutoHashMap(u32, *UpstreamSession).init(allocator),
            .active = std.atomic.Value(bool).init(true),
            .ref_count = std.atomic.Value(usize).init(1),
            .allocator = allocator,
        };
        return ctx;
    }

    pub fn acquire(self: *ConnectionContext) void {
        _ = self.ref_count.fetchAdd(1, .seq_cst);
    }

    pub fn release(self: *ConnectionContext) void {
        if (self.ref_count.fetchSub(1, .seq_cst) == 1) {
            self.conn_stream.close();
            self.sessions.deinit();
            self.allocator.destroy(self);
        }
    }

    pub fn writeFrame(self: *ConnectionContext, stream_id: u32, frame_type: protocol.FrameType, flags: u8, payload: []const u8) !void {
        if (!self.active.load(.seq_cst)) return error.ConnectionClosed;
        var hdr_buf: [8]u8 = undefined;
        const hdr = protocol.Header{
            .stream_id = stream_id,
            .frame_type = frame_type,
            .flags = flags,
            .length = @intCast(payload.len),
        };
        hdr.encode(&hdr_buf);

        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        try self.conn_stream.writeAll(&hdr_buf);
        if (payload.len > 0) {
            try self.conn_stream.writeAll(payload);
        }
    }
};

fn pumpUpstreamToTunnel(
    ctx: *ConnectionContext,
    session: *UpstreamSession,
) void {
    defer {
        session.active.store(false, .seq_cst);
        session.release(ctx.allocator);
        ctx.release();
    }

    var buf: [16384]u8 = undefined;
    while (session.active.load(.seq_cst) and ctx.active.load(.seq_cst)) {
        const n = session.target_stream.read(&buf) catch break;
        if (n == 0) break;
        std.log.info("[Hub] Upstream {s}:{d} read {d} bytes, encoding into tunnel frame (stream {d})", .{ session.getHost(), session.target_port, n, session.stream_id });
        ctx.writeFrame(session.stream_id, .data, 0, buf[0..n]) catch break;
    }
    ctx.writeFrame(session.stream_id, .close, protocol.Flags.FIN, &.{}) catch {};
    std.log.info("[Hub] Upstream session completed for {s}:{d} (stream {d})", .{ session.getHost(), session.target_port, session.stream_id });
}

fn handleConnection(allocator: std.mem.Allocator, conn: std.net.Server.Connection) void {
    std.log.info("Incoming connection accepted from {any}", .{conn.address});

    var buf: [4096]u8 = undefined;
    const read_len = conn.stream.read(&buf) catch {
        conn.stream.close();
        return;
    };
    if (read_len == 0) {
        conn.stream.close();
        return;
    }
    const data = buf[0..read_len];

    if (std.mem.startsWith(u8, data, "GET /api/v1/health")) {
        defer conn.stream.close();
        const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        _ = conn.stream.writeAll(resp) catch {};
        return;
    } else if (std.mem.startsWith(u8, data, "GET / HTTP/1.1") or std.mem.startsWith(u8, data, "GET /index.html")) {
        defer conn.stream.close();
        const html = embedded_ui.index_html;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{html.len}) catch return;
        _ = conn.stream.writeAll(header) catch {};
        _ = conn.stream.writeAll(html) catch {};
        return;
    } else if (std.mem.startsWith(u8, data, "GET /assets/index.js")) {
        defer conn.stream.close();
        const js = embedded_ui.index_js;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{js.len}) catch return;
        _ = conn.stream.writeAll(header) catch {};
        _ = conn.stream.writeAll(js) catch {};
        return;
    } else if (std.mem.indexOf(u8, data, "Upgrade: websocket") != null or std.mem.startsWith(u8, data, "GET /api/v2/stream")) {
        const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        conn.stream.writeAll(resp) catch {
            conn.stream.close();
            return;
        };
        std.log.info("WebSocket tunnel established with {any}", .{conn.address});

        const ctx = ConnectionContext.create(allocator, conn.stream) catch {
            conn.stream.close();
            return;
        };
        defer {
            ctx.active.store(false, .seq_cst);
            ctx.sessions_mutex.lock();
            var it = ctx.sessions.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.active.store(false, .seq_cst);
                entry.value_ptr.*.release(allocator);
            }
            ctx.sessions_mutex.unlock();
            ctx.release();
        }

        var parser = protocol.FrameParser.init();

        while (ctx.active.load(.seq_cst)) {
            const dest = parser.getWriteSlice();
            const n = ctx.conn_stream.read(dest) catch break;
            if (n == 0) break;
            parser.advance(n);

            while (parser.next()) |frame| {
                if (frame.header.frame_type == .ping) {
                    ctx.writeFrame(0, .pong, 0, &.{}) catch break;
                } else if (frame.header.frame_type == .connect) {
                    if (frame.payload.len >= 4 and frame.payload[0] == 0x02) {
                        const domain_len = frame.payload[1];
                        if (frame.payload.len >= 2 + domain_len + 2) {
                            const domain = frame.payload[2 .. 2 + domain_len];
                            const port = std.mem.readInt(u16, frame.payload[2 + domain_len ..][0..2], .big);

                            std.log.info("[Hub] Received CONNECT: proxying to {s}:{d} (stream {d})...", .{ domain, port, frame.header.stream_id });

                            const target_stream = std.net.tcpConnectToHost(allocator, domain, port) catch |err| {
                                std.log.err("[Hub] Connection to upstream {s}:{d} failed: {any}", .{ domain, port, err });
                                ctx.writeFrame(frame.header.stream_id, .close, protocol.Flags.RST, &.{}) catch {};
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

                            ctx.sessions_mutex.lock();
                            ctx.sessions.put(frame.header.stream_id, session) catch {
                                ctx.sessions_mutex.unlock();
                                target_stream.close();
                                allocator.destroy(session);
                                continue;
                            };
                            ctx.sessions_mutex.unlock();

                            ctx.acquire();
                            const reader_thread = std.Thread.spawn(.{}, pumpUpstreamToTunnel, .{
                                ctx,
                                session,
                            }) catch {
                                ctx.release();
                                ctx.sessions_mutex.lock();
                                _ = ctx.sessions.remove(frame.header.stream_id);
                                ctx.sessions_mutex.unlock();
                                session.release(allocator);
                                session.release(allocator);
                                continue;
                            };
                            reader_thread.detach();
                        }
                    }
                } else if (frame.header.frame_type == .data) {
                    ctx.sessions_mutex.lock();
                    const maybe_session = ctx.sessions.get(frame.header.stream_id);
                    ctx.sessions_mutex.unlock();

                    if (maybe_session) |session| {
                        session.target_stream.writeAll(frame.payload) catch {
                            session.active.store(false, .seq_cst);
                        };
                        std.log.info("[Hub] Wrote {d} bytes from tunnel to upstream {s}:{d} (stream {d})", .{ frame.payload.len, session.getHost(), session.target_port, frame.header.stream_id });
                    }
                } else if (frame.header.frame_type == .close) {
                    ctx.sessions_mutex.lock();
                    const maybe_session = ctx.sessions.fetchRemove(frame.header.stream_id);
                    ctx.sessions_mutex.unlock();

                    if (maybe_session) |kv| {
                        kv.value.active.store(false, .seq_cst);
                        kv.value.release(allocator);
                    }
                }
            }
        }
    } else {
        conn.stream.close();
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
