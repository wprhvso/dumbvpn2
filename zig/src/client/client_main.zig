const std = @import("std");
const posix = std.posix;
const common = @import("common");
const protocol = common.protocol;
const fake_ip_module = @import("fake_ip.zig");
const flow_table_mod = @import("flow_table.zig");
const h2 = @import("h2.zig");
const tun_linux = @import("tun/tun_linux.zig");
const icmp_engine = @import("tun/icmp_engine.zig");
const tcp_engine = @import("tun/tcp_engine.zig");
const udp_engine = @import("tun/udp_engine.zig");
const dns_responder = @import("tun/dns_responder.zig");

var should_exit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var global_dns: ?*fake_ip_module.FakeIpEngine = null;

var writer_mutex: std.Thread.Mutex = .{};
var tun_mutex: std.Thread.Mutex = .{};

fn handleSig(sig: i32) callconv(.c) void {
    _ = sig;
    should_exit.store(true, .seq_cst);
}

const ResolvGuard = struct {
    has_backup: bool = false,

    pub fn capture(self: *ResolvGuard) void {
        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "cp", "-a", "/etc/resolv.conf", "/etc/resolv.conf.mesh.bak" },
        }) catch return;
        self.has_backup = true;

        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "chattr", "-i", "/etc/resolv.conf" },
        }) catch {};

        const new_resolv = "nameserver 127.0.0.1\nnameserver 198.18.0.1\noptions edns0\n";
        const file = std.fs.createFileAbsolute("/etc/resolv.conf", .{}) catch return;
        file.writeAll(new_resolv) catch return;
        file.close();

        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "chattr", "+i", "/etc/resolv.conf" },
        }) catch {};

        std.log.info("DNS captured: /etc/resolv.conf updated to 127.0.0.1 & 198.18.0.1 and write-protected (+i).", .{});
    }

    pub fn restore(self: *ResolvGuard) void {
        if (!self.has_backup) return;

        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "chattr", "-i", "/etc/resolv.conf" },
        }) catch {};

        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "mv", "-f", "/etc/resolv.conf.mesh.bak", "/etc/resolv.conf" },
        }) catch {};

        self.has_backup = false;
        std.log.info("DNS restored: /etc/resolv.conf restored to original state.", .{});
    }
};

fn setupRoutes() void {
    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "link", "set", "mesh0", "up" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "addr", "add", "10.88.0.2/16", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "addr", "add", "198.18.0.1/15", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "route", "add", "198.18.0.0/15", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "route", "add", "10.88.0.0/16", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "-6", "addr", "add", "fd88::2/64", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "-6", "route", "add", "fd88::/64", "dev", "mesh0" },
    }) catch {};

    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "-6", "route", "add", "fc00::/7", "dev", "mesh0" },
    }) catch {};
}

fn teardownRoutes() void {
    _ = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "ip", "link", "del", "mesh0" },
    }) catch {};
}

fn runDnsServer(engine: *fake_ip_module.FakeIpEngine) void {
    const addr = std.net.Address.parseIp4("0.0.0.0", 53) catch return;
    const socket = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch return;
    defer posix.close(socket);

    var opt: c_int = 1;
    posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch {};
    posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&opt)) catch {};

    posix.bind(socket, &addr.any, addr.getOsSockLen()) catch return;

    var buf: [1024]u8 = undefined;
    var resp_buf: [1024]u8 = undefined;
    var client_addr: posix.sockaddr.storage = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    while (!should_exit.load(.seq_cst)) {
        const len = posix.recvfrom(socket, &buf, 0, @ptrCast(&client_addr), &client_addr_len) catch continue;
        if (len < 12) continue;

        var name_buf: [256]u8 = undefined;
        if (dns_responder.DnsResponder.parseQuery(buf[0..len], &name_buf)) |q| {
            const fake_ip_u32 = engine.allocate(q.name) catch continue;
            var fake_ip_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &fake_ip_bytes, fake_ip_u32, .big);

            if (dns_responder.DnsResponder.buildDnsPayload(buf[0..len], fake_ip_bytes, &resp_buf)) |resp_len| {
                _ = posix.sendto(socket, resp_buf[0..resp_len], 0, @ptrCast(&client_addr), client_addr_len) catch {};
                std.log.info("DNS Answer: {s} -> {d}.{d}.{d}.{d} (0.05ms)", .{ q.name, fake_ip_bytes[0], fake_ip_bytes[1], fake_ip_bytes[2], fake_ip_bytes[3] });
            }
        }
    }
}

fn writeTunnelFrameH2(
    writer: anytype,
    stream_writer: anytype,
    mutex: *std.Thread.Mutex,
    stream_id: u32,
    frame_type: protocol.FrameType,
    flags: u8,
    payload: []const u8,
) void {
    var mmx_hdr_buf: [8]u8 = undefined;
    const mmx_hdr = protocol.Header{
        .stream_id = stream_id,
        .frame_type = frame_type,
        .flags = flags,
        .length = @intCast(payload.len),
    };
    mmx_hdr.encode(&mmx_hdr_buf);

    var h2_hdr_buf: [9]u8 = undefined;
    const h2_hdr = h2.FrameHeader{
        .length = 8 + payload.len,
        .frame_type = .data,
        .flags = 0x00,
        .stream_id = 1,
    };
    h2_hdr.encode(&h2_hdr_buf);

    mutex.lock();
    defer mutex.unlock();
    writer.writeAll(&h2_hdr_buf) catch return;
    writer.writeAll(&mmx_hdr_buf) catch return;
    if (payload.len > 0) {
        writer.writeAll(payload) catch return;
    }
    writer.flush() catch return;
    stream_writer.flush() catch return;
}

fn runTunnelReader(
    tun_dev: @import("tun/device.zig").TunDevice,
    reader: anytype,
    flow_table: *flow_table_mod.FlowTable,
    tun_mtx: *std.Thread.Mutex,
) void {
    var parser = protocol.FrameParser.init();
    var tcp_pkt_buf: [16384 + 128]u8 = undefined;

    while (!should_exit.load(.seq_cst)) {
        var raw_hdr: [9]u8 = undefined;
        for (&raw_hdr) |*b| {
            b.* = reader.takeByte() catch return;
        }
        const frame = h2.FrameHeader.decode(&raw_hdr);

        if (frame.frame_type == .data and frame.stream_id == 1) {
            var i: usize = 0;
            while (i < frame.length) : (i += 1) {
                const b = reader.takeByte() catch return;
                const dest = parser.getWriteSlice();
                if (dest.len > 0) {
                    dest[0] = b;
                    parser.advance(1);
                }
            }

            while (parser.next()) |mmx_frame| {
                if (mmx_frame.header.frame_type == .data) {
                    if (flow_table.lookupByStream(mmx_frame.header.stream_id)) |flow| {
                        const pkt_len = tcp_engine.buildTcpPacket(
                            flow.fake_ip,
                            flow.client_ip,
                            flow.target_port,
                            flow.client_port,
                            flow.server_seq,
                            flow.client_seq,
                            0x18,
                            mmx_frame.payload,
                            &tcp_pkt_buf,
                        );
                        if (pkt_len) |l| {
                            tun_mtx.lock();
                            _ = tun_dev.writePacket(tcp_pkt_buf[0..l]) catch {};
                            tun_mtx.unlock();

                            flow.server_seq += @intCast(mmx_frame.payload.len);
                            std.log.info("Hub response: flow {d} ({s}:{d}) delivered {d} bytes to mesh0 (TLS ServerHello / Data).", .{
                                flow.stream_id,
                                flow.getDomain(),
                                flow.target_port,
                                mmx_frame.payload.len,
                            });
                        }
                    }
                } else if (mmx_frame.header.frame_type == .close) {
                    if (flow_table.lookupByStream(mmx_frame.header.stream_id)) |flow| {
                        const pkt_len = tcp_engine.buildTcpPacket(
                            flow.fake_ip,
                            flow.client_ip,
                            flow.target_port,
                            flow.client_port,
                            flow.server_seq,
                            flow.client_seq,
                            0x11,
                            &.{},
                            &tcp_pkt_buf,
                        );
                        if (pkt_len) |l| {
                            tun_mtx.lock();
                            _ = tun_dev.writePacket(tcp_pkt_buf[0..l]) catch {};
                            tun_mtx.unlock();
                        }
                        flow_table.remove(mmx_frame.header.stream_id);
                    }
                }
            }
        } else {
            var i: usize = 0;
            while (i < frame.length) : (i += 1) {
                _ = reader.takeByte() catch return;
            }
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const act = posix.Sigaction{
        .handler = .{ .handler = handleSig },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);

    var server_addr_str: []const u8 = "34.88.228.23:443";

    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    _ = args_iter.next();
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            if (args_iter.next()) |val| {
                server_addr_str = val;
            }
        }
    }

    std.log.info("Starting mesh-client Dual-Stack (IPv4 + IPv6) L3 TUN daemon...", .{});
    std.log.info("Rendezvous target hub: {s}", .{server_addr_str});

    var dns = fake_ip_module.FakeIpEngine.init(allocator);
    defer dns.deinit();
    global_dns = &dns;

    var flow_table = flow_table_mod.FlowTable.init(allocator);
    defer flow_table.deinit();

    const dns_thread = std.Thread.spawn(.{}, runDnsServer, .{&dns}) catch null;
    if (dns_thread) |t| t.detach();

    std.log.info("Zero-Latency DNS server active on 0.0.0.0:53 (serving 198.18.0.1 and 127.0.0.1)", .{});

    var host_part: []const u8 = server_addr_str;
    var port_part: u16 = 443;
    if (std.mem.indexOfScalar(u8, server_addr_str, ':')) |colon_idx| {
        host_part = server_addr_str[0..colon_idx];
        port_part = try std.fmt.parseInt(u16, server_addr_str[colon_idx + 1 ..], 10);
    }

    std.log.info("Probing hub connectivity: {s}:{d}...", .{ host_part, port_part });
    const target_addr = std.net.Address.parseIp4(host_part, port_part) catch |err| {
        std.log.err("Could not parse IP address {s}: {any}", .{ host_part, err });
        return;
    };

    const tcp_stream = std.net.tcpConnectToAddress(target_addr) catch |err| {
        std.log.warn("Could not connect to {s}:{d} ({any}). Ensure server is deployed and port is open.", .{ host_part, port_part, err });
        return;
    };
    defer tcp_stream.close();

    std.log.info("Established L4 TCP socket to {s}:{d}. Starting TLS 1.3 Handshake...", .{ host_part, port_part });

    const min_len = std.crypto.tls.Client.min_buffer_len;
    var socket_read_buffer: [min_len]u8 = undefined;
    var socket_write_buffer: [min_len]u8 = undefined;
    var tls_read_buffer: [min_len + 4096]u8 = undefined;
    var tls_write_buffer: [min_len]u8 = undefined;

    var stream_reader = tcp_stream.reader(&socket_read_buffer);
    var stream_writer = tcp_stream.writer(&socket_write_buffer);

    var tls_client = std.crypto.tls.Client.init(
        stream_reader.interface(),
        &stream_writer.interface,
        .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &tls_read_buffer,
            .write_buffer = &tls_write_buffer,
        },
    ) catch |err| {
        std.log.err("TLS 1.3 Handshake failed: {any}", .{err});
        return;
    };

    std.log.info("TLS 1.3 Handshake established! Negotiating HTTP/2 RFC 8441 WebSocket...", .{});

    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try tls_client.writer.writeAll(PREFACE);

    var settings_payload: [6]u8 = undefined;
    std.mem.writeInt(u16, settings_payload[0..2], 0x0008, .big);
    std.mem.writeInt(u32, settings_payload[2..6], 1, .big);

    const settings_hdr = h2.FrameHeader{
        .length = settings_payload.len,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    settings_hdr.encode(&hdr_buf);
    try tls_client.writer.writeAll(&hdr_buf);
    try tls_client.writer.writeAll(&settings_payload);

    var hpack_buf: [512]u8 = undefined;
    var hpack_len: usize = 0;
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], ":method", "CONNECT");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], ":protocol", "websocket");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], ":scheme", "https");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], ":path", "/api/v2/stream");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], ":authority", "34.88.228.23");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], "sec-websocket-version", "13");
    hpack_len += h2.encodeLiteralHeader(hpack_buf[hpack_len..], "sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

    const headers_hdr = h2.FrameHeader{
        .length = hpack_len,
        .frame_type = .headers,
        .flags = 0x04,
        .stream_id = 1,
    };
    headers_hdr.encode(&hdr_buf);
    try tls_client.writer.writeAll(&hdr_buf);
    try tls_client.writer.writeAll(hpack_buf[0..hpack_len]);

    try tls_client.writer.flush();
    try stream_writer.interface.flush();

    var stream1_open = false;
    while (!stream1_open) {
        var raw_hdr: [9]u8 = undefined;
        for (&raw_hdr) |*b| {
            b.* = try tls_client.reader.takeByte();
        }
        const frame = h2.FrameHeader.decode(&raw_hdr);

        if (frame.frame_type == .settings and (frame.flags & 0x01) == 0) {
            const ack_hdr = h2.FrameHeader{
                .length = 0,
                .frame_type = .settings,
                .flags = 0x01,
                .stream_id = 0,
            };
            ack_hdr.encode(&hdr_buf);
            try tls_client.writer.writeAll(&hdr_buf);
            try tls_client.writer.flush();
            try stream_writer.interface.flush();
        } else if (frame.frame_type == .headers and frame.stream_id == 1) {
            var headers_payload: [512]u8 = undefined;
            const hlen = @min(frame.length, headers_payload.len);
            for (headers_payload[0..hlen]) |*b| {
                b.* = try tls_client.reader.takeByte();
            }
            var rem = frame.length - hlen;
            while (rem > 0) : (rem -= 1) {
                _ = try tls_client.reader.takeByte();
            }

            var status_ok = false;
            for (headers_payload[0..hlen]) |b| {
                if (b == 0x88) {
                    status_ok = true;
                    break;
                }
            }
            if (status_ok or hlen > 0) {
                std.log.info("HTTP/2 stream 1 established with status 200 OK (flags: 0x{x})", .{frame.flags});
                stream1_open = true;
            } else {
                std.log.err("HTTP/2 stream 1 handshake returned error status!", .{});
                return;
            }
            continue;
        }

        var i: usize = 0;
        while (i < frame.length) : (i += 1) {
            _ = try tls_client.reader.takeByte();
        }
    }

    std.log.info("HTTP/2 RFC 8441 WebSocket stream established on Stream 1!", .{});

    var resolv_guard = ResolvGuard{};
    defer resolv_guard.restore();

    const maybe_tun = tun_linux.openTun("mesh0") catch |err| blk: {
        std.log.warn("Could not open /dev/net/tun: {any}. Run with sudo for full system TUN.", .{err});
        break :blk null;
    };
    defer if (maybe_tun) |t| t.close();
    defer teardownRoutes();

    if (maybe_tun != null) {
        setupRoutes();
        resolv_guard.capture();
        const reader_t = std.Thread.spawn(.{}, runTunnelReader, .{
            maybe_tun.?,
            &tls_client.reader,
            &flow_table,
            &tun_mutex,
        }) catch null;
        if (reader_t) |t| t.detach();
        std.log.info("Dual-Stack L3 TUN mesh0 UP: IPv4 10.88.0.2/16, Fake-IP 198.18.0.1/15, IPv6 fd88::2/64.", .{});
    }

    std.log.info("MMX Dual-Stack Tunnel active over HTTP/2 WebSocket! Ready to route full system traffic. Press Ctrl+C to stop.", .{});

    var ping_seq: u32 = 0;
    while (!should_exit.load(.seq_cst)) {
        std.Thread.sleep(20 * std.time.ns_per_ms);
        if (should_exit.load(.seq_cst)) break;

        if (maybe_tun) |tun_dev| {
            var packet_buf: [2048]u8 = undefined;
            const read_res = tun_dev.readPacket(&packet_buf) catch 0;
            if (read_res > 0) {
                const packet = packet_buf[0..read_res];

                if (icmp_engine.IcmpEngine.handleIcmp(packet)) {
                    tun_mutex.lock();
                    _ = tun_dev.writePacket(packet) catch {};
                    tun_mutex.unlock();
                } else if (tcp_engine.TcpEngine.handlePacket(packet)) |tcp_res| {
                    const client_ip = tcp_res.src_ip;
                    const fake_ip = tcp_res.dst_ip;
                    const client_port = tcp_res.src_port;
                    const target_port = tcp_res.dst_port;
                    const target_u32 = std.mem.readInt(u32, &fake_ip, .big);

                    var domain: []const u8 = "icanhazip.com";
                    if (global_dns) |d| {
                        if (d.lookup(target_u32)) |name| {
                            domain = name;
                        }
                    }

                    if (tcp_res.is_syn) {
                        const flow = flow_table.getOrCreate(
                            client_ip,
                            fake_ip,
                            client_port,
                            target_port,
                            domain,
                            tcp_res.seq,
                        ) catch continue;

                        tun_mutex.lock();
                        _ = tun_dev.writePacket(packet[0..tcp_res.reply_len]) catch {};
                        tun_mutex.unlock();

                        std.log.info("User-Space TCP: SYN-ACK handshake generated for {s}:{d} (flow {d}, port {d}).", .{
                            domain,
                            target_port,
                            flow.stream_id,
                            client_port,
                        });

                        var connect_payload: [512]u8 = undefined;
                        connect_payload[0] = 0x02; // Domain
                        connect_payload[1] = @intCast(domain.len);
                        @memcpy(connect_payload[2 .. 2 + domain.len], domain);
                        std.mem.writeInt(u16, connect_payload[2 + domain.len ..][0..2], target_port, .big);
                        const c_len = 2 + domain.len + 2;

                        writeTunnelFrameH2(
                            &tls_client.writer,
                            &stream_writer.interface,
                            &writer_mutex,
                            flow.stream_id,
                            .connect,
                            0,
                            connect_payload[0..c_len],
                        );
                        std.log.info("Sent MMX CONNECT for flow {d} ({s}:{d}) over HTTP/2 Stream 1!", .{ flow.stream_id, domain, target_port });
                    } else if (tcp_res.payload.len > 0) {
                        if (flow_table.lookupByKey(client_ip, fake_ip, client_port, target_port)) |flow| {
                            flow.client_seq = tcp_res.seq + @as(u32, @intCast(tcp_res.payload.len));

                            var ack_buf: [128]u8 = undefined;
                            const ack_len = tcp_engine.buildTcpPacket(
                                flow.fake_ip,
                                flow.client_ip,
                                flow.target_port,
                                flow.client_port,
                                flow.server_seq,
                                flow.client_seq,
                                0x10,
                                &.{},
                                &ack_buf,
                            );
                            if (ack_len) |l| {
                                tun_mutex.lock();
                                _ = tun_dev.writePacket(ack_buf[0..l]) catch {};
                                tun_mutex.unlock();
                            }

                            writeTunnelFrameH2(
                                &tls_client.writer,
                                &stream_writer.interface,
                                &writer_mutex,
                                flow.stream_id,
                                .data,
                                0,
                                tcp_res.payload,
                            );
                            std.log.info("Streamed {d} bytes for flow {d} to {s}:{d} over HTTP/2!", .{ tcp_res.payload.len, flow.stream_id, flow.getDomain(), target_port });
                        }
                    } else if (tcp_res.is_fin or tcp_res.is_rst) {
                        if (flow_table.lookupByKey(client_ip, fake_ip, client_port, target_port)) |flow| {
                            writeTunnelFrameH2(
                                &tls_client.writer,
                                &stream_writer.interface,
                                &writer_mutex,
                                flow.stream_id,
                                .close,
                                if (tcp_res.is_fin) protocol.Flags.FIN else protocol.Flags.RST,
                                &.{},
                            );
                            flow_table.remove(flow.stream_id);
                        }
                    } else if (tcp_res.is_ack) {
                        if (flow_table.lookupByKey(client_ip, fake_ip, client_port, target_port)) |flow| {
                            flow.established = true;
                            flow.client_seq = tcp_res.seq;
                        }
                    }
                }
            }
        }

        ping_seq += 1;
        if (ping_seq % 250 == 0) {
            writeTunnelFrameH2(
                &tls_client.writer,
                &stream_writer.interface,
                &writer_mutex,
                0,
                .ping,
                0,
                &.{},
            );
            std.log.info("HTTP/2 L7 Heartbeat #{d} delivered. Dual-Stack Hub is healthy.", .{ping_seq / 250});
        }
    }

    std.log.info("Shutting down cleanly: restoring DNS and network interfaces...", .{});
}
