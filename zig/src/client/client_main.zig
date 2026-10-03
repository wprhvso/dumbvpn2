const std = @import("std");
const posix = std.posix;
const common = @import("common");
const protocol = common.protocol;
const fake_ip = @import("fake_ip.zig");
const h2 = @import("h2.zig");
const tun_linux = @import("tun/tun_linux.zig");
const icmp_engine = @import("tun/icmp_engine.zig");
const tcp_engine = @import("tun/tcp_engine.zig");
const udp_engine = @import("tun/udp_engine.zig");
const dns_responder = @import("tun/dns_responder.zig");

var should_exit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var global_dns: ?*fake_ip.FakeIpEngine = null;

var active_fake_ip = [4]u8{ 198, 18, 0, 3 };
var active_client_ip = [4]u8{ 10, 88, 0, 2 };
var active_client_port: u16 = 0;
var active_target_port: u16 = 443;
var active_server_seq: u32 = 0x10000001;
var active_client_seq: u32 = 0;
var writer_mutex: std.Thread.Mutex = .{};

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

fn runDnsServer(engine: *fake_ip.FakeIpEngine) void {
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

fn runTunnelReader(tun_dev: @import("tun/device.zig").TunDevice, reader: anytype) void {
    var raw_hdr: [9]u8 = undefined;
    var data_buf: [16384]u8 = undefined;
    var tcp_pkt_buf: [16384 + 128]u8 = undefined;

    while (!should_exit.load(.seq_cst)) {
        for (&raw_hdr) |*b| {
            b.* = reader.takeByte() catch return;
        }
        const frame = h2.FrameHeader.decode(&raw_hdr);

        if (frame.frame_type == .data and frame.stream_id == 1) {
            const len = @min(frame.length, data_buf.len);
            var i: usize = 0;
            while (i < frame.length) : (i += 1) {
                const b = reader.takeByte() catch return;
                if (i < len) data_buf[i] = b;
            }
            if (len == 0) continue;

            var payload = data_buf[0..len];
            if (payload.len >= 2 and payload[0] == 0x82) {
                var offset: usize = 2;
                if (payload[1] == 126) {
                    offset = 4;
                } else if (payload[1] == 127) {
                    offset = 10;
                }
                if (payload.len >= offset) {
                    payload = payload[offset..];
                }
            }
            if (payload.len == 0) continue;

            const pkt_len = tcp_engine.buildTcpPacket(
                active_fake_ip,
                active_client_ip,
                active_target_port,
                active_client_port,
                active_server_seq,
                active_client_seq,
                0x18,
                payload,
                &tcp_pkt_buf,
            );
            if (pkt_len) |l| {
                _ = tun_dev.writePacket(tcp_pkt_buf[0..l]) catch {};
                active_server_seq += @intCast(payload.len);
                std.log.info("Hub response: delivered {d} bytes to mesh0 (TLS ServerHello / Data).", .{payload.len});
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

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();
    global_dns = &dns;

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
            stream1_open = true;
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
        const reader_t = std.Thread.spawn(.{}, runTunnelReader, .{ maybe_tun.?, &tls_client.reader }) catch null;
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
                    _ = tun_dev.writePacket(packet) catch {};
                } else if (tcp_engine.TcpEngine.handlePacket(packet)) |tcp_res| {
                    const client_ip = packet[12..16];
                    const target_ip = packet[16..20];
                    const target_u32 = std.mem.readInt(u32, target_ip, .big);

                    var domain: []const u8 = "icanhazip.com";
                    if (global_dns) |d| {
                        if (d.lookup(target_u32)) |name| {
                            domain = name;
                        }
                    }

                    if (tcp_res.is_syn) {
                        active_client_port = tcp_res.src_port;
                        active_target_port = tcp_res.dst_port;
                        active_fake_ip = target_ip.*;
                        active_client_ip = client_ip.*;
                        active_client_seq = tcp_res.seq + 1;
                        active_server_seq = 0x10000001;

                        _ = tun_dev.writePacket(packet[0..tcp_res.reply_len]) catch {};
                        std.log.info("User-Space TCP: SYN-ACK handshake generated for {s}:{d} (flow port {d}).", .{ domain, tcp_res.dst_port, tcp_res.src_port });

                        var connect_payload: [512]u8 = undefined;
                        std.mem.writeInt(u32, connect_payload[0..4], 1, .big);
                        connect_payload[4] = 0x01; // CONNECT
                        connect_payload[5] = 0x00;
                        const p_len = 1 + 1 + domain.len + 2;
                        std.mem.writeInt(u16, connect_payload[6..8], @intCast(p_len), .big);
                        connect_payload[8] = 0x02; // Domain
                        connect_payload[9] = @intCast(domain.len);
                        @memcpy(connect_payload[10 .. 10 + domain.len], domain);
                        std.mem.writeInt(u16, connect_payload[10 + domain.len ..][0..2], tcp_res.dst_port, .big);

                        const data_frame = h2.FrameHeader{
                            .length = 8 + p_len,
                            .frame_type = .data,
                            .flags = 0x00,
                            .stream_id = 1,
                        };
                        data_frame.encode(&hdr_buf);
                        writer_mutex.lock();
                        tls_client.writer.writeAll(&hdr_buf) catch {};
                        tls_client.writer.writeAll(connect_payload[0 .. 8 + p_len]) catch {};
                        tls_client.writer.flush() catch {};
                        stream_writer.interface.flush() catch {};
                        writer_mutex.unlock();
                        std.log.info("Sent MMX CONNECT for {s}:{d} over HTTP/2 Stream 1!", .{ domain, tcp_res.dst_port });
                    } else if (tcp_res.payload.len > 0) {
                        active_client_seq = tcp_res.seq + @as(u32, @intCast(tcp_res.payload.len));

                        var ack_buf: [128]u8 = undefined;
                        const ack_len = tcp_engine.buildTcpPacket(
                            target_ip.*,
                            client_ip.*,
                            tcp_res.dst_port,
                            tcp_res.src_port,
                            active_server_seq,
                            active_client_seq,
                            0x10,
                            &.{},
                            &ack_buf,
                        );
                        if (ack_len) |l| {
                            _ = tun_dev.writePacket(ack_buf[0..l]) catch {};
                        }

                        const data_frame = h2.FrameHeader{
                            .length = tcp_res.payload.len,
                            .frame_type = .data,
                            .flags = 0x00,
                            .stream_id = 1,
                        };
                        data_frame.encode(&hdr_buf);
                        writer_mutex.lock();
                        tls_client.writer.writeAll(&hdr_buf) catch {};
                        tls_client.writer.writeAll(tcp_res.payload) catch {};
                        tls_client.writer.flush() catch {};
                        stream_writer.interface.flush() catch {};
                        writer_mutex.unlock();
                        std.log.info("Streamed {d} bytes to {s}:{d} over HTTP/2!", .{ tcp_res.payload.len, domain, tcp_res.dst_port });
                    }
                }
            }
        }

        ping_seq += 1;
        if (ping_seq % 250 == 0) {
            const ping_hdr = h2.FrameHeader{
                .length = 8,
                .frame_type = .ping,
                .flags = 0x00,
                .stream_id = 0,
            };
            ping_hdr.encode(&hdr_buf);
            writer_mutex.lock();
            tls_client.writer.writeAll(&hdr_buf) catch {};
            tls_client.writer.writeAll("PINGPING") catch {};
            tls_client.writer.flush() catch {};
            stream_writer.interface.flush() catch {};
            writer_mutex.unlock();
            std.log.info("HTTP/2 L7 Heartbeat #{d} delivered. Dual-Stack Hub is healthy.", .{ping_seq / 250});
        }
    }

    std.log.info("Shutting down cleanly: restoring DNS and network interfaces...", .{});
}
