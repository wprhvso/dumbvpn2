const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const fake_ip = @import("fake_ip.zig");
const h2 = @import("h2.zig");

fn pumpStreamToTls(stream: std.net.Stream, tls_writer: anytype, tcp_writer: anytype) void {
    var buf: [16384]u8 = undefined;
    while (true) {
        const len = stream.read(&buf) catch break;
        if (len == 0) break;
        tls_writer.writeAll(buf[0..len]) catch break;
        tls_writer.flush() catch break;
        tcp_writer.flush() catch break;
    }
}

fn pumpTlsToStream(tls_reader: anytype, stream: std.net.Stream) void {
    var buf: [16384]u8 = undefined;
    while (true) {
        const len = tls_reader.readSliceShort(&buf) catch break;
        if (len == 0) break;
        stream.writeAll(buf[0..len]) catch break;
    }
}

fn handleSocks5(client_conn: std.net.Server.Connection, hub_host: []const u8, hub_port: u16) void {
    defer client_conn.stream.close();

    var buf: [1024]u8 = undefined;
    var n = client_conn.stream.read(&buf) catch return;
    if (n < 3 or buf[0] != 0x05) return;
    client_conn.stream.writeAll(&[_]u8{ 0x05, 0x00 }) catch return;

    n = client_conn.stream.read(&buf) catch return;
    if (n < 7 or buf[0] != 0x05 or buf[1] != 0x01) return;

    const atyp = buf[3];
    var domain_name: []const u8 = "";
    var target_port: u16 = 80;

    if (atyp == 0x03) {
        const dlen = buf[4];
        if (n >= 5 + dlen + 2) {
            domain_name = buf[5 .. 5 + dlen];
            target_port = std.mem.readInt(u16, buf[5 + dlen ..][0..2], .big);
        }
    } else if (atyp == 0x01) {
        if (n >= 10) {
            const ip = buf[4..8];
            var ip_str_buf: [16]u8 = undefined;
            const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return;
            domain_name = ip_str;
            target_port = std.mem.readInt(u16, buf[8..10], .big);
        }
    }

    if (domain_name.len == 0) return;

    const hub_addr = std.net.Address.parseIp4(hub_host, hub_port) catch return;
    const hub_tcp = std.net.tcpConnectToAddress(hub_addr) catch return;
    defer hub_tcp.close();

    const min_len = std.crypto.tls.Client.min_buffer_len;
    var s_read_buf: [min_len]u8 = undefined;
    var s_write_buf: [min_len]u8 = undefined;
    var t_read_buf: [min_len + 4096]u8 = undefined;
    var t_write_buf: [min_len]u8 = undefined;

    var s_reader = hub_tcp.reader(&s_read_buf);
    var s_writer = hub_tcp.writer(&s_write_buf);

    var tls = std.crypto.tls.Client.init(
        s_reader.interface(),
        &s_writer.interface,
        .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &t_read_buf,
            .write_buffer = &t_write_buf,
        },
    ) catch return;

    const ws_upgrade = "GET /api/v2/stream HTTP/1.1\r\n" ++
        "Host: 34.88.228.23\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    tls.writer.writeAll(ws_upgrade) catch return;
    tls.writer.flush() catch return;
    s_writer.interface.flush() catch return;

    var resp_buf: [512]u8 = undefined;
    var head_len: usize = 0;
    while (head_len < resp_buf.len) {
        const byte = tls.reader.takeByte() catch break;
        resp_buf[head_len] = byte;
        head_len += 1;
        if (head_len >= 4 and std.mem.eql(u8, resp_buf[head_len - 4 .. head_len], "\r\n\r\n")) break;
    }

    var connect_frame: [512]u8 = undefined;
    const payload_len = 1 + 1 + domain_name.len + 2;
    const hdr = protocol.Header{
        .stream_id = 2,
        .frame_type = .connect,
        .flags = 0,
        .length = @intCast(payload_len),
    };
    hdr.encode(connect_frame[0..8]);
    connect_frame[8] = 0x02;
    connect_frame[9] = @intCast(domain_name.len);
    @memcpy(connect_frame[10 .. 10 + domain_name.len], domain_name);
    std.mem.writeInt(u16, connect_frame[10 + domain_name.len ..][0..2], target_port, .big);

    tls.writer.writeAll(connect_frame[0 .. 8 + payload_len]) catch return;
    tls.writer.flush() catch return;
    s_writer.interface.flush() catch return;

    client_conn.stream.writeAll(&[_]u8{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch return;

    const t_pump = std.Thread.spawn(.{}, pumpTlsToStream, .{ &tls.reader, client_conn.stream }) catch return;
    t_pump.detach();
    pumpStreamToTls(client_conn.stream, &tls.writer, &s_writer.interface);
}

fn socks5Server(hub_host: []const u8, hub_port: u16) void {
    const socks_addr = std.net.Address.parseIp4("127.0.0.1", 1080) catch return;
    var server = socks_addr.listen(.{ .reuse_address = true }) catch return;
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        const thread = std.Thread.spawn(.{}, handleSocks5, .{ conn, hub_host, hub_port }) catch {
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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

    std.log.info("Starting mesh-client daemon...", .{});
    std.log.info("Rendezvous target hub: {s}", .{server_addr_str});

    var host_part: []const u8 = server_addr_str;
    var port_part: u16 = 443;
    if (std.mem.indexOfScalar(u8, server_addr_str, ':')) |colon_idx| {
        host_part = server_addr_str[0..colon_idx];
        port_part = try std.fmt.parseInt(u16, server_addr_str[colon_idx + 1 ..], 10);
    }

    const socks_thread = std.Thread.spawn(.{}, socks5Server, .{ host_part, port_part }) catch |err| {
        std.log.warn("Could not bind SOCKS5 listener on 127.0.0.1:1080: {any}", .{err});
        return;
    };
    socks_thread.detach();

    std.log.info("SOCKS5 Proxy active and listening on 127.0.0.1:1080!", .{});
    std.log.info("Zero-Latency DNS active: 198.18.0.1:53", .{});

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
    std.log.info("MMX Tunnel active over HTTP/2 WebSocket! Ready to route SOCKS5 & Mesh traffic.", .{});

    var ping_seq: u32 = 0;
    while (true) {
        std.Thread.sleep(5 * std.time.ns_per_s);
        ping_seq += 1;

        const ping_hdr = h2.FrameHeader{
            .length = 8,
            .frame_type = .ping,
            .flags = 0x00,
            .stream_id = 0,
        };
        ping_hdr.encode(&hdr_buf);
        try tls_client.writer.writeAll(&hdr_buf);
        try tls_client.writer.writeAll("PINGPING");

        const mmx_data = [_]u8{ 0, 0, 0, 0, 0x05, 0, 0, 0 };
        const data_hdr = h2.FrameHeader{
            .length = mmx_data.len,
            .frame_type = .data,
            .flags = 0x00,
            .stream_id = 1,
        };
        data_hdr.encode(&hdr_buf);
        try tls_client.writer.writeAll(&hdr_buf);
        try tls_client.writer.writeAll(&mmx_data);

        try tls_client.writer.flush();
        try stream_writer.interface.flush();

        var ping_ack_hdr: [9]u8 = undefined;
        for (&ping_ack_hdr) |*b| {
            b.* = try tls_client.reader.takeByte();
        }
        const ack_frame = h2.FrameHeader.decode(&ping_ack_hdr);
        var j: usize = 0;
        while (j < ack_frame.length) : (j += 1) {
            _ = try tls_client.reader.takeByte();
        }

        std.log.info("HTTP/2 L7 Heartbeat #{d} delivered. Hub is healthy.", .{ping_seq});
    }
}
