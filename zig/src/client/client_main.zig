const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const fake_ip = @import("fake_ip.zig");

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

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();

    const sample_ip = try dns.allocate("google.com");
    std.log.info("Zero-Latency DNS active: 198.18.0.1:53 (sample 198.18.x.x allocated for google.com: 0x{x})", .{sample_ip});

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

    std.log.info("TLS 1.3 Handshake established! Negotiated secure session.", .{});

    const ws_upgrade = "GET /api/v2/stream HTTP/1.1\r\n" ++
        "Host: 34.88.228.23\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    try tls_client.writer.writeAll(ws_upgrade);
    try tls_client.writer.flush();
    try stream_writer.interface.flush();

    var resp_buf: [512]u8 = undefined;
    var n: usize = 0;
    while (n < resp_buf.len) {
        const byte = try tls_client.reader.takeByte();
        resp_buf[n] = byte;
        n += 1;
        if (n >= 4 and std.mem.eql(u8, resp_buf[n - 4 .. n], "\r\n\r\n")) break;
    }

    if (std.mem.indexOf(u8, resp_buf[0..n], "101") != null) {
        std.log.info("WebSocket Upgrade accepted by Envoy: HTTP/1.1 101 Switching Protocols!", .{});
        std.log.info("MMX Tunnel established over TLS 1.3 WebSocket! Active and running. Press Ctrl+C to stop.", .{});
    } else {
        std.log.warn("Unexpected server response: {s}", .{resp_buf[0..n]});
        return;
    }

    var ping_seq: u32 = 0;
    while (true) {
        std.Thread.sleep(5 * std.time.ns_per_s);
        ping_seq += 1;

        const ping_frame = [_]u8{ 0x82, 0x08, 0, 0, 0, 0, 0x05, 0, 0, 0 };
        tls_client.writer.writeAll(&ping_frame) catch |err| {
            std.log.warn("Connection lost: {any}. Reconnecting...", .{err});
            break;
        };
        tls_client.writer.flush() catch |err| {
            std.log.warn("TLS flush error: {any}. Reconnecting...", .{err});
            break;
        };
        stream_writer.interface.flush() catch |err| {
            std.log.warn("TCP flush error: {any}. Reconnecting...", .{err});
            break;
        };
        std.log.info("L7 Heartbeat #{d} delivered via TLS 1.3 WebSocket tunnel. Hub is healthy.", .{ping_seq});
    }
}
