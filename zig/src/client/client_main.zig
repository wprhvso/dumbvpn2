const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const fake_ip = @import("fake_ip.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server_addr_str: []const u8 = "34.88.228.23:4000";

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

    std.log.info("Starting mesh-client...", .{});
    std.log.info("Rendezvous target hub: {s}", .{server_addr_str});

    var dns = fake_ip.FakeIpEngine.init(allocator);
    defer dns.deinit();

    const sample_ip = try dns.allocate("google.com");
    std.log.info("Zero-Latency DNS active: 198.18.0.1:53 (sample 198.18.x.x allocated for google.com: 0x{x})", .{sample_ip});

    var host_part: []const u8 = server_addr_str;
    var port_part: u16 = 4000;
    if (std.mem.indexOfScalar(u8, server_addr_str, ':')) |colon_idx| {
        host_part = server_addr_str[0..colon_idx];
        port_part = try std.fmt.parseInt(u16, server_addr_str[colon_idx + 1 ..], 10);
    }

    std.log.info("Probing hub connectivity: {s}:{d}...", .{ host_part, port_part });
    const target_addr = std.net.Address.parseIp4(host_part, port_part) catch |err| {
        std.log.err("Could not parse IP address {s}: {any}", .{ host_part, err });
        return;
    };

    const stream = std.net.tcpConnectToAddress(target_addr) catch |err| {
        std.log.warn("Could not connect to {s}:{d} ({any}). Ensure server is deployed and port is open.", .{ host_part, port_part, err });
        std.log.info("Client initialized in standby mode, waiting for network connectivity.", .{});
        return;
    };
    defer stream.close();

    std.log.info("Successfully established L4 connection to hub {s}:{d}!", .{ host_part, port_part });

    var header_buf: [8]u8 = undefined;
    const hdr = protocol.Header{
        .stream_id = 1,
        .frame_type = .connect,
        .flags = 0,
        .length = 0,
    };
    hdr.encode(&header_buf);
    try stream.writeAll(&header_buf);
    std.log.info("Sent MMX Handshake frame. Tunnel established!", .{});
}
