const std = @import("std");

pub const UdpSession = struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    last_seen: i64,
};

pub const UdpEngine = struct {
    sessions: std.AutoHashMap(u64, UdpSession),

    pub fn init(allocator: std.mem.Allocator) UdpEngine {
        return .{
            .sessions = std.AutoHashMap(u64, UdpSession).init(allocator),
        };
    }

    pub fn deinit(self: *UdpEngine) void {
        self.sessions.deinit();
    }

    pub fn processDatagram(self: *UdpEngine, packet: []const u8) ?struct { host: [4]u8, port: u16, payload: []const u8 } {
        if (packet.len < 28) return null;
        const ihl = (packet[0] & 0x0F) * 4;
        if (packet.len < ihl + 8 or packet[9] != 17) return null;

        const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
        const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);
        const udp_len = std.mem.readInt(u16, packet[ihl + 4 ..][0..2], .big);
        if (packet.len < ihl + udp_len) return null;

        const key = (@as(u64, src_port) << 48) | (@as(u64, dst_port) << 32) | std.mem.readInt(u32, packet[12..16], .big);
        _ = self.sessions.put(key, .{
            .src_ip = std.mem.readInt(u32, packet[12..16], .big),
            .dst_ip = std.mem.readInt(u32, packet[16..20], .big),
            .src_port = src_port,
            .dst_port = dst_port,
            .last_seen = std.time.timestamp(),
        }) catch {};

        var dst_ip: [4]u8 = undefined;
        @memcpy(&dst_ip, packet[16..20]);

        return .{
            .host = dst_ip,
            .port = dst_port,
            .payload = packet[ihl + 8 .. ihl + udp_len],
        };
    }
};
