const std = @import("std");

pub const TcpEngine = struct {
    pub fn processPacket(packet: []const u8) ?[]const u8 {
        if (packet.len < 20) return null;
        return packet;
    }
};
