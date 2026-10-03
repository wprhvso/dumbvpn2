const std = @import("std");

pub const LanBeacon = struct {
    pub const PORT: u16 = 51820;

    pub fn broadcast(socket: std.net.Stream, pubkey: [32]u8) !void {
        _ = socket;
        _ = pubkey;
    }
};
