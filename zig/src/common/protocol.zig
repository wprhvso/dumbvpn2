const std = @import("std");
pub const types = @import("types.zig");

pub const FrameType = enum(u8) {
    connect = 0x01,
    data = 0x02,
    window_update = 0x03,
    close = 0x04,
    ping = 0x05,
    pong = 0x06,
    peer_route = 0x07,
    rules_delta = 0x08,
};

pub const Flags = struct {
    pub const EARLY_DATA: u8 = 0x01;
    pub const UDP_MODE: u8 = 0x02;
    pub const FIN: u8 = 0x04;
    pub const RST: u8 = 0x08;
};

pub const Header = extern struct {
    stream_id: u32,
    frame_type: FrameType,
    flags: u8,
    length: u16,

    pub fn encode(self: Header, dest: *[8]u8) void {
        std.mem.writeInt(u32, dest[0..4], self.stream_id, .big);
        dest[4] = @intFromEnum(self.frame_type);
        dest[5] = self.flags;
        std.mem.writeInt(u16, dest[6..8], self.length, .big);
    }

    pub fn decode(src: *const [8]u8) Header {
        return .{
            .stream_id = std.mem.readInt(u32, src[0..4], .big),
            .frame_type = @enumFromInt(src[4]),
            .flags = src[5],
            .length = std.mem.readInt(u16, src[6..8], .big),
        };
    }
};
