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

pub const FrameParser = struct {
    buffer: [65536]u8 = undefined,
    start: usize = 0,
    len: usize = 0,

    pub fn init() FrameParser {
        return .{};
    }

    pub fn getWriteSlice(self: *FrameParser) []u8 {
        if (self.start > 0 and self.len > 0) {
            std.mem.copyForwards(u8, self.buffer[0..self.len], self.buffer[self.start .. self.start + self.len]);
            self.start = 0;
        } else if (self.len == 0) {
            self.start = 0;
        }
        return self.buffer[self.len..];
    }

    pub fn append(self: *FrameParser, bytes: []const u8) !void {
        const dest = self.getWriteSlice();
        if (bytes.len > dest.len) return error.BufferOverflow;
        @memcpy(dest[0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn advance(self: *FrameParser, bytes_read: usize) void {
        self.len += bytes_read;
    }

    pub const Frame = struct {
        header: Header,
        payload: []const u8,
    };

    pub fn next(self: *FrameParser) ?Frame {
        if (self.len < 8) return null;
        const hdr_slice: *const [8]u8 = @ptrCast(self.buffer[self.start .. self.start + 8]);
        const hdr = Header.decode(hdr_slice);
        const total = 8 + @as(usize, hdr.length);
        if (self.len < total) return null;

        const payload = self.buffer[self.start + 8 .. self.start + total];
        self.start += total;
        self.len -= total;
        return .{
            .header = hdr,
            .payload = payload,
        };
    }
};
