const std = @import("std");

pub const FrameType = enum(u8) {
    data = 0x00,
    headers = 0x01,
    priority = 0x02,
    rst_stream = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    ping = 0x06,
    goaway = 0x07,
    window_update = 0x08,
    continuation = 0x09,
    _,
};

pub const FrameHeader = struct {
    length: usize,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,

    pub fn encode(self: FrameHeader, dest: *[9]u8) void {
        dest[0] = @intCast((self.length >> 16) & 0xFF);
        dest[1] = @intCast((self.length >> 8) & 0xFF);
        dest[2] = @intCast(self.length & 0xFF);
        dest[3] = @intFromEnum(self.frame_type);
        dest[4] = self.flags;
        std.mem.writeInt(u32, dest[5..9], self.stream_id, .big);
    }

    pub fn decode(src: *const [9]u8) FrameHeader {
        const len = (@as(usize, src[0]) << 16) | (@as(usize, src[1]) << 8) | @as(usize, src[2]);
        const stream = std.mem.readInt(u32, src[5..9], .big) & 0x7FFFFFFF;
        return .{
            .length = len,
            .frame_type = @enumFromInt(src[3]),
            .flags = src[4],
            .stream_id = stream,
        };
    }
};

pub fn buildWindowUpdate(stream_id: u32, increment: u31, buf: *[13]u8) usize {
    const hdr = FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = stream_id,
    };
    hdr.encode(buf[0..9]);
    std.mem.writeInt(u32, buf[9..13], increment & 0x7FFFFFFF, .big);
    return 13;
}

pub fn encodeLiteralHeader(dest: []u8, name: []const u8, val: []const u8) usize {
    var offset: usize = 0;
    dest[offset] = 0x00;
    offset += 1;
    dest[offset] = @intCast(name.len);
    offset += 1;
    @memcpy(dest[offset .. offset + name.len], name);
    offset += name.len;
    dest[offset] = @intCast(val.len);
    offset += 1;
    @memcpy(dest[offset .. offset + val.len], val);
    offset += val.len;
    return offset;
}
