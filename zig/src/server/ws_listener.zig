const std = @import("std");

pub fn unmask(payload: []u8, mask: [4]u8) void {
    var i: usize = 0;
    while (i + 4 <= payload.len) : (i += 4) {
        const chunk: *[4]u8 = @ptrCast(payload[i .. i + 4]);
        chunk[0] ^= mask[0];
        chunk[1] ^= mask[1];
        chunk[2] ^= mask[2];
        chunk[3] ^= mask[3];
    }
    while (i < payload.len) : (i += 1) {
        payload[i] ^= mask[i % 4];
    }
}

pub fn parseHeader(src: []const u8) ?struct { len: usize, mask: ?[4]u8, header_size: usize } {
    if (src.len < 2) return null;
    const masked = (src[1] & 0x80) != 0;
    var len: usize = src[1] & 0x7F;
    var offset: usize = 2;
    if (len == 126) {
        if (src.len < 4) return null;
        len = std.mem.readInt(u16, src[2..][0..2], .big);
        offset = 4;
    } else if (len == 127) {
        if (src.len < 10) return null;
        len = @intCast(std.mem.readInt(u64, src[2..][0..8], .big));
        offset = 10;
    }
    var mask_key: ?[4]u8 = null;
    if (masked) {
        if (src.len < offset + 4) return null;
        mask_key = src[offset..][0..4].*;
        offset += 4;
    }
    return .{ .len = len, .mask = mask_key, .header_size = offset };
}
