const std = @import("std");

pub fn unmask(payload: []u8, mask_key: [4]u8) void {
    var i: usize = 0;
    while (i + 4 <= payload.len) : (i += 4) {
        const chunk: *[4]u8 = @ptrCast(payload[i .. i + 4]);
        chunk[0] ^= mask_key[0];
        chunk[1] ^= mask_key[1];
        chunk[2] ^= mask_key[2];
        chunk[3] ^= mask_key[3];
    }
    while (i < payload.len) : (i += 1) {
        payload[i] ^= mask_key[i % 4];
    }
}

pub fn wrapWsBinaryMasked(payload: []const u8, dest: []u8) usize {
    var offset: usize = 0;
    dest[0] = 0x82;
    const mask = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

    if (payload.len < 126) {
        dest[1] = 0x80 | @as(u8, @intCast(payload.len));
        offset = 2;
    } else if (payload.len <= 65535) {
        dest[1] = 0x80 | 126;
        std.mem.writeInt(u16, dest[2..4], @intCast(payload.len), .big);
        offset = 4;
    } else {
        dest[1] = 0x80 | 127;
        std.mem.writeInt(u64, dest[2..10], @intCast(payload.len), .big);
        offset = 10;
    }

    @memcpy(dest[offset .. offset + 4], &mask);
    offset += 4;

    for (payload, 0..) |b, i| {
        dest[offset + i] = b ^ mask[i % 4];
    }
    return offset + payload.len;
}

pub fn wrapWsBinaryServer(payload: []const u8, dest: []u8) usize {
    var offset: usize = 0;
    dest[0] = 0x82;

    if (payload.len < 126) {
        dest[1] = @intCast(payload.len);
        offset = 2;
    } else if (payload.len <= 65535) {
        dest[1] = 126;
        std.mem.writeInt(u16, dest[2..4], @intCast(payload.len), .big);
        offset = 4;
    } else {
        dest[1] = 127;
        std.mem.writeInt(u64, dest[2..10], @intCast(payload.len), .big);
        offset = 10;
    }

    @memcpy(dest[offset .. offset + payload.len], payload);
    return offset + payload.len;
}

pub fn unwrapWs(src: []u8) ?[]u8 {
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
    const payload = src[offset .. @min(src.len, offset + len)];
    if (mask_key) |m| {
        for (payload, 0..) |*b, i| {
            b.* ^= m[i % 4];
        }
    }
    return payload;
}
