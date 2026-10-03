const std = @import("std");

pub fn calculateChecksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        sum += std.mem.readInt(u16, header[i..][0..2], .big);
    }
    if (i < header.len) {
        sum += @as(u32, header[i]) << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum));
}
