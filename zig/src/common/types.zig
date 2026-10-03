const std = @import("std");

pub const StreamId = u32;
pub const PeerId = [32]u8;
pub const VirtualIp = [4]u8;

pub const AddrType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x02,
    ipv6 = 0x03,
    mesh_peer = 0x04,
};

pub const TargetAddress = union(AddrType) {
    ipv4: [4]u8,
    domain: []const u8,
    ipv6: [16]u8,
    mesh_peer: PeerId,
};

pub fn hashFlow(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) u32 {
    var hasher = std.hash.Fnv1a_32.init();
    hasher.update(std.mem.asBytes(&src_ip));
    hasher.update(std.mem.asBytes(&dst_ip));
    hasher.update(std.mem.asBytes(&src_port));
    hasher.update(std.mem.asBytes(&dst_port));
    return hasher.final();
}
