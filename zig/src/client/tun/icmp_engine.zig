const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub const IcmpEngine = struct {
    pub fn handleIcmp(packet: []u8) bool {
        if (packet.len < 28) return false;
        const version_ihl = packet[0];
        const ihl = (version_ihl & 0x0F) * 4;
        if (packet.len < ihl + 8) return false;
        if (packet[9] != 1) return false;

        const icmp_type = packet[ihl];
        if (icmp_type != 8) return false;

        var src_ip: [4]u8 = undefined;
        var dst_ip: [4]u8 = undefined;
        @memcpy(&src_ip, packet[12..16]);
        @memcpy(&dst_ip, packet[16..20]);
        @memcpy(packet[12..16], &dst_ip);
        @memcpy(packet[16..20], &src_ip);

        packet[10] = 0;
        packet[11] = 0;
        const ip_cksum = ip_checksum.calculateChecksum(packet[0..ihl]);
        std.mem.writeInt(u16, packet[10..][0..2], ip_cksum, .big);

        packet[ihl] = 0;
        packet[ihl + 2] = 0;
        packet[ihl + 3] = 0;
        const icmp_cksum = ip_checksum.calculateChecksum(packet[ihl..packet.len]);
        std.mem.writeInt(u16, packet[ihl + 2 ..][0..2], icmp_cksum, .big);

        return true;
    }
};
