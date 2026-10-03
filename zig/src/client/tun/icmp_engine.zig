const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub const IcmpEngine = struct {
    pub fn handleIcmp(packet: []u8) bool {
        if (packet.len < 28) return false;
        const version = packet[0] >> 4;

        if (version == 4) {
            const ihl = (packet[0] & 0x0F) * 4;
            if (packet.len < ihl + 8 or packet[9] != 1) return false;
            if (packet[ihl] != 8) return false;

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
        } else if (version == 6) {
            if (packet.len < 48 or packet[6] != 58) return false;
            if (packet[40] != 128) return false;

            var src_ip: [16]u8 = undefined;
            var dst_ip: [16]u8 = undefined;
            @memcpy(&src_ip, packet[8..24]);
            @memcpy(&dst_ip, packet[24..40]);
            @memcpy(packet[8..24], &dst_ip);
            @memcpy(packet[24..40], &src_ip);

            packet[40] = 129;
            packet[42] = 0;
            packet[43] = 0;

            const payload_len = packet.len - 40;
            var sum = ip_checksum.calculateIpv6PseudoChecksum(&dst_ip, &src_ip, 58, @intCast(payload_len));
            var i: usize = 40;
            while (i + 1 < packet.len) : (i += 2) {
                sum += std.mem.readInt(u16, packet[i..][0..2], .big);
            }
            if (i < packet.len) sum += @as(u32, packet[i]) << 8;
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            std.mem.writeInt(u16, packet[42..][0..2], ~@as(u16, @intCast(sum)), .big);
            return true;
        }

        return false;
    }
};
