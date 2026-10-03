const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub const TcpEngine = struct {
    pub fn handlePacket(packet: []u8) ?struct { is_syn: bool, is_fin: bool, payload: []const u8, reply_len: usize } {
        if (packet.len < 40) return null;
        const version = packet[0] >> 4;

        if (version == 4) {
            const ihl = (packet[0] & 0x0F) * 4;
            if (packet.len < ihl + 20 or packet[9] != 6) return null;

            const tcp_offset = (packet[ihl + 12] >> 4) * 4;
            const flags = packet[ihl + 13];
            const is_syn = (flags & 0x02) != 0;
            const is_fin = (flags & 0x01) != 0;
            const seq = std.mem.readInt(u32, packet[ihl + 4 ..][0..4], .big);

            if (is_syn) {
                var src_ip: [4]u8 = undefined;
                var dst_ip: [4]u8 = undefined;
                @memcpy(&src_ip, packet[12..16]);
                @memcpy(&dst_ip, packet[16..20]);
                @memcpy(packet[12..16], &dst_ip);
                @memcpy(packet[16..20], &src_ip);

                const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
                const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);
                std.mem.writeInt(u16, packet[ihl..][0..2], dst_port, .big);
                std.mem.writeInt(u16, packet[ihl + 2 ..][0..2], src_port, .big);

                std.mem.writeInt(u32, packet[ihl + 4 ..][0..4], 0x10000000, .big);
                std.mem.writeInt(u32, packet[ihl + 8 ..][0..4], seq + 1, .big);
                packet[ihl + 13] = 0x12;
                std.mem.writeInt(u16, packet[ihl + 14 ..][0..2], 65535, .big);

                packet[10] = 0;
                packet[11] = 0;
                const ip_cksum = ip_checksum.calculateChecksum(packet[0..ihl]);
                std.mem.writeInt(u16, packet[10..][0..2], ip_cksum, .big);

                packet[ihl + 16] = 0;
                packet[ihl + 17] = 0;
                return .{
                    .is_syn = true,
                    .is_fin = false,
                    .payload = &.{},
                    .reply_len = ihl + tcp_offset,
                };
            }

            const data_start = ihl + tcp_offset;
            const payload = if (data_start < packet.len) packet[data_start..] else &[_]u8{};
            return .{
                .is_syn = false,
                .is_fin = is_fin,
                .payload = payload,
                .reply_len = 0,
            };
        } else if (version == 6) {
            if (packet.len < 60 or packet[6] != 6) return null;
            const ihl: usize = 40;
            const tcp_offset = (packet[ihl + 12] >> 4) * 4;
            const flags = packet[ihl + 13];
            const is_syn = (flags & 0x02) != 0;
            const is_fin = (flags & 0x01) != 0;
            const seq = std.mem.readInt(u32, packet[ihl + 4 ..][0..4], .big);

            if (is_syn) {
                var src_ip: [16]u8 = undefined;
                var dst_ip: [16]u8 = undefined;
                @memcpy(&src_ip, packet[8..24]);
                @memcpy(&dst_ip, packet[24..40]);
                @memcpy(packet[8..24], &dst_ip);
                @memcpy(packet[24..40], &src_ip);

                const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
                const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);
                std.mem.writeInt(u16, packet[ihl..][0..2], dst_port, .big);
                std.mem.writeInt(u16, packet[ihl + 2 ..][0..2], src_port, .big);

                std.mem.writeInt(u32, packet[ihl + 4 ..][0..4], 0x20000000, .big);
                std.mem.writeInt(u32, packet[ihl + 8 ..][0..4], seq + 1, .big);
                packet[ihl + 13] = 0x12;
                std.mem.writeInt(u16, packet[ihl + 14 ..][0..2], 65535, .big);

                packet[ihl + 16] = 0;
                packet[ihl + 17] = 0;

                var sum = ip_checksum.calculateIpv6PseudoChecksum(&dst_ip, &src_ip, 6, @intCast(tcp_offset));
                var i: usize = ihl;
                while (i + 1 < ihl + tcp_offset) : (i += 2) {
                    sum += std.mem.readInt(u16, packet[i..][0..2], .big);
                }
                while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
                std.mem.writeInt(u16, packet[ihl + 16 ..][0..2], ~@as(u16, @intCast(sum)), .big);

                return .{
                    .is_syn = true,
                    .is_fin = false,
                    .payload = &.{},
                    .reply_len = ihl + tcp_offset,
                };
            }

            const data_start = ihl + tcp_offset;
            const payload = if (data_start < packet.len) packet[data_start..] else &[_]u8{};
            return .{
                .is_syn = false,
                .is_fin = is_fin,
                .payload = payload,
                .reply_len = 0,
            };
        }

        return null;
    }
};
