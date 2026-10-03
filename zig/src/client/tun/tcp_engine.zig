const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub const TcpEngine = struct {
    pub fn handlePacket(packet: []u8) ?struct { is_syn: bool, is_fin: bool, payload: []const u8, reply_len: usize } {
        if (packet.len < 40) return null;
        const ihl = (packet[0] & 0x0F) * 4;
        if (packet.len < ihl + 20) return null;
        if (packet[9] != 6) return null;

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
            std.mem.writeInt(u16, packet[10..12], ip_cksum, .big);

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
    }
};
