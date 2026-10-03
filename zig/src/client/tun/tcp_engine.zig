const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub fn buildTcpPacket(
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: []const u8,
    buf: []u8,
) ?usize {
    const ihl: usize = 20;
    const tcp_hdr_len: usize = 20;
    const total_len: usize = ihl + tcp_hdr_len + payload.len;
    if (buf.len < total_len) return null;

    buf[0] = 0x45;
    buf[1] = 0x00;
    std.mem.writeInt(u16, buf[2..4], @intCast(total_len), .big);
    buf[4] = 0x00;
    buf[5] = 0x01;
    buf[6] = 0x40;
    buf[7] = 0x00;
    buf[8] = 64;
    buf[9] = 6;
    buf[10] = 0;
    buf[11] = 0;
    @memcpy(buf[12..16], &src_ip);
    @memcpy(buf[16..20], &dst_ip);

    const ip_ck = ip_checksum.calculateChecksum(buf[0..ihl]);
    std.mem.writeInt(u16, buf[10..12], ip_ck, .big);

    std.mem.writeInt(u16, buf[ihl..][0..2], src_port, .big);
    std.mem.writeInt(u16, buf[ihl + 2 ..][0..2], dst_port, .big);
    std.mem.writeInt(u32, buf[ihl + 4 ..][0..4], seq, .big);
    std.mem.writeInt(u32, buf[ihl + 8 ..][0..4], ack, .big);
    buf[ihl + 12] = (tcp_hdr_len / 4) << 4;
    buf[ihl + 13] = flags;
    std.mem.writeInt(u16, buf[ihl + 14 ..][0..2], 65535, .big);
    buf[ihl + 16] = 0;
    buf[ihl + 17] = 0;
    buf[ihl + 18] = 0;
    buf[ihl + 19] = 0;

    if (payload.len > 0) {
        @memcpy(buf[ihl + tcp_hdr_len .. total_len], payload);
    }

    var sum: u32 = 0;
    var i: usize = 12;
    while (i < 20) : (i += 2) {
        sum += std.mem.readInt(u16, buf[i..][0..2], .big);
    }
    sum += 6;
    sum += @as(u32, @intCast(tcp_hdr_len + payload.len));

    i = ihl;
    while (i + 1 < total_len) : (i += 2) {
        sum += std.mem.readInt(u16, buf[i..][0..2], .big);
    }
    if (i < total_len) {
        sum += @as(u32, buf[i]) << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const tcp_ck = ~@as(u16, @intCast(sum));
    std.mem.writeInt(u16, buf[ihl + 16 ..][0..2], tcp_ck, .big);

    return total_len;
}

pub const TcpEngine = struct {
    pub fn handlePacket(packet: []u8) ?struct {
        is_syn: bool,
        is_fin: bool,
        payload: []const u8,
        reply_len: usize,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    } {
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
            const ack = std.mem.readInt(u32, packet[ihl + 8 ..][0..4], .big);

            const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
            const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);

            if (is_syn) {
                var src_ip: [4]u8 = undefined;
                var dst_ip: [4]u8 = undefined;
                @memcpy(&src_ip, packet[12..16]);
                @memcpy(&dst_ip, packet[16..20]);
                @memcpy(packet[12..16], &dst_ip);
                @memcpy(packet[16..20], &src_ip);

                std.mem.writeInt(u16, packet[2..4], 40, .big);

                std.mem.writeInt(u16, packet[ihl..][0..2], dst_port, .big);
                std.mem.writeInt(u16, packet[ihl + 2 ..][0..2], src_port, .big);

                std.mem.writeInt(u32, packet[ihl + 4 ..][0..4], 0x10000000, .big);
                std.mem.writeInt(u32, packet[ihl + 8 ..][0..4], seq + 1, .big);
                packet[ihl + 12] = 0x50;
                packet[ihl + 13] = 0x12;
                std.mem.writeInt(u16, packet[ihl + 14 ..][0..2], 65535, .big);

                packet[10] = 0;
                packet[11] = 0;
                const ip_cksum = ip_checksum.calculateChecksum(packet[0..ihl]);
                std.mem.writeInt(u16, packet[10..12], ip_cksum, .big);

                packet[ihl + 16] = 0;
                packet[ihl + 17] = 0;

                var sum: u32 = 0;
                var j: usize = 12;
                while (j < 20) : (j += 2) {
                    sum += std.mem.readInt(u16, packet[j..][0..2], .big);
                }
                sum += 6;
                sum += 20;

                j = ihl;
                while (j < ihl + 20) : (j += 2) {
                    sum += std.mem.readInt(u16, packet[j..][0..2], .big);
                }
                while ((sum >> 16) != 0) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                std.mem.writeInt(u16, packet[ihl + 16 ..][0..2], ~@as(u16, @intCast(sum)), .big);

                return .{
                    .is_syn = true,
                    .is_fin = false,
                    .payload = &.{},
                    .reply_len = 40,
                    .src_port = src_port,
                    .dst_port = dst_port,
                    .seq = seq,
                    .ack = ack,
                };
            }

            const data_start = ihl + tcp_offset;
            const payload = if (data_start < packet.len) packet[data_start..] else &[_]u8{};
            return .{
                .is_syn = false,
                .is_fin = is_fin,
                .payload = payload,
                .reply_len = 0,
                .src_port = src_port,
                .dst_port = dst_port,
                .seq = seq,
                .ack = ack,
            };
        } else if (version == 6) {
            if (packet.len < 60 or packet[6] != 6) return null;
            const ihl: usize = 40;
            const tcp_offset = (packet[ihl + 12] >> 4) * 4;
            const flags = packet[ihl + 13];
            const is_syn = (flags & 0x02) != 0;
            const is_fin = (flags & 0x01) != 0;
            const seq = std.mem.readInt(u32, packet[ihl + 4 ..][0..4], .big);
            const ack = std.mem.readInt(u32, packet[ihl + 8 ..][0..4], .big);
            const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
            const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);

            if (is_syn) {
                var src_ip: [16]u8 = undefined;
                var dst_ip: [16]u8 = undefined;
                @memcpy(&src_ip, packet[8..24]);
                @memcpy(&dst_ip, packet[24..40]);
                @memcpy(packet[8..24], &dst_ip);
                @memcpy(packet[24..40], &src_ip);

                std.mem.writeInt(u16, packet[4..6], 20, .big);

                std.mem.writeInt(u16, packet[ihl..][0..2], dst_port, .big);
                std.mem.writeInt(u16, packet[ihl + 2 ..][0..2], src_port, .big);

                std.mem.writeInt(u32, packet[ihl + 4 ..][0..4], 0x20000000, .big);
                std.mem.writeInt(u32, packet[ihl + 8 ..][0..4], seq + 1, .big);
                packet[ihl + 12] = 0x50;
                packet[ihl + 13] = 0x12;
                std.mem.writeInt(u16, packet[ihl + 14 ..][0..2], 65535, .big);

                packet[ihl + 16] = 0;
                packet[ihl + 17] = 0;

                var sum = ip_checksum.calculateIpv6PseudoChecksum(&dst_ip, &src_ip, 6, 20);
                var j: usize = ihl;
                while (j < ihl + 20) : (j += 2) {
                    sum += std.mem.readInt(u16, packet[j..][0..2], .big);
                }
                while ((sum >> 16) != 0) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                std.mem.writeInt(u16, packet[ihl + 16 ..][0..2], ~@as(u16, @intCast(sum)), .big);

                return .{
                    .is_syn = true,
                    .is_fin = false,
                    .payload = &.{},
                    .reply_len = 60,
                    .src_port = src_port,
                    .dst_port = dst_port,
                    .seq = seq,
                    .ack = ack,
                };
            }

            const data_start = ihl + tcp_offset;
            const payload = if (data_start < packet.len) packet[data_start..] else &[_]u8{};
            return .{
                .is_syn = false,
                .is_fin = is_fin,
                .payload = payload,
                .reply_len = 0,
                .src_port = src_port,
                .dst_port = dst_port,
                .seq = seq,
                .ack = ack,
            };
        }

        return null;
    }
};
