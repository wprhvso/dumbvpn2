const std = @import("std");
const ip_checksum = @import("ip_checksum.zig");

pub const DnsResponder = struct {
    pub fn parseQuery(payload: []const u8, dest: []u8) ?struct { name: []const u8, qtype: u16 } {
        if (payload.len < 12) return null;
        var i: usize = 12;
        var out_i: usize = 0;

        while (i < payload.len and payload[i] != 0) {
            const label_len = payload[i];
            i += 1;
            if (i + label_len > payload.len or out_i + label_len + 1 > dest.len) return null;
            if (out_i > 0) {
                dest[out_i] = '.';
                out_i += 1;
            }
            @memcpy(dest[out_i .. out_i + label_len], payload[i .. i + label_len]);
            out_i += label_len;
            i += label_len;
        }

        if (i + 4 > payload.len) return null;
        i += 1;
        const qtype = std.mem.readInt(u16, payload[i..][0..2], .big);

        return .{
            .name = dest[0..out_i],
            .qtype = qtype,
        };
    }

    pub fn handleDnsPacket(packet: []u8, fake_ip_bytes: [4]u8, reply_buf: []u8) ?usize {
        if (packet.len < 28) return null;
        const ihl = (packet[0] & 0x0F) * 4;
        if (packet.len < ihl + 8 or packet[9] != 17) return null;

        const dst_port = std.mem.readInt(u16, packet[ihl + 2 ..][0..2], .big);
        if (dst_port != 53) return null;

        const src_port = std.mem.readInt(u16, packet[ihl..][0..2], .big);
        const udp_len = std.mem.readInt(u16, packet[ihl + 4 ..][0..2], .big);
        if (packet.len < ihl + udp_len or udp_len < 8 + 12) return null;

        const query = packet[ihl + 8 .. ihl + udp_len];
        if (reply_buf.len < ihl + 8 + query.len + 16) return null;

        @memcpy(reply_buf[0..ihl], packet[0..ihl]);

        var src_ip: [4]u8 = undefined;
        var dst_ip: [4]u8 = undefined;
        @memcpy(&src_ip, reply_buf[12..16]);
        @memcpy(&dst_ip, reply_buf[16..20]);
        @memcpy(reply_buf[12..16], &dst_ip);
        @memcpy(reply_buf[16..20], &src_ip);

        std.mem.writeInt(u16, reply_buf[ihl..][0..2], 53, .big);
        std.mem.writeInt(u16, reply_buf[ihl + 2 ..][0..2], src_port, .big);

        const dns_start = ihl + 8;
        @memcpy(reply_buf[dns_start .. dns_start + query.len], query);

        reply_buf[dns_start + 2] = 0x81;
        reply_buf[dns_start + 3] = 0x80;
        reply_buf[dns_start + 6] = 0x00;
        reply_buf[dns_start + 7] = 0x01;

        var offset = dns_start + query.len;
        reply_buf[offset] = 0xc0;
        reply_buf[offset + 1] = 0x0c;
        offset += 2;

        std.mem.writeInt(u16, reply_buf[offset..][0..2], 0x0001, .big);
        offset += 2;
        std.mem.writeInt(u16, reply_buf[offset..][0..2], 0x0001, .big);
        offset += 2;
        std.mem.writeInt(u32, reply_buf[offset..][0..4], 60, .big);
        offset += 4;
        std.mem.writeInt(u16, reply_buf[offset..][0..2], 4, .big);
        offset += 2;
        @memcpy(reply_buf[offset .. offset + 4], &fake_ip_bytes);
        offset += 4;

        const new_udp_len: u16 = @intCast(offset - ihl);
        std.mem.writeInt(u16, reply_buf[ihl + 4 ..][0..2], new_udp_len, .big);
        reply_buf[ihl + 6] = 0;
        reply_buf[ihl + 7] = 0;

        const total_ip_len: u16 = @intCast(offset);
        std.mem.writeInt(u16, reply_buf[2..4], total_ip_len, .big);
        reply_buf[10] = 0;
        reply_buf[11] = 0;

        const ip_cksum = ip_checksum.calculateChecksum(reply_buf[0..ihl]);
        std.mem.writeInt(u16, reply_buf[10..12], ip_cksum, .big);

        return offset;
    }
};
