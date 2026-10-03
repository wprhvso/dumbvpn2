const std = @import("std");

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

        if (i >= payload.len or payload[i] != 0) return null;
        i += 1;
        if (i + 4 > payload.len) return null;
        const qtype = std.mem.readInt(u16, payload[i..][0..2], .big);

        return .{
            .name = dest[0..out_i],
            .qtype = qtype,
        };
    }

    pub fn findQuestionEnd(payload: []const u8) ?usize {
        if (payload.len < 12) return null;
        var i: usize = 12;
        while (i < payload.len and payload[i] != 0) {
            const label_len = payload[i];
            i += 1 + label_len;
        }
        if (i >= payload.len or payload[i] != 0) return null;
        i += 1;
        if (i + 4 > payload.len) return null;
        i += 4;
        return i;
    }

    pub fn buildDnsPayload(query: []const u8, fake_ip_bytes: [4]u8, resp_buf: []u8) ?usize {
        const q_end = findQuestionEnd(query) orelse return null;
        if (resp_buf.len < q_end + 16) return null;

        @memcpy(resp_buf[0..q_end], query[0..q_end]);

        resp_buf[2] = 0x81;
        resp_buf[3] = 0x80;
        resp_buf[4] = 0x00;
        resp_buf[5] = 0x01;
        resp_buf[6] = 0x00;
        resp_buf[7] = 0x01;
        resp_buf[8] = 0x00;
        resp_buf[9] = 0x00;
        resp_buf[10] = 0x00;
        resp_buf[11] = 0x00;

        var offset = q_end;
        resp_buf[offset] = 0xc0;
        resp_buf[offset + 1] = 0x0c;
        offset += 2;

        std.mem.writeInt(u16, resp_buf[offset..][0..2], 0x0001, .big);
        offset += 2;
        std.mem.writeInt(u16, resp_buf[offset..][0..2], 0x0001, .big);
        offset += 2;

        std.mem.writeInt(u32, resp_buf[offset..][0..4], 60, .big);
        offset += 4;

        std.mem.writeInt(u16, resp_buf[offset..][0..2], 4, .big);
        offset += 2;

        @memcpy(resp_buf[offset .. offset + 4], &fake_ip_bytes);
        offset += 4;

        return offset;
    }
};
