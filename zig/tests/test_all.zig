const std = @import("std");
const common = @import("common");
const server = @import("server");
const client = @import("client");

const protocol = common.protocol;
const crypto = common.crypto;
const ring_buffer = common.ring_buffer;
const types = common.types;

const ws = server.ws_listener;
const fake_ip = client.fake_ip;
const tcp_engine = client.tcp_engine;
const icmp_engine = client.icmp_engine;
const udp_engine = client.udp_engine;
const ip_checksum = client.ip_checksum;

test "protocol header encode decode" {
    const hdr = protocol.Header{
        .stream_id = 42,
        .frame_type = .data,
        .flags = protocol.Flags.FIN,
        .length = 1024,
    };
    var buf: [8]u8 = undefined;
    hdr.encode(&buf);
    const decoded = protocol.Header.decode(&buf);
    try std.testing.expectEqual(hdr.stream_id, decoded.stream_id);
    try std.testing.expectEqual(hdr.frame_type, decoded.frame_type);
    try std.testing.expectEqual(hdr.flags, decoded.flags);
    try std.testing.expectEqual(hdr.length, decoded.length);
}

test "ring buffer operations and wrap around" {
    var rb = ring_buffer.RingBuffer(16).init();
    try std.testing.expect(rb.isEmpty());

    const w1 = rb.write("12345678");
    try std.testing.expectEqual(@as(usize, 8), w1);
    try std.testing.expectEqual(@as(usize, 8), rb.size);

    var out: [8]u8 = undefined;
    const r1 = rb.read(&out);
    try std.testing.expectEqual(@as(usize, 8), r1);
    try std.testing.expectEqualStrings("12345678", &out);
    try std.testing.expect(rb.isEmpty());
}

test "fake ip allocation and consistent reverse lookup" {
    var engine = fake_ip.FakeIpEngine.init(std.testing.allocator);
    defer engine.deinit();

    const ip_google = try engine.allocate("google.com");
    const ip_google_cached = try engine.allocate("google.com");

    try std.testing.expectEqual(ip_google, ip_google_cached);

    const domain = engine.lookup(ip_google);
    try std.testing.expect(domain != null);
    try std.testing.expectEqualStrings("google.com", domain.?);
}

test "ip checksum calculation" {
    const raw_hdr = [_]u8{ 0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c };
    const cksum = ip_checksum.calculateChecksum(&raw_hdr);
    try std.testing.expect(cksum != 0);
}

test "icmp echo request to reply translation (IPv4)" {
    var icmp_pkt = [_]u8{
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        10,   88,   0,    2,    10,   88,   0,    1,
        8,    0,    0,    0,    0,    1,    0,    1,
    };

    const handled = icmp_engine.IcmpEngine.handleIcmp(&icmp_pkt);
    try std.testing.expect(handled);
    try std.testing.expectEqual(@as(u8, 0), icmp_pkt[20]);
    try std.testing.expectEqual(@as(u8, 10), icmp_pkt[12]);
    try std.testing.expectEqual(@as(u8, 1), icmp_pkt[15]);
}

test "icmpv6 echo request to reply translation (IPv6)" {
    var icmpv6_pkt = [_]u8{
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 58, 64, // IPv6 header, Next Header 58 (ICMPv6)
        0xfd, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // Src: fd88::2
        0xfd, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Dst: fd88::1
        128,  0,    0, 0, 0, 1, 0, 1, // Echo Request (type 128)
    };

    const handled = icmp_engine.IcmpEngine.handleIcmp(&icmpv6_pkt);
    try std.testing.expect(handled);
    try std.testing.expectEqual(@as(u8, 129), icmpv6_pkt[40]); // Echo Reply (type 129)
    try std.testing.expectEqual(@as(u8, 1), icmpv6_pkt[23]); // Swapped Src: fd88::1
}

test "tcp syn to syn-ack translation (Dual-Stack IPv4 & IPv6)" {
    // IPv4 SYN:
    var tcp4_pkt = [_]u8{
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        10,   88,   0,    2,    198,  18,   0,    42,
        0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    };
    const res4 = tcp_engine.TcpEngine.handlePacket(&tcp4_pkt);
    try std.testing.expect(res4 != null);
    try std.testing.expect(res4.?.is_syn);
    try std.testing.expectEqual(@as(u8, 0x12), tcp4_pkt[33]);

    // IPv6 SYN:
    var tcp6_pkt = [_]u8{
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 6, 64, // IPv6 header, Next Header 6 (TCP), len 20
        0xfd, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // Src: fd88::2
        0xfd, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Dst: fd88::1
        0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x05, // Src 12345, Dst 443, Seq 5
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, // TCP Offset 5, SYN
        0x00, 0x00, 0x00, 0x00,
    };
    const res6 = tcp_engine.TcpEngine.handlePacket(&tcp6_pkt);
    try std.testing.expect(res6 != null);
    try std.testing.expect(res6.?.is_syn);
    try std.testing.expectEqual(@as(u8, 0x12), tcp6_pkt[53]); // SYN-ACK flag in IPv6 TCP packet
}
