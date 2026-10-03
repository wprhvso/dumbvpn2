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
const flow_table = client.flow_table;
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

test "preservation of src and dst ip addresses after syn-ack" {
    var syn_pkt = [_]u8{
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        10,   88,   0,    2,    198,  18,   0,    42, // src: 10.88.0.2, dst: 198.18.0.42
        0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x05, // src port: 12345, dst port: 443
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    };
    const res = tcp_engine.TcpEngine.handlePacket(&syn_pkt);
    try std.testing.expect(res != null);
    try std.testing.expect(res.?.is_syn);
    // Original addresses must not be swapped in the parsed result:
    try std.testing.expectEqual([4]u8{ 10, 88, 0, 2 }, res.?.src_ip);
    try std.testing.expectEqual([4]u8{ 198, 18, 0, 42 }, res.?.dst_ip);
    try std.testing.expectEqual(@as(u16, 12345), res.?.src_port);
    try std.testing.expectEqual(@as(u16, 443), res.?.dst_port);
}

test "two concurrent tcp flows without crosstalk" {
    var table = flow_table.FlowTable.init(std.testing.allocator);
    defer table.deinit();

    // Flow 1
    const f1 = try table.getOrCreate(
        [4]u8{ 10, 88, 0, 2 },
        [4]u8{ 198, 18, 0, 3 },
        50001,
        443,
        "icanhazip.com",
        1000,
    );
    try std.testing.expectEqual(@as(u32, 1), f1.stream_id);
    try std.testing.expectEqual(@as(u32, 1001), f1.client_seq);
    try std.testing.expectEqualStrings("icanhazip.com", f1.getDomain());

    // Flow 2
    const f2 = try table.getOrCreate(
        [4]u8{ 10, 88, 0, 2 },
        [4]u8{ 198, 18, 0, 4 },
        50002,
        443,
        "api.github.com",
        2000,
    );
    try std.testing.expectEqual(@as(u32, 2), f2.stream_id);
    try std.testing.expectEqual(@as(u32, 2001), f2.client_seq);
    try std.testing.expectEqualStrings("api.github.com", f2.getDomain());

    // Modify Flow 1 state
    f1.server_seq += 500;
    f1.client_seq += 100;

    // Verify Flow 2 is untouched
    const lookup_f2 = table.lookupByKey([4]u8{ 10, 88, 0, 2 }, [4]u8{ 198, 18, 0, 4 }, 50002, 443);
    try std.testing.expect(lookup_f2 != null);
    try std.testing.expectEqual(@as(u32, 2001), lookup_f2.?.client_seq);
    try std.testing.expectEqual(@as(u32, 0x10000001), lookup_f2.?.server_seq);

    // Verify lookup by stream
    const s1 = table.lookupByStream(1);
    try std.testing.expect(s1 != null);
    try std.testing.expectEqualStrings("icanhazip.com", s1.?.getDomain());

    const s2 = table.lookupByStream(2);
    try std.testing.expect(s2 != null);
    try std.testing.expectEqualStrings("api.github.com", s2.?.getDomain());
}

test "partial and coalesced tunnel frames parsing" {
    var parser = protocol.FrameParser.init();

    // Prepare two frames:
    var f1_buf: [8 + 5]u8 = undefined;
    const h1 = protocol.Header{ .stream_id = 1, .frame_type = .data, .flags = 0, .length = 5 };
    h1.encode(f1_buf[0..8]);
    @memcpy(f1_buf[8..13], "hello");

    var f2_buf: [8 + 6]u8 = undefined;
    const h2_frame = protocol.Header{ .stream_id = 2, .frame_type = .data, .flags = 0, .length = 6 };
    h2_frame.encode(f2_buf[0..8]);
    @memcpy(f2_buf[8..14], "world!");

    // Partial test: Append 4 bytes (half of header 1)
    try parser.append(f1_buf[0..4]);
    try std.testing.expect(parser.next() == null);

    // Append next 6 bytes (rest of header 1 + 2 bytes of payload)
    try parser.append(f1_buf[4..10]);
    try std.testing.expect(parser.next() == null);

    // Coalesced test: Append rest of frame 1 AND all of frame 2
    try parser.append(f1_buf[10..13]);
    try parser.append(&f2_buf);

    // Now both frames must be parsed in sequence:
    const parsed1 = parser.next();
    try std.testing.expect(parsed1 != null);
    try std.testing.expectEqual(@as(u32, 1), parsed1.?.header.stream_id);
    try std.testing.expectEqual(protocol.FrameType.data, parsed1.?.header.frame_type);
    try std.testing.expectEqualStrings("hello", parsed1.?.payload);

    const parsed2 = parser.next();
    try std.testing.expect(parsed2 != null);
    try std.testing.expectEqual(@as(u32, 2), parsed2.?.header.stream_id);
    try std.testing.expectEqual(protocol.FrameType.data, parsed2.?.header.frame_type);
    try std.testing.expectEqualStrings("world!", parsed2.?.payload);

    // No more frames
    try std.testing.expect(parser.next() == null);
}

test "connect frame generation with exact resolved domain" {
    var dns = fake_ip.FakeIpEngine.init(std.testing.allocator);
    defer dns.deinit();

    const fake_u32_github = try dns.allocate("api.github.com");
    const fake_u32_example = try dns.allocate("example.com");

    const resolved_github = dns.lookup(fake_u32_github);
    try std.testing.expect(resolved_github != null);
    try std.testing.expectEqualStrings("api.github.com", resolved_github.?);

    const resolved_example = dns.lookup(fake_u32_example);
    try std.testing.expect(resolved_example != null);
    try std.testing.expectEqualStrings("example.com", resolved_example.?);

    // Build MMX CONNECT frame for api.github.com:443
    var connect_buf: [64]u8 = undefined;
    connect_buf[0] = 0x02; // domain type
    connect_buf[1] = @intCast(resolved_github.?.len);
    @memcpy(connect_buf[2 .. 2 + resolved_github.?.len], resolved_github.?);
    std.mem.writeInt(u16, connect_buf[2 + resolved_github.?.len ..][0..2], 443, .big);

    // Verify connect payload parsing
    try std.testing.expectEqual(@as(u8, 0x02), connect_buf[0]);
    try std.testing.expectEqual(@as(u8, @intCast("api.github.com".len)), connect_buf[1]);
    try std.testing.expectEqualStrings("api.github.com", connect_buf[2 .. 2 + connect_buf[1]]);
    const port = std.mem.readInt(u16, connect_buf[2 + connect_buf[1] ..][0..2], .big);
    try std.testing.expectEqual(@as(u16, 443), port);
}

test "upstream response bytes routed to correct fake flow" {
    var table = flow_table.FlowTable.init(std.testing.allocator);
    defer table.deinit();

    _ = try table.getOrCreate([4]u8{ 10, 88, 0, 2 }, [4]u8{ 198, 18, 0, 3 }, 50001, 443, "icanhazip.com", 1000);
    _ = try table.getOrCreate([4]u8{ 10, 88, 0, 2 }, [4]u8{ 198, 18, 0, 4 }, 50002, 443, "api.github.com", 2000);

    // Simulated upstream reply for stream 2 (api.github.com)
    const upstream_payload = "HTTP/1.1 200 OK\r\n\r\nhello";
    const flow2 = table.lookupByStream(2);
    try std.testing.expect(flow2 != null);

    var tcp_pkt_buf: [512]u8 = undefined;
    const pkt_len = tcp_engine.buildTcpPacket(
        flow2.?.fake_ip,
        flow2.?.client_ip,
        flow2.?.target_port,
        flow2.?.client_port,
        flow2.?.server_seq,
        flow2.?.client_seq,
        0x18,
        upstream_payload,
        &tcp_pkt_buf,
    );
    try std.testing.expect(pkt_len != null);

    const pkt = tcp_pkt_buf[0..pkt_len.?];
    // Check IPv4 src/dst
    try std.testing.expectEqual([4]u8{ 198, 18, 0, 4 }, pkt[12..16].*); // Fake IP of flow 2!
    try std.testing.expectEqual([4]u8{ 10, 88, 0, 2 }, pkt[16..20].*);  // Client IP
    // Check TCP ports
    const src_port = std.mem.readInt(u16, pkt[20..22], .big);
    const dst_port = std.mem.readInt(u16, pkt[22..24], .big);
    try std.testing.expectEqual(@as(u16, 443), src_port);
    try std.testing.expectEqual(@as(u16, 50002), dst_port);
    // Check TCP payload
    try std.testing.expectEqualStrings(upstream_payload, pkt[40..]);
}
