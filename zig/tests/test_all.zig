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

    const w2 = rb.write("abcdefghijklmnop");
    try std.testing.expectEqual(@as(usize, 16), w2);
    try std.testing.expect(rb.isFull());

    var out2: [16]u8 = undefined;
    const r2 = rb.read(&out2);
    try std.testing.expectEqual(@as(usize, 16), r2);
    try std.testing.expectEqualStrings("abcdefghijklmnop", &out2);
}

test "crypto x25519 and chacha20poly1305 roundtrip" {
    const alice = crypto.KeyPair.generate();
    const bob = crypto.KeyPair.generate();

    const shared1 = try alice.diffieHellman(bob.public_key);
    const shared2 = try bob.diffieHellman(alice.public_key);
    try std.testing.expectEqualSlices(u8, &shared1, &shared2);

    const plaintext = "payload";
    var ciphertext: [7]u8 = undefined;
    var tag: [16]u8 = undefined;
    const npub = [_]u8{7} ** 12;
    crypto.encryptAead(&ciphertext, &tag, plaintext, "", npub, shared1);

    var decrypted: [7]u8 = undefined;
    try crypto.decryptAead(&decrypted, &ciphertext, tag, "", npub, shared2);
    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "fake ip allocation and consistent reverse lookup" {
    var engine = fake_ip.FakeIpEngine.init(std.testing.allocator);
    defer engine.deinit();

    const ip_google = try engine.allocate("google.com");
    const ip_youtube = try engine.allocate("youtube.com");
    const ip_google_cached = try engine.allocate("google.com");

    try std.testing.expectEqual(ip_google, ip_google_cached);
    try std.testing.expect(ip_google != ip_youtube);

    const domain = engine.lookup(ip_google);
    try std.testing.expect(domain != null);
    try std.testing.expectEqualStrings("google.com", domain.?);
}

test "websocket framing and unmasking" {
    var payload = [_]u8{ 'A', 'B', 'C', 'D', 'E' };
    const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };

    for (&payload, 0..) |*b, idx| {
        b.* ^= mask[idx % 4];
    }
    ws.unmask(&payload, mask);
    try std.testing.expectEqualStrings("ABCDE", &payload);

    const raw_header = [_]u8{ 0x82, 0x85, 0x11, 0x22, 0x33, 0x44 };
    const parsed = ws.parseHeader(&raw_header);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(@as(usize, 5), parsed.?.len);
    try std.testing.expectEqual(mask, parsed.?.mask.?);
}

test "flow hashing determinism" {
    const hash1 = types.hashFlow(0x7F000001, 0x08080808, 12345, 443);
    const hash2 = types.hashFlow(0x7F000001, 0x08080808, 12345, 443);
    const hash3 = types.hashFlow(0x7F000001, 0x08080808, 12346, 443);

    try std.testing.expectEqual(hash1, hash2);
    try std.testing.expect(hash1 != hash3);
}

test "tcp engine packet validation" {
    const valid_packet = [_]u8{ 0x45, 0x00, 0x00, 0x28 } ++ ([_]u8{0} ** 20);
    const result = tcp_engine.TcpEngine.processPacket(&valid_packet);
    try std.testing.expect(result != null);

    const invalid_packet = [_]u8{ 0x45, 0x00 };
    const invalid_result = tcp_engine.TcpEngine.processPacket(&invalid_packet);
    try std.testing.expect(invalid_result == null);
}
