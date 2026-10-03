const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const crypto = common.crypto;
const ring_buffer = common.ring_buffer;
const types = common.types;

test "protocol header encode and decode all types" {
    const frame_types = [_]protocol.FrameType{
        .connect,
        .data,
        .window_update,
        .close,
        .ping,
        .pong,
        .peer_route,
        .rules_delta,
    };

    for (frame_types) |ft| {
        const hdr = protocol.Header{
            .stream_id = 0x12345678,
            .frame_type = ft,
            .flags = protocol.Flags.EARLY_DATA | protocol.Flags.UDP_MODE,
            .length = 32768,
        };
        var buf: [8]u8 = undefined;
        hdr.encode(&buf);
        const decoded = protocol.Header.decode(&buf);

        try std.testing.expectEqual(hdr.stream_id, decoded.stream_id);
        try std.testing.expectEqual(hdr.frame_type, decoded.frame_type);
        try std.testing.expectEqual(hdr.flags, decoded.flags);
        try std.testing.expectEqual(hdr.length, decoded.length);
    }
}

test "ring buffer wrap around and data integrity" {
    var rb = ring_buffer.RingBuffer(16).init();
    try std.testing.expect(rb.isEmpty());

    const w1 = rb.write("hello");
    try std.testing.expectEqual(@as(usize, 5), w1);
    try std.testing.expectEqual(@as(usize, 5), rb.size);

    var out: [16]u8 = undefined;
    const r1 = rb.read(out[0..3]);
    try std.testing.expectEqual(@as(usize, 3), r1);
    try std.testing.expectEqualStrings("hel", out[0..3]);
    try std.testing.expectEqual(@as(usize, 2), rb.size);

    const w2 = rb.write("1234567890");
    try std.testing.expectEqual(@as(usize, 10), w2);
    try std.testing.expectEqual(@as(usize, 12), rb.size);

    const r2 = rb.read(out[0..12]);
    try std.testing.expectEqual(@as(usize, 12), r2);
    try std.testing.expectEqualStrings("lo1234567890", out[0..12]);
    try std.testing.expect(rb.isEmpty());
}

test "crypto x25519 and chacha20poly1305 roundtrip" {
    const alice = crypto.KeyPair.generate();
    const bob = crypto.KeyPair.generate();

    const shared_alice = try alice.diffieHellman(bob.public_key);
    const shared_bob = try bob.diffieHellman(alice.public_key);
    try std.testing.expectEqualSlices(u8, &shared_alice, &shared_bob);

    const msg = "secret payload mesh";
    var ciphertext: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    const nonce = [_]u8{7} ** 12;
    const ad = "header";

    crypto.encryptAead(&ciphertext, &tag, msg, ad, nonce, shared_alice);

    var decrypted: [msg.len]u8 = undefined;
    try crypto.decryptAead(&decrypted, &ciphertext, tag, ad, nonce, shared_bob);
    try std.testing.expectEqualStrings(msg, &decrypted);
}

test "flow hashing deterministic distribution" {
    const hash1 = types.hashFlow(0x0a000001, 0x0a000002, 12345, 443);
    const hash2 = types.hashFlow(0x0a000001, 0x0a000002, 12345, 443);
    const hash3 = types.hashFlow(0x0a000001, 0x0a000002, 12346, 443);

    try std.testing.expectEqual(hash1, hash2);
    try std.testing.expect(hash1 != hash3);
}
