const std = @import("std");
const crypto = std.crypto;

pub const KeyPair = struct {
    public_key: [32]u8,
    secret_key: [32]u8,

    pub fn generate() KeyPair {
        const pair = crypto.dh.X25519.KeyPair.generate();
        return .{
            .public_key = pair.public_key,
            .secret_key = pair.secret_key,
        };
    }

    pub fn diffieHellman(self: KeyPair, peer_public: [32]u8) ![32]u8 {
        return crypto.dh.X25519.scalarmult(self.secret_key, peer_public);
    }
};

pub fn encryptAead(dest: []u8, tag: *[16]u8, plaintext: []const u8, ad: []const u8, npub: [12]u8, key: [32]u8) void {
    crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(dest, tag, plaintext, ad, npub, key);
}

pub fn decryptAead(dest: []u8, ciphertext: []const u8, tag: [16]u8, ad: []const u8, npub: [12]u8, key: [32]u8) !void {
    try crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(dest, ciphertext, tag, ad, npub, key);
}
