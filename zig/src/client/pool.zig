const std = @import("std");

pub const TunnelPool = struct {
    streams: [6]?std.net.Stream = [_]?std.net.Stream{null} ** 6,

    pub fn selectStream(self: *TunnelPool, hash: u32) ?std.net.Stream {
        return self.streams[hash % 6];
    }
};
