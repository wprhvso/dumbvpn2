const std = @import("std");
const common = @import("common");
const protocol = common.protocol;

test "header encode decode" {
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
