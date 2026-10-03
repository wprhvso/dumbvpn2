const std = @import("std");

pub const RqliteClient = struct {
    endpoint: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) RqliteClient {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
        };
    }

    pub fn logAccess(self: *RqliteClient, client_name: []const u8, bytes_in: usize, bytes_out: usize) !void {
        _ = self;
        _ = client_name;
        _ = bytes_in;
        _ = bytes_out;
    }
};
