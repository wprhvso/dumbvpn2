const std = @import("std");
const common = @import("common");
const protocol = common.protocol;
const types = common.types;

pub const StreamSession = struct {
    stream_id: types.StreamId,
    target_fd: ?std.posix.fd_t = null,
    sent_offset: u64 = 0,
    ack_offset: u64 = 0,
    parked: bool = false,
};

pub const StreamRouter = struct {
    sessions: std.AutoHashMap(types.StreamId, StreamSession),

    pub fn init(allocator: std.mem.Allocator) StreamRouter {
        return .{
            .sessions = std.AutoHashMap(types.StreamId, StreamSession).init(allocator),
        };
    }

    pub fn deinit(self: *StreamRouter) void {
        self.sessions.deinit();
    }

    pub fn routeFrame(self: *StreamRouter, hdr: protocol.Header, payload: []const u8) !void {
        _ = self;
        _ = hdr;
        _ = payload;
    }
};
