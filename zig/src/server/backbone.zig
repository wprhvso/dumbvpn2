const std = @import("std");
const common = @import("common");
const types = common.types;

pub const HubConnection = struct {
    hub_id: u32,
    socket: std.net.Stream,
    connected: bool,

    pub fn relay(self: *HubConnection, frame_bytes: []const u8) !void {
        if (!self.connected) return error.Disconnected;
        try self.socket.writeAll(frame_bytes);
    }
};

pub const Backbone = struct {
    hubs: std.ArrayList(HubConnection),

    pub fn init(allocator: std.mem.Allocator) Backbone {
        return .{
            .hubs = std.ArrayList(HubConnection).init(allocator),
        };
    }

    pub fn deinit(self: *Backbone) void {
        self.hubs.deinit();
    }
};
