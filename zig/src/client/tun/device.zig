const std = @import("std");

pub const TunDevice = struct {
    fd: std.os.fd_t,

    pub fn readPacket(self: TunDevice, buf: []u8) !usize {
        return std.os.read(self.fd, buf);
    }

    pub fn writePacket(self: TunDevice, buf: []const u8) !usize {
        return std.os.write(self.fd, buf);
    }

    pub fn close(self: TunDevice) void {
        std.os.close(self.fd);
    }
};
