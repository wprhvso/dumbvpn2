const std = @import("std");
const posix = std.posix;

pub const TunDevice = struct {
    fd: posix.fd_t,

    pub fn readPacket(self: TunDevice, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn writePacket(self: TunDevice, buf: []const u8) !usize {
        return posix.write(self.fd, buf);
    }

    pub fn close(self: TunDevice) void {
        posix.close(self.fd);
    }
};
