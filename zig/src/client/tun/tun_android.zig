const std = @import("std");
const device = @import("device.zig");

pub fn fromAndroidFd(fd: std.os.fd_t) device.TunDevice {
    return device.TunDevice{ .fd = fd };
}
