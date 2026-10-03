const std = @import("std");
const posix = std.posix;
const device = @import("device.zig");

pub fn fromAndroidFd(fd: posix.fd_t) device.TunDevice {
    return device.TunDevice{ .fd = fd };
}
