const std = @import("std");
const device = @import("device.zig");

pub fn openUtun() !device.TunDevice {
    return error.PlatformNotSupported;
}
