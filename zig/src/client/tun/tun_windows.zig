const std = @import("std");
const device = @import("device.zig");

pub fn openWintun() !device.TunDevice {
    return error.PlatformNotSupported;
}
