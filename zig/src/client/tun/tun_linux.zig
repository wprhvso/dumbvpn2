const std = @import("std");
const device = @import("device.zig");

pub fn openTun(dev_name: []const u8) !device.TunDevice {
    const fd = try std.os.open("/dev/net/tun", std.os.O.RDWR, 0);
    var ifr: std.os.linux.ifreq = undefined;
    @memset(std.mem.asBytes(&ifr), 0);
    ifr.ifru.flags = std.os.linux.IFF.TUN | std.os.linux.IFF.NO_PI;
    @memcpy(ifr.ifrn.name[0..@min(dev_name.len, 15)], dev_name[0..@min(dev_name.len, 15)]);
    _ = std.os.linux.ioctl(fd, std.os.linux.TUNSETIFF, @intFromPtr(&ifr));
    return device.TunDevice{ .fd = fd };
}
