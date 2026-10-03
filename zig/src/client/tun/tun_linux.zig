const std = @import("std");
const posix = std.posix;
const device = @import("device.zig");

pub const ifreq = extern struct {
    name: [16]u8,
    flags: i16,
    pad: [22]u8 = [_]u8{0} ** 22,
};

pub fn openTun(dev_name: []const u8) !device.TunDevice {
    const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
    errdefer posix.close(fd);

    const IFF_TUN: i16 = 0x0001;
    const IFF_NO_PI: i16 = 0x1000;
    const TUNSETIFF: u32 = 0x400454ca;

    var req: ifreq = undefined;
    @memset(std.mem.asBytes(&req), 0);
    req.flags = IFF_TUN | IFF_NO_PI;
    @memcpy(req.name[0..@min(dev_name.len, 15)], dev_name[0..@min(dev_name.len, 15)]);

    const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&req));
    const errno = std.posix.errno(rc);
    if (errno != .SUCCESS) {
        std.log.err("ioctl(TUNSETIFF) failed for {s}: {any}", .{ dev_name, errno });
        return error.TunSetIffFailed;
    }

    return device.TunDevice{ .fd = fd };
}
