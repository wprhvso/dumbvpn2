const std = @import("std");

pub fn receiveFd(sock_fd: std.os.fd_t) !std.os.fd_t {
    var buf: [1]u8 = undefined;
    var iov = [_]std.os.iovec{.{ .iov_base = &buf, .iov_len = 1 }};
    var cmsg_buf: [std.os.CMSG_SPACE(@sizeOf(std.os.fd_t))]u8 = undefined;
    var msghdr: std.os.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = cmsg_buf.len,
        .flags = 0,
    };
    _ = sock_fd;
    _ = msghdr;
    return error.NotImplemented;
}
