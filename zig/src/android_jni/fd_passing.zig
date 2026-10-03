const std = @import("std");
const posix = std.posix;

pub fn receiveFd(sock_fd: posix.fd_t) !posix.fd_t {
    _ = sock_fd;
    return error.NotImplemented;
}
