const std = @import("std");
const posix = std.posix;

pub fn spliceSocketToSocket(in_fd: posix.fd_t, out_fd: posix.fd_t, pipe_fds: [2]posix.fd_t, len: usize) !usize {
    const SPLICE_F_MOVE: usize = 0x01;
    const SPLICE_F_NONBLOCK: usize = 0x02;
    const flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;

    const in_rc = std.os.linux.syscall6(
        std.os.linux.SYS.splice,
        @as(usize, @intCast(in_fd)),
        0,
        @as(usize, @intCast(pipe_fds[1])),
        0,
        len,
        flags,
    );
    if (in_rc == 0) return 0;

    const out_rc = std.os.linux.syscall6(
        std.os.linux.SYS.splice,
        @as(usize, @intCast(pipe_fds[0])),
        0,
        @as(usize, @intCast(out_fd)),
        0,
        in_rc,
        flags,
    );
    return out_rc;
}
