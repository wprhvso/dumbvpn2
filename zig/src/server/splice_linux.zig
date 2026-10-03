const std = @import("std");
const os = std.os;

pub fn spliceSocketToSocket(in_fd: os.fd_t, out_fd: os.fd_t, pipe_fds: [2]os.fd_t, len: usize) !usize {
    const SPLICE_F_MOVE: u32 = 0x01;
    const SPLICE_F_NONBLOCK: u32 = 0x02;
    const flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;

    const in_res = std.os.linux.splice(in_fd, null, pipe_fds[1], null, len, flags);
    if (in_res == 0) return 0;
    const out_res = std.os.linux.splice(pipe_fds[0], null, out_fd, null, in_res, flags);
    return out_res;
}
