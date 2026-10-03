const std = @import("std");

export fn Java_com_mesh_vpn_NativeLoader_startEngine(env: ?*anyopaque, thiz: ?*anyopaque, tun_fd: i32) i32 {
    _ = env;
    _ = thiz;
    _ = tun_fd;
    return 0;
}

export fn Java_com_mesh_vpn_NativeLoader_stopEngine(env: ?*anyopaque, thiz: ?*anyopaque) void {
    _ = env;
    _ = thiz;
}
