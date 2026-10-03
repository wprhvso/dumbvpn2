const std = @import("std");

pub const index_html = @embedFile("assets/index.html");

pub fn serveStatic(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
        return index_html;
    }
    return null;
}
