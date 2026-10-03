const std = @import("std");

pub const index_html = @embedFile("assets/index.html");
pub const index_js = @embedFile("assets/assets/index.js");

pub fn serveStatic(path: []const u8) ?struct { data: []const u8, content_type: []const u8 } {
    if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
        return .{ .data = index_html, .content_type = "text/html; charset=utf-8" };
    } else if (std.mem.endsWith(u8, path, "index.js")) {
        return .{ .data = index_js, .content_type = "application/javascript; charset=utf-8" };
    }
    return null;
}
